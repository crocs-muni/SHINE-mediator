mod state;
mod client;
mod protocol;

use client::SimulatedClient;
use state::State;

use log::info;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, ProjectivePoint};
use crate::state::{schnorr_verify, decrypt_nonces};

#[cfg(feature = "smartcard")]
fn connect_smartcard_clients(state: &mut State) -> Result<(), String> {
    use client::SmartcardClient;
    use pcsc::{Context, Scope, ShareMode, Protocols};
    use log::error;

    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to establish context: {}", err);
            return Err(String::from("Failed to establish context"))
        }
    };

    let mut readers_buf = [0; 2048];
    let readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            error!("Failed to list readers: {}", err);
            return Err(String::from("Failed to list readers"))
        }
    };

    for reader in readers {
        let reader_name = reader.to_str().unwrap();
        info!("Discovered reader {}", reader_name);
        let card= match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => {
                info!("Card connected");
                card
            },
            Err(pcsc::Error::NoSmartcard) => {
                info!("No smartcard in reader {}", reader_name);
                continue;
            }
            Err(err) => {
                error!("Failed to connect to card: {}", err);
                continue;
            }
        };

        if let Ok(client) = SmartcardClient::new(card) {
            state.add_client(Box::new(client));
        }
    }

    Ok(())
}

fn main() -> Result<(), String> {
    env_logger::init();
    info!("Starting");
    let mut state = State::new();

    #[cfg(feature = "smartcard")]
    connect_smartcard_clients(&mut state)?;

    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));

    let parties = state.clients.len();

    for client in state.clients.iter_mut() {
        println!("{}", client.get_info().unwrap());
        println!("{}", hex::encode(client.get_identity_key().unwrap().to_encoded_point(false).as_bytes()));
    }

    let group_key = state.keygen_commitment(parties);

    let message = [0; 32];
    let signature = state.schnorr_serial_sign(0, message);

    assert!(schnorr_verify(signature, message, &group_key));

    let cached_nonces = state.schnorr_serial_cache(5);
    let decryption_keys = state.schnorr_serial_reveal(5);
    let decrypted_nonces = decrypt_nonces(cached_nonces, decryption_keys);

    let nonce_points = decrypted_nonces.clone();

    for (plain, decrypted) in state.schnorr_serial_nonce(5).into_iter().zip(decrypted_nonces) {
        assert_eq!(plain, decrypted);
    }

    let aggregate_nonce = PublicKey::from_affine(nonce_points.iter()
        .map(PublicKey::to_projective)
        .fold(ProjectivePoint::identity(), |acc, x| acc + x)
        .to_affine()
    ).unwrap();

    let cached_nonces = state.schnorr_serial_cache(6);
    let (_, decryption_keys) = state.schnorr_serial_sign_reveal(5, aggregate_nonce, message);
    let decrypted_nonces = decrypt_nonces(cached_nonces, decryption_keys);

    for (plain, decrypted) in state.schnorr_serial_nonce(6).into_iter().zip(decrypted_nonces) {
        assert_eq!(plain, decrypted);
    }

    let commitments = state.schnorr_commitment_commit(message);
    let reveals = state.schnorr_commitment_reveal(commitments);
    let signature = state.schnorr_commitment_sign(reveals);
    assert!(schnorr_verify(signature, message, &group_key));

    let signature = state.interop_commit_sign(10, message);
    assert!(schnorr_verify(signature, message, &group_key));

    info!("Terminating");
    Ok(())
}
