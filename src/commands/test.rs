use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, ProjectivePoint};
use crate::state::{State, schnorr_verify, decrypt_nonces};
use crate::client::simulated::SimulatedClient;
use crate::protocol::Protocol;
use log::{error, warn, info};

#[cfg(feature = "smartcard")]
fn connect_smartcard_clients(state: &mut State) -> Result<(), String> {
    use crate::client::SmartcardClient;
    use pcsc::{Context, Scope, ShareMode, Protocols};

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

pub fn run_tests() -> Result<(), String> {
    info!("Functionality tests start");

    let mut state = State::new();

    #[cfg(feature = "smartcard")]
        connect_smartcard_clients(&mut state)?;

    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));

    let parties = state.clients.len();

    for client in state.clients.iter_mut() {
        info!("New client {} | ID {}",
              client.get_info().unwrap(),
              hex::encode(client.get_identity_key().unwrap().to_encoded_point(true).as_bytes())
        );
    }

    if !state.all_support(Protocol::KeygenCommit) {
        return Err(String::from("Clients cannot agree on key generation"))
    }

    let group_key = state.keygen_commitment(parties);

    let message = [0; 32];
    let signature = state.schnorr_exchange_sign(0, message);

    if schnorr_verify(signature, message, &group_key) {
        info!("Nonce exchange successful");
    } else {
        warn!("Nonce exchange failed");
    }

    let cached_nonces = state.schnorr_exchange_cache(5);
    let decryption_keys = state.schnorr_exchange_reveal(5);
    let decrypted_nonces = decrypt_nonces(cached_nonces, decryption_keys);

    let nonce_points = decrypted_nonces.clone();

    let mut failure = false;
    for (plain, decrypted) in state.schnorr_exchange_nonce(5).into_iter().zip(decrypted_nonces) {
        if plain != decrypted {
            failure = true;
        }
    }
    if failure {
        warn!("Nonce caching failed");
    } else {
        info!("Nonce caching successful");
    }

    let aggregate_nonce = PublicKey::from_affine(nonce_points.iter()
        .map(PublicKey::to_projective)
        .fold(ProjectivePoint::identity(), |acc, x| acc + x)
        .to_affine()
    ).unwrap();

    let cached_nonces = state.schnorr_exchange_cache(6);
    let (_, decryption_keys) = state.schnorr_exchange_sign_reveal(5, aggregate_nonce, message);
    let decrypted_nonces = decrypt_nonces(cached_nonces, decryption_keys);

    failure = false;
    for (plain, decrypted) in state.schnorr_exchange_nonce(6).into_iter().zip(decrypted_nonces) {
        if plain != decrypted {
            failure = true;
        }
    }
    if failure {
        warn!("Key piggybacking failed");
    } else {
        info!("Key piggybacking successful");
    }

    if state.all_support(Protocol::SchnorrCommit) {
        let commitments = state.schnorr_commitment_commit(message);
        let reveals = state.schnorr_commitment_reveal(commitments);
        let signature = state.schnorr_commitment_sign(reveals);
        if schnorr_verify(signature, message, &group_key) {
            info!("Nonce commitment successful");
        } else {
            warn!("Nonce commitment failed");
        }
    } else {
        warn!("Some clients do not support nonce commitment - skipping");
    }

    let signature = state.interop_commit_sign(10, message);
    if schnorr_verify(signature, message, &group_key) {
        info!("Interoperability with nonce commitment successful");
    } else {
        warn!("Interoperability with nonce commitment failed");
    }

    if state.all_support(Protocol::SchnorrDelin) {
        let prenonces = state.schnorr_delin_prenonces();
        let signature = state.schnorr_delin_sign(prenonces, message);
        if schnorr_verify(signature, message, &group_key) {
            info!("Nonce delinearization successful");
        } else {
            warn!("Nonce delinearization successful");
        }
    } else {
        warn!("Some clients do not support nonce delinearization - skipping");
    }

    let signature = state.interop_delin_sign(20, message);
    if schnorr_verify(signature, message, &group_key) {
        info!("Interoperability with nonce delinearization successful");
    } else {
        warn!("Interoperability with nonce delinearization failed");
    }

    info!("Functionality tests ended");
    Ok(())
}
