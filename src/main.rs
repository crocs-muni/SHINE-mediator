mod state;
mod client;

use client::{SimulatedClient, SmartcardClient};
use state::State;

use std::ops::{Mul, Sub};
use log::{info, error};
use pcsc::{Context, Scope, ShareMode, Protocols};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, ProjectivePoint, Scalar};

fn main() -> Result<(), String> {
    env_logger::init();
    info!("Starting");
    let mut state = State::new();

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
    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));

    let parties = state.clients.len();

    for client in state.clients.iter_mut() {
        println!("{}", client.get_info().unwrap());
        println!("{}", hex::encode(client.get_identity_key().unwrap().to_encoded_point(false).as_bytes()));
    }

    let commitments: Vec<_> = state.clients.iter_mut().map(|x| x.keygen_initialize(parties).unwrap()).collect();
    let public_keys: Vec<_> = state.clients.iter_mut().map(|x| x.keygen_reveal(commitments.clone()).unwrap()).collect();
    let group_keys: Vec<_> = state.clients.iter_mut().map(|x| x.keygen_finalize(public_keys.clone()).unwrap()).collect();
    let mut group_keys = group_keys.into_iter();
    let group_key = group_keys.next().unwrap();
    for other_group_key in group_keys {
        assert_eq!(group_key, other_group_key);
    }

    let nonce_points: Vec<_> = state.clients.iter_mut().map(|x| x.get_nonce(0).unwrap()).collect();
    let aggregate_nonce = nonce_points.iter().map(PublicKey::to_projective).fold(ProjectivePoint::identity(), |acc, x| acc + x).to_affine();
    let message = [0; 32];
    let signatures: Vec<_> = state.clients.iter_mut().map(|x| x.sign(0, aggregate_nonce, message).unwrap()).collect();
    let signature = signatures.iter().fold(Scalar::zero(), |acc, x| acc + x);

    let challenge = client::simulated::compute_challenge(group_key, aggregate_nonce, message);
    assert_eq!(ProjectivePoint::generator().mul(signature).sub(group_key.to_projective().mul(challenge)).to_affine(), aggregate_nonce);

    let cached_nonces: Vec<_> = state.clients.iter_mut().map(|x| x.cache_nonce(5).unwrap()).collect();
    let decryption_keys: Vec<_> = state.clients.iter_mut().map(|x| x.reveal_nonce(5).unwrap()).collect();
    let mut decrypted_nonces = Vec::new();
    for (encrypted_nonce, decryption_key) in cached_nonces.iter().zip(decryption_keys.iter()) {
        assert_eq!(encrypted_nonce.len(), decryption_key.len());
        let mut point = vec![0x04];
        point.extend(
        encrypted_nonce.iter()
            .zip(decryption_key.iter())
            .map(|(l, r)| *l ^ *r)
        );
        decrypted_nonces.push(PublicKey::from_sec1_bytes(&point).unwrap());
    }

    for (plain, decrypted) in state.clients.iter_mut().map(|x| x.get_nonce(5).unwrap()).zip(decrypted_nonces) {
        assert_eq!(plain, decrypted);
    }
    info!("Terminating");
    Ok(())
}
