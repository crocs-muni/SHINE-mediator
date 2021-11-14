mod state;
mod client;
mod protocol;

use client::SimulatedClient;
use state::State;

use log::{error, warn, info};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, ProjectivePoint};
use clap::{Arg, App};
use state::{schnorr_verify, decrypt_nonces};
use protocol::Protocol;
use tonic::{transport::Server, Request, Response, Status};

pub mod proto {
    tonic::include_proto!("mpcp");
}

use proto::{IdentityRequest, IdentityResponse};
use proto::node_server::{Node, NodeServer};

#[cfg(feature = "smartcard")]
fn connect_smartcard_clients(state: &mut State) -> Result<(), String> {
    use client::SmartcardClient;
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

fn run_tests() -> Result<(), String> {
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

#[derive(Debug, Default)]
pub struct NodeService {}

#[tonic::async_trait]
impl Node for NodeService {
    async fn get_identity(
        &self,
        request: Request<IdentityRequest>,
    ) -> Result<Response<IdentityResponse>, Status> {
        println!("Got a request: {:?}", request);

        let resp = proto::IdentityResponse {
            identity_key: "Response".into()
        };

        Ok(Response::new(resp))
    }
}


#[tokio::main]
async fn main() -> Result<(), String> {
    let matches = App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .arg(Arg::new("test")
            .long("test")
            .about("Run functionality tests and exit")
            .takes_value(false))
        .arg(Arg::new("command")
            .long("command")
            .short('c')
            .about("Send command to a running instance of mpcd")
        )
        .get_matches();

    env_logger::init();
    info!("Starting");

    if matches.is_present("test") {
        run_tests()?;
    } else if matches.is_present("command") {
        // TODO command handling
    } else {
        let addr = "127.0.0.1:1337".parse().unwrap();

        let node = NodeService::default();

        Server::builder()
            .add_service(NodeServer::new(node))
            .serve(addr)
            .await
            .unwrap();
    }

    info!("Terminating");
    Ok(())
}
