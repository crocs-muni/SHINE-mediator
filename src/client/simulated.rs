use crate::client::Client;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;

pub struct SimulatedClient {
    identity_secret: SecretKey,
}

impl SimulatedClient {
    pub fn new() -> Self {
        let rng = OsRng::default();
        SimulatedClient {
            identity_secret: SecretKey::random(rng)
        }
    }
}

impl Client for SimulatedClient {
    fn get_info(&mut self) -> Result<String, String> {
        Ok(String::from("SimulatedClient 0.1.0"))
    }

    fn get_identity_key(&mut self) -> PublicKey {
        self.identity_secret.public_key()
    }
}

