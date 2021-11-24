use crate::client::Client;
use k256::{PublicKey, SecretKey, ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use std::iter::Iterator;
use rand::RngCore;
use crate::protocol::{Protocol, ProtocolMessage, ProtocolData, ECDSA, ECDSAData};

pub struct SimulatedClient {
    rng: OsRng,
    identity_secret: SecretKey,
}

impl SimulatedClient {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut cache_secret = Vec::with_capacity(32);
        cache_secret.resize(32, 0);
        rng.fill_bytes(&mut cache_secret);
        SimulatedClient {
            rng,
            identity_secret: SecretKey::random(rng)
        }
    }

    fn handle_ecdsa(&mut self, msg: ECDSA) -> ECDSAData {
        unimplemented!()
    }
}

impl Client for SimulatedClient {
    fn get_info(&mut self) -> Result<String, String> {
        Ok(format!("Simulator {}", env!("CARGO_PKG_VERSION")))
    }

    fn get_identity_key(&mut self) -> Result<PublicKey, String> {
        Ok(self.identity_secret.public_key())
    }

    fn process(&mut self, msg: ProtocolMessage) -> ProtocolData {
        match msg {
            ProtocolMessage::ECDSA(msg) => ProtocolData::ECDSAData(self.handle_ecdsa(msg)),
        }
    }

    fn is_supported(&self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::ECDSA => true,
        }
    }
}
