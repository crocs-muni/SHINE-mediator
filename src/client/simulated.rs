use crate::client::Client;
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    PublicKey, SecretKey
};
use rand::rngs::OsRng;
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
        match msg {
            ECDSA::Keygen => {
                self.identity_secret = SecretKey::random(self.rng);
                ECDSAData::Key(self.identity_secret.public_key())
            }
            ECDSA::Sign(public_key, msg) => {
                assert_eq!(public_key, self.identity_secret.public_key());
                let signing_key = SigningKey::from(&self.identity_secret);
                ECDSAData::Signature(signing_key.sign(&msg).to_der().as_bytes().into())
            }
        }
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
