mod smartcard;
pub mod simulated;

pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::PublicKey;
use crate::protocol::{Protocol, ProtocolData};

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> Result<PublicKey, String>;

    fn process(&mut self, protocol: Protocol) -> ProtocolData;
}