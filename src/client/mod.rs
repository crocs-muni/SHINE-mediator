#[cfg(feature = "smartcard")]
mod smartcard;
pub mod simulated;

#[cfg(feature = "smartcard")]
pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use k256::PublicKey;
use crate::protocol::{ProtocolMessage, ProtocolData, Protocol};
use crate::proto::ProtocolIdentifier;

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> Result<PublicKey, String>;
    fn get_supported(&self) -> Vec<ProtocolIdentifier>;

    fn process(&mut self, protocol: ProtocolMessage) -> ProtocolData;
    fn is_supported(&self, protocol: Protocol) -> bool;
}
