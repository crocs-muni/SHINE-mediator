#[cfg(feature = "smartcard")]
mod smartcard;
pub mod simulated;

#[cfg(feature = "smartcard")]
pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::PublicKey;
use crate::protocol::{ProtocolMessage, ProtocolData, Protocol};

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> Result<PublicKey, String>;

    fn process(&mut self, protocol: ProtocolMessage) -> ProtocolData;
    fn is_supported(&self, protocol: Protocol) -> bool;

    fn get_supported(&self) -> Vec<Protocol> {
        IntoIterator::into_iter([
            Protocol::ECDSA,
        ]).filter(|x| self.is_supported(*x)).collect()
    }
}
