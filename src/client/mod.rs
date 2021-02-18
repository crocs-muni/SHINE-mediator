mod smartcard;
mod simulated;

pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::PublicKey;

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> PublicKey;
}