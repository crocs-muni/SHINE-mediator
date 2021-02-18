mod smartcard;
mod simulated;

pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::AffinePoint;

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_public_key(&mut self) -> AffinePoint;
}