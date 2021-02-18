mod smartcard;
mod simulated;

pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::PublicKey;

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> PublicKey;

    fn keygen_initialize(&mut self, group_size: usize) -> Vec<u8>;
    fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> PublicKey;
    fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> PublicKey;
}