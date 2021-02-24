mod smartcard;
pub mod simulated;

pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::{PublicKey, AffinePoint, Scalar};

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> PublicKey;

    fn keygen_initialize(&mut self, group_size: usize) -> Vec<u8>;
    fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> PublicKey;
    fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> PublicKey;

    fn get_nonce(&mut self, counter: u16) -> PublicKey;
    fn cache_nonce(&mut self, counter: u16) -> Vec<u8>;
    fn reveal_nonce(&mut self, counter: u16) -> Vec<u8>;
    fn sign(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Scalar;
    fn sign_reveal(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> (Scalar, Vec<u8>);
}