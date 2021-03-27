mod smartcard;
pub mod simulated;

pub use smartcard::SmartcardClient;
pub use simulated::SimulatedClient;

use p256::{PublicKey, AffinePoint, Scalar};

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
    fn get_identity_key(&mut self) -> Result<PublicKey, String>;

    fn keygen_initialize(&mut self, group_size: usize) -> Result<Vec<u8>, String>;
    fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> Result<PublicKey, String>;
    fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> Result<PublicKey, String>;

    fn get_nonce(&mut self, counter: u16) -> Result<PublicKey, String>;
    fn cache_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String>;
    fn reveal_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String>;
    fn sign(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Result<Scalar, String>;
    fn sign_reveal(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> (Scalar, Vec<u8>);
}