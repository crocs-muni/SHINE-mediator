use p256::{PublicKey, AffinePoint, Scalar};

pub trait KeygenCommitment {
    fn keygen_initialize(&mut self, group_size: usize) -> Result<Vec<u8>, String>;
    fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> Result<PublicKey, String>;
    fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> Result<PublicKey, String>;
}

pub trait NonceEncryption {
    fn get_nonce(&mut self, counter: u16) -> Result<PublicKey, String>;
    fn cache_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String>;
    fn reveal_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String>;
    fn sign(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Result<Scalar, String>;
    fn sign_reveal(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Result<(Scalar, Vec<u8>), String>;
}