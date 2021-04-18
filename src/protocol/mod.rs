use p256::{PublicKey, AffinePoint, Scalar};

#[derive(Clone)]
pub enum Protocol {
    KeygenCommitment(KeygenCommitment),
}

#[derive(Clone)]
pub enum KeygenCommitment {
    Initialize(usize), // group_size
    Reveal(Vec<Vec<u8>>), // commitments
    Finalize(Vec<PublicKey>), // public_keys
}

pub enum ProtocolData {
    KeygenCommitment(KeygenCommitmentData)
}

pub enum KeygenCommitmentData {
    Commitment(Vec<u8>),
    Reveal(PublicKey),
    Result(PublicKey),
}

impl ProtocolData {
    pub fn expect_bytes(self) -> Vec<u8> {
        match self {
            ProtocolData::KeygenCommitment(data) => match data {
                KeygenCommitmentData::Commitment(data) => data,
                _ => panic!(),
            }
            _ => panic!(),
        }
    }

    pub fn expect_public_key(self) -> PublicKey {
        match self {
            ProtocolData::KeygenCommitment(data) => match data {
                KeygenCommitmentData::Reveal(data) => data,
                KeygenCommitmentData::Result(data) => data,
                _ => panic!(),
            }
            _ => panic!(),
        }
    }
}
// pub trait KeygenCommitment {
//     fn keygen_initialize(&mut self, group_size: usize) -> Result<Vec<u8>, String>;
//     fn keygen_reveal(&mut self, commitments: Vec<Vec<u8>>) -> Result<PublicKey, String>;
//     fn keygen_finalize(&mut self, public_keys: Vec<PublicKey>) -> Result<PublicKey, String>;
// }

pub trait NonceEncryption {
    fn get_nonce(&mut self, counter: u16) -> Result<PublicKey, String>;
    fn cache_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String>;
    fn reveal_nonce(&mut self, counter: u16) -> Result<Vec<u8>, String>;
    fn sign(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Result<Scalar, String>;
    fn sign_reveal(&mut self, counter: u16, nonce_point: AffinePoint, message: [u8; 32]) -> Result<(Scalar, Vec<u8>), String>;
}