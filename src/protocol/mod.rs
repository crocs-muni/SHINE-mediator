use p256::{PublicKey, AffinePoint, Scalar};

#[derive(Clone)]
pub enum Protocol {
    KeygenCommitment(KeygenCommitment),
    SchnorrSerial(SchnorrSerial),
}

#[derive(Clone)]
pub enum KeygenCommitment {
    Initialize(usize),
    Reveal(Vec<Vec<u8>>),
    Finalize(Vec<PublicKey>),
}

#[derive(Clone)]
pub enum SchnorrSerial {
    GetNonce(u16),
    CacheNonce(u16),
    RevealNonce(u16),
    Sign(u16, AffinePoint, [u8; 32]),
    SignReveal(u16, AffinePoint, [u8; 32]),
}

pub enum ProtocolData {
    KeygenCommitment(KeygenCommitmentData),
    SchnorrSerial(SchnorrSerialData),
}

pub enum KeygenCommitmentData {
    Commitment(Vec<u8>),
    Reveal(PublicKey),
    Result(PublicKey),
}

pub enum SchnorrSerialData {
    Nonce(PublicKey),
    EncryptedNonce(Vec<u8>),
    NonceKey(Vec<u8>),
    Signature(Scalar),
    SignatureNonceKey(Scalar, Vec<u8>),
}

impl ProtocolData {
    pub fn expect_bytes(self) -> Vec<u8> {
        match self {
            ProtocolData::KeygenCommitment(data) => match data {
                KeygenCommitmentData::Commitment(data) => data,
                _ => panic!(),
            }
            ProtocolData::SchnorrSerial(data) => match data {
                SchnorrSerialData::EncryptedNonce(data) => data,
                SchnorrSerialData::NonceKey(data) => data,
                _ => panic!(),
            }
        }
    }

    pub fn expect_public_key(self) -> PublicKey {
        match self {
            ProtocolData::KeygenCommitment(data) => match data {
                KeygenCommitmentData::Reveal(data) => data,
                KeygenCommitmentData::Result(data) => data,
                _ => panic!(),
            },
            ProtocolData::SchnorrSerial(data) => match data {
                SchnorrSerialData::Nonce(data) => data,
                _ => panic!(),
            }
        }
    }

    pub fn expect_scalar(self) -> Scalar {
        match self {
            ProtocolData::SchnorrSerial(data) => match data {
                SchnorrSerialData::Signature(data) => data,
                _ => panic!(),
            }
            _ => panic!(),
        }
    }
}