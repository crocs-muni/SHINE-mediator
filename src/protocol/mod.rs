use p256::{PublicKey, Scalar};

pub enum Protocol {
    KeygenCommitment,
    SchnorrSerial,
    SchnorrCommitment,
    SchnorrDelin,
}

#[derive(Clone)]
pub enum ProtocolMessage {
    KeygenCommitment(KeygenCommitment),
    SchnorrSerial(SchnorrSerial),
    SchnorrCommitment(SchnorrCommitment),
    SchnorrDelin(SchnorrDelin)
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
    Sign(u16, PublicKey, [u8; 32]),
    SignReveal(u16, PublicKey, [u8; 32]),
}

#[derive(Clone)]
pub enum SchnorrCommitment {
    CommitNonce([u8; 32]),
    RevealNonce(Vec<Vec<u8>>),
    Sign(Vec<PublicKey>)
}

#[derive(Clone)]
pub enum SchnorrDelin {
    GetPrenonces,
    Sign(Vec<(PublicKey, PublicKey)>, [u8; 32])
}

pub enum ProtocolData {
    KeygenCommitment(KeygenCommitmentData),
    SchnorrSerial(SchnorrSerialData),
    SchnorrCommitment(SchnorrCommitmentData),
    SchnorrDelin(SchnorrDelinData),
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

pub enum SchnorrCommitmentData {
    Commitment(Vec<u8>),
    Reveal(PublicKey),
    Signature(PublicKey, Scalar)
}

pub enum SchnorrDelinData {
    Prenonces((PublicKey, PublicKey)),
    Signature(PublicKey, Scalar),
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
            },
            ProtocolData::SchnorrCommitment(data) => match data {
                SchnorrCommitmentData::Commitment(data) => data,
                _ => panic!(),
            }
            ProtocolData::SchnorrDelin(_) => panic!(),
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
            ProtocolData::SchnorrCommitment(data) => match data {
                SchnorrCommitmentData::Reveal(data) => data,
                _ => panic!(),
            },
            ProtocolData::SchnorrDelin(data) => match data {
                SchnorrDelinData::Signature(nonce, _) => nonce,
                _ => panic!(),
            }
        }
    }

    pub fn expect_scalar(self) -> Scalar {
        match self {
            ProtocolData::SchnorrSerial(data) => match data {
                SchnorrSerialData::Signature(data) => data,
                _ => panic!(),
            },
            ProtocolData::SchnorrCommitment(data) => match data {
                SchnorrCommitmentData::Signature(_, data) => data,
                _ => panic!(),
            }
            ProtocolData::SchnorrDelin(data) => match data {
                SchnorrDelinData::Signature(_, signature) => signature,
                _ => panic!(),
            },
            _ => panic!()
        }
    }
}