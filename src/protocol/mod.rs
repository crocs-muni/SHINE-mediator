use k256::{PublicKey, Scalar};

#[derive(Copy, Clone)]
pub enum Protocol {
    KeygenCommit,
    SchnorrExchange,
    SchnorrCommit,
    SchnorrDelin,
}

#[derive(Clone)]
pub enum ProtocolMessage {
    KeygenCommit(KeygenCommit),
    SchnorrExchange(SchnorrExchange),
    SchnorrCommit(SchnorrCommit),
    SchnorrDelin(SchnorrDelin)
}

#[derive(Clone)]
pub enum KeygenCommit {
    Initialize(usize),
    Reveal(Vec<Vec<u8>>),
    Finalize(Vec<PublicKey>),
}

#[derive(Clone)]
pub enum SchnorrExchange {
    GetNonce(u16),
    CacheNonce(u16),
    RevealNonce(u16),
    Sign(u16, PublicKey, [u8; 32]),
    SignReveal(u16, PublicKey, [u8; 32]),
}

#[derive(Clone)]
pub enum SchnorrCommit {
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
    KeygenCommit(KeygenCommitData),
    SchnorrExchange(SchnorrExchangeData),
    SchnorrCommit(SchnorrCommitData),
    SchnorrDelin(SchnorrDelinData),
}

pub enum KeygenCommitData {
    Commitment(Vec<u8>),
    Reveal(PublicKey),
    Result(PublicKey),
}

pub enum SchnorrExchangeData {
    Nonce(PublicKey),
    EncryptedNonce(Vec<u8>),
    NonceKey(Vec<u8>),
    Signature(Scalar),
    SignatureNonceKey(Scalar, Vec<u8>),
}

pub enum SchnorrCommitData {
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
            ProtocolData::KeygenCommit(data) => match data {
                KeygenCommitData::Commitment(data) => data,
                _ => panic!(),
            }
            ProtocolData::SchnorrExchange(data) => match data {
                SchnorrExchangeData::EncryptedNonce(data) => data,
                SchnorrExchangeData::NonceKey(data) => data,
                _ => panic!(),
            },
            ProtocolData::SchnorrCommit(data) => match data {
                SchnorrCommitData::Commitment(data) => data,
                _ => panic!(),
            }
            ProtocolData::SchnorrDelin(_) => panic!(),
        }
    }

    pub fn expect_public_key(self) -> PublicKey {
        match self {
            ProtocolData::KeygenCommit(data) => match data {
                KeygenCommitData::Reveal(data) => data,
                KeygenCommitData::Result(data) => data,
                _ => panic!(),
            },
            ProtocolData::SchnorrExchange(data) => match data {
                SchnorrExchangeData::Nonce(data) => data,
                _ => panic!(),
            }
            ProtocolData::SchnorrCommit(data) => match data {
                SchnorrCommitData::Reveal(data) => data,
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
            ProtocolData::SchnorrExchange(data) => match data {
                SchnorrExchangeData::Signature(data) => data,
                _ => panic!(),
            },
            ProtocolData::SchnorrCommit(data) => match data {
                SchnorrCommitData::Signature(_, data) => data,
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
