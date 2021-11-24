use k256::PublicKey;

#[derive(Copy, Clone)]
pub enum Protocol {
    ECDSA,
}

#[derive(Clone)]
pub enum ProtocolMessage {
    ECDSA(ECDSA),
}

#[derive(Clone)]
pub enum ECDSA {
    Keygen,
    Sign(PublicKey, Vec<u8>),
}

pub enum ProtocolData {
    ECDSAData(ECDSAData),
}

pub enum ECDSAData {
    Key(PublicKey),
    Signature(Vec<u8>),
}

impl ProtocolData {
    pub fn expect_bytes(self) -> Vec<u8> {
        match self {
            ProtocolData::ECDSAData(data) => match data {
                ECDSAData::Signature(data) => data,
                _ => panic!(),
            },
        }
    }

    pub fn expect_public_key(self) -> PublicKey {
        match self {
            ProtocolData::ECDSAData(data) => match data {
                ECDSAData::Key(data) => data,
                _ => panic!(),
            },
            _ => panic!(),
        }
    }
}
