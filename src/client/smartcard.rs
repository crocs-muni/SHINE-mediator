use crate::client::Client;
use pcsc::Card;
use log::{info, warn};
use std::convert::TryInto;
use k256::{PublicKey, Scalar};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::protocol::{KeygenCommit, ProtocolMessage, ProtocolData, KeygenCommitData, SchnorrExchange, SchnorrExchangeData, Protocol};

pub struct SmartcardClient {
    card: Card,
    rapdu: [u8; pcsc::MAX_BUFFER_SIZE]
}

fn make_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: Option<&[u8]>) -> Vec<u8> {
    let mut apdu_buffer = vec![cla, ins, p1, p2];
    if let Some(data) = data {
        apdu_buffer.push(data.len() as u8);
        apdu_buffer.extend_from_slice(data);
    }
    apdu_buffer
}

fn select_applet(card: &mut Card, aid: &[u8]) -> Result<(), String> {
    let apdu = make_apdu(0x00, 0xa4, 0x04, 0x00, Some(aid));
    info!("Selecting applet {}", std::str::from_utf8(aid).unwrap());
    let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE];
    let rapdu = match card.transmit(&apdu, &mut rapdu_buf) {
        Ok(rapdu) => rapdu,
        Err(err) => return Err(err.to_string())
    };
    if rapdu != b"\x90\x00" {
        warn!("Selection failed: {:?}", rapdu);
        return Err(format!("Selection failed {:?}", rapdu));
    }
    info!("Selected successfully");
    Ok(())
}

impl SmartcardClient {
    pub fn new(mut card: Card) -> Result<SmartcardClient, String> {
        match select_applet(&mut card, b"mpcapplet") {
            Ok(_) => Ok(SmartcardClient { card, rapdu: [0; pcsc::MAX_BUFFER_SIZE] }),
            Err(e) => Err(e)
        }
    }

    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(u16, &[u8]), String> {
        self.card.transmit(apdu, &mut self.rapdu).map(|bytes| {
            let (rest, code) = bytes.split_at(bytes.len() - std::mem::size_of::<u16>());
            (u16::from_be_bytes(code.try_into().unwrap()), rest)
        }).map_err(|x| x.to_string())
    }

    fn handle_keygen_commitment(&mut self, message: KeygenCommit) -> KeygenCommitData {
        match message {
            KeygenCommit::Initialize(group_size) => {
                let (_, resp) = self.send_apdu(&[0x00, 0x01, group_size as u8, 0x00]).unwrap();
                KeygenCommitData::Commitment(resp.to_vec())
            },
            KeygenCommit::Reveal(commitments) => {
                for (idx, commitment) in commitments.iter().enumerate() {
                    let mut data = vec![0x00, 0x02, idx as u8, 0x00];
                    data.push(commitment.len() as u8);
                    data.extend_from_slice(commitment);
                    self.send_apdu(&data).unwrap();
                }
                let (_, resp) = self.send_apdu(&[0x00, 0x03, 0x00, 0x00]).unwrap();
                KeygenCommitData::Reveal(PublicKey::from_sec1_bytes(resp).unwrap())
            },
            KeygenCommit::Finalize(public_keys) => {
                for (idx, public_key) in public_keys.iter().enumerate() {
                    let public_key = public_key.to_encoded_point(false).as_bytes().to_vec();
                    let mut data = vec![0x00, 0x04, idx as u8, 0x00];
                    data.push(public_key.len() as u8);
                    data.extend_from_slice(&public_key);
                    self.send_apdu(&data).unwrap();
                }
                let (_, resp) = self.send_apdu(&[0x00, 0x05, 0x00, 0x00]).unwrap();
                KeygenCommitData::Result(PublicKey::from_sec1_bytes(resp).unwrap())
            }
        }
    }

    fn handle_schnorr_serial(&mut self, message: SchnorrExchange) -> SchnorrExchangeData {
        match message {
            SchnorrExchange::GetNonce(counter) => {
                let mut data = vec![0x00, 0x06];
                data.extend_from_slice(&u16::to_le_bytes(counter));
                let (_, resp) = self.send_apdu(&data).unwrap();
                SchnorrExchangeData::Nonce(PublicKey::from_sec1_bytes(resp).unwrap())
            },
            SchnorrExchange::CacheNonce(counter) => {
                let mut data = vec![0x00, 0x07];
                data.extend_from_slice(&u16::to_le_bytes(counter));
                let (_, resp) = self.send_apdu(&data).unwrap();
                SchnorrExchangeData::EncryptedNonce(Vec::from(resp))
            },
            SchnorrExchange::RevealNonce(counter) => {
                let mut data = vec![0x00, 0x08];
                data.extend_from_slice(&u16::to_le_bytes(counter));
                let (_, resp) = self.send_apdu(&data).unwrap();
                SchnorrExchangeData::NonceKey(Vec::from(resp))
            },
            SchnorrExchange::Sign(counter, nonce_point, message) => {
                let mut data = vec![0x00, 0x09];
                data.extend_from_slice(&u16::to_le_bytes(counter));
                let nonce_point = nonce_point.to_encoded_point(false).as_bytes().to_vec();
                data.push((nonce_point.len() + message.len()) as u8);
                data.extend_from_slice(&nonce_point);
                data.extend_from_slice(&message);
                let (_, resp) = self.send_apdu(&data).unwrap();
                SchnorrExchangeData::Signature(Scalar::from_bytes_reduced(resp.into()))
            },
            SchnorrExchange::SignReveal(counter, nonce_point, message) => {
                let mut data = vec![0x00, 0x0a];
                data.extend_from_slice(&u16::to_le_bytes(counter));
                let nonce_point = nonce_point.to_encoded_point(false).as_bytes().to_vec();
                data.push((nonce_point.len() + message.len()) as u8);
                data.extend_from_slice(&nonce_point);
                data.extend_from_slice(&message);
                let (_, resp) = self.send_apdu(&data).unwrap();
                let (s, k) = resp.split_at(32);
                let s = Scalar::from_bytes_reduced(s.into());
                let k = Vec::from(k);
                SchnorrExchangeData::SignatureNonceKey(s, k)
            }
        }
    }
}

impl Client for SmartcardClient {
    fn get_info(&mut self) -> Result<String, String> {
        let (_, resp) = self.send_apdu(b"\x00\xf0\x00\x00")?;
        Ok(std::str::from_utf8(resp).map(String::from).unwrap())
    }

    fn get_identity_key(&mut self) -> Result<PublicKey, String> {
        let (_, resp) = self.send_apdu(b"\x00\xf1\x00\x00")?;
        match PublicKey::from_sec1_bytes(resp) {
            Ok(identity_key) => Ok(identity_key),
            Err(_) => Err(String::from("Received invalid identity key"))
        }
    }

    fn process(&mut self, msg: ProtocolMessage) -> ProtocolData {
        match msg {
            ProtocolMessage::KeygenCommit(msg) => ProtocolData::KeygenCommit(self.handle_keygen_commitment(msg)),
            ProtocolMessage::SchnorrExchange(msg) => ProtocolData::SchnorrExchange(self.handle_schnorr_serial(msg)),
            _ => panic!()
        }
    }

    fn is_supported(&self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::KeygenCommit => true,
            Protocol::SchnorrExchange => true,
            Protocol::SchnorrCommit => false,
            Protocol::SchnorrDelin => false,
        }
    }
}
