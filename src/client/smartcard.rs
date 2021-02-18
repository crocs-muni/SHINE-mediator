use crate::client::Client;
use pcsc::Card;
use log::{info, warn};
use std::convert::TryInto;
use p256::{PublicKey, AffinePoint, Scalar};

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

    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(u16, &[u8]), pcsc::Error> {
        self.card.transmit(apdu, &mut self.rapdu).map(|bytes| {
            let (rest, code) = bytes.split_at(bytes.len() - std::mem::size_of::<u16>());
            (u16::from_be_bytes(code.try_into().unwrap()), rest)
        })
    }
}

impl Client for SmartcardClient {
    fn get_info(&mut self) -> Result<String, String> {
        if let Ok((_code, resp)) = self.send_apdu(b"\xc2\xf0\x00\x00") {
            Ok(std::str::from_utf8(resp).map(String::from).unwrap())
        } else {
            Err(String::from("Unknown Version"))
        }
    }

    fn get_identity_key(&mut self) -> PublicKey {
        unimplemented!()
    }

    fn keygen_initialize(&mut self, _group_size: usize) -> Vec<u8> {
        unimplemented!()
    }

    fn keygen_reveal(&mut self, _commitments: Vec<Vec<u8>>) -> PublicKey {
        unimplemented!()
    }

    fn keygen_finalize(&mut self, _public_keys: Vec<PublicKey>) -> PublicKey {
        unimplemented!()
    }

    fn cache_nonce(&mut self, _counter: u16) -> PublicKey {
        unimplemented!()
    }

    fn sign(&mut self, _counter: u16, _nonce_point: AffinePoint, _message: [u8; 32]) -> Scalar {
        unimplemented!()
    }
}