use crate::client::Client;
use pcsc::Card;
use log::{info, warn};
use std::convert::TryInto;
use k256::PublicKey;
use crate::protocol::{ProtocolMessage, ProtocolData, Protocol};

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

    fn process(&mut self, _msg: ProtocolMessage) -> ProtocolData {
        unimplemented!()
    }

    fn is_supported(&self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::ECDSA => false,
        }
    }
}
