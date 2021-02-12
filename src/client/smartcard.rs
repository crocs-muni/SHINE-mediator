use crate::client::Client;
use pcsc::Card;
use log::{info, warn};

pub struct SmartcardClient {
    card: Card
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
        match select_applet(&mut card, b"jcmusig2app") {
            Ok(_) => Ok(SmartcardClient { card }),
            Err(e) => Err(e)
        }
    }
}

impl Client for SmartcardClient {
    fn get_version(&self) -> String {
        String::from("SmartCard MPC 0.1")
    }
}