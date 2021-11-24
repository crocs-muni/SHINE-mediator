use crate::client::Client;
use crate::protocol::{ProtocolMessage, ProtocolData, Protocol};
use std::collections::HashMap;
use p256::elliptic_curve::sec1::ToEncodedPoint;

pub struct State {
    pub clients: HashMap<Vec<u8>, Box<dyn Client + Send + Sync>>,
    pub groups: HashMap<Vec<u8>, Vec<Vec<u8>>>
}

impl State {
    pub fn new() -> State {
        State {
            clients: HashMap::new(),
            groups: HashMap::new()
        }
    }

    pub fn add_client(&mut self, mut client: Box<dyn Client + Send + Sync>) {
        self.clients.insert(
            client.get_identity_key().unwrap().to_encoded_point(false).as_bytes().into(),
            client
        );
    }

    pub fn add_group(&mut self, group_key: Vec<u8>, devices: Vec<Vec<u8>>) {
        self.groups.insert(group_key, devices);
    }

    pub fn broadcast(&mut self, message: ProtocolMessage) -> Vec<ProtocolData> {
        self.clients.values_mut().map(|x| x.process(message.clone())).collect()
    }

    pub fn all_support(&mut self, protocol: Protocol) -> bool {
        self.clients.values().all(|x| x.is_supported(protocol))
    }
}
