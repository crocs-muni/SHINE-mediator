use crate::client::Client;
use crate::protocol::{ProtocolMessage, ProtocolData, Protocol};

pub struct State {
    pub clients: Vec<Box<dyn Client + Send + Sync>>
}

impl State {
    pub fn new() -> State {
        State { clients: Vec::new() }
    }

    pub fn add_client(&mut self, client: Box<dyn Client + Send + Sync>) {
        self.clients.push(client);
    }

    pub fn broadcast(&mut self, message: ProtocolMessage) -> Vec<ProtocolData> {
        self.clients.iter_mut().map(|x| x.process(message.clone())).collect()
    }

    pub fn all_support(&mut self, protocol: Protocol) -> bool {
        self.clients.iter_mut().all(|x| x.is_supported(protocol))
    }
}
