use crate::client::Client;
use crate::protocol::{Protocol, ProtocolData};

pub struct State {
    pub clients: Vec<Box<dyn Client>>
}

impl State {
    pub fn new() -> State {
        State { clients: Vec::new() }
    }

    pub fn add_client(&mut self, client: Box<dyn Client>) {
        self.clients.push(client);
    }

    pub fn broadcast(&mut self, message: Protocol) -> Vec<ProtocolData> {
        self.clients.iter_mut().map(|x| x.process(message.clone())).collect()
    }
}