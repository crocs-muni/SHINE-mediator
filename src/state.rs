use crate::client::Client;

pub struct State {
    clients: Vec<Box<dyn Client>>
}

impl State {
    pub fn new() -> State {
        State { clients: Vec::new() }
    }

    pub fn add_client(&mut self, client: Box<dyn Client>) {
        self.clients.push(client);
    }
}