use crate::client::Client;
use p256::AffinePoint;

pub struct SimulatedClient {}

impl SimulatedClient {
    pub fn new() -> Self {
        SimulatedClient {}
    }
}

impl Client for SimulatedClient {
    fn get_info(&mut self) -> Result<String, String> {
        Ok(String::from("SimulatedClient 0.1.0"))
    }

    fn get_identity_key(&mut self) -> AffinePoint {
        AffinePoint::generator()
    }
}

