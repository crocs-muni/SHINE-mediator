use tonic::{Request, Response, Status, transport::Server};
use log::info;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tokio::sync::Mutex;

use crate::proto::{InfoRequest, Info, GroupRequest, Group, SignRequest, Signature, Device, ProtocolIdentifier};
use crate::proto::node_server::{Node, NodeServer};
use crate::state::State;
use crate::protocol::{Protocol, ProtocolMessage, ECDSA};

pub struct NodeService {
    state: Mutex<State>
}

impl NodeService {
    pub fn new(state: State) -> Self {
        NodeService { state: Mutex::new(state) }
    }
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn get_info(&self, request: Request<InfoRequest>) -> Result<Response<Info>, Status> {
        info!("RPC Request: {:?}", request);
        let mut state = self.state.lock().await;

        let mut devices = Vec::new();
        for client in state.clients.values_mut() {
            let key = client.get_identity_key().unwrap();
            let encoded = key.to_encoded_point(false);
            devices.push(Device {
                identity_key: encoded.as_bytes().to_vec(),
                supported_protocols: client.get_supported().iter().map(protocol_to_proto).collect()
            });
        }

        let resp = Info {
            devices
        };

        Ok(Response::new(resp))
    }

    async fn establish_group(&self, request: Request<GroupRequest>) -> Result<Response<Group>, Status> {
        info!("RPC Request: {:?}", request);

        let mut data = request.into_inner();
        let protocol = data.protocol.as_ref().unwrap();
        let mut group_key: Vec<u8> = Vec::new();
        let mut state = self.state.lock().await;
        for device in data.devices.iter_mut() {
            let device = state.clients.get_mut(&device.identity_key).unwrap();
            assert!(device.is_supported(proto_to_protocol(protocol.identifier)));
            let message = ProtocolMessage::ECDSA(ECDSA::Keygen);
            let key = device.process(message).expect_public_key();
            group_key.extend(key.to_encoded_point(false).as_bytes());
        }

        let resp = Group {
            protocol: data.protocol,
            devices: data.devices,
            group_key
        };

        Ok(Response::new(resp))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<Signature>, Status> {
        info!("RPC Request: {:?}", request);

        let resp = Signature {
            signature: "Signature".into()
        };

        Ok(Response::new(resp))
    }
}

pub async fn run_rpc(state: State) -> Result<(), String> {
    let addr = "127.0.0.1:1337".parse().unwrap();
    let node = NodeService::new(state);

    Server::builder()
        .add_service(NodeServer::new(node))
        .serve(addr)
        .await
        .unwrap();

    Ok(())
}

fn protocol_to_proto(protocol: &Protocol) -> i32 {
    match protocol {
        Protocol::ECDSA => ProtocolIdentifier::Ecdsa as i32
    }
}

fn proto_to_protocol(protocol: i32) -> Protocol {
    match protocol {
        0 => Protocol::ECDSA,
        _ => panic!()
    }
}
