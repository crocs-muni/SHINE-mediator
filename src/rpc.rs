use tonic::{Request, Response, Status, transport::Server};
use log::info;

use crate::proto::{InfoRequest, Info, GroupRequest, Group, SignRequest, Signature};
use crate::proto::node_server::{Node, NodeServer};
use crate::state::State;

pub struct NodeService {
    state: State
}

impl NodeService {
    pub fn new(state: State) -> Self {
        NodeService { state }
    }
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn get_info(&self, request: Request<InfoRequest>) -> Result<Response<Info>, Status> {
        info!("RPC Request: {:?}", request);

        let resp = Info {
            devices: Vec::new()
        };

        Ok(Response::new(resp))
    }

    async fn establish_group(&self, request: Request<GroupRequest>) -> Result<Response<Group>, Status> {
        info!("RPC Request: {:?}", request);

        let data = request.into_inner();
        let resp = Group {
            protocol: data.protocol,
            devices: data.devices,
            group_key: "GroupKey".into()
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
