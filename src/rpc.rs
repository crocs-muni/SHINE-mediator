use tonic::{Request, Response, Status, transport::Server};
use log::info;

use crate::proto::{IdentityRequest, IdentityResponse};
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
    async fn get_identity(&self, request: Request<IdentityRequest>) -> Result<Response<IdentityResponse>, Status> {
        info!("RPC Request: {:?}", request);

        let resp = IdentityResponse {
            identity_key: "Response".into()
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
