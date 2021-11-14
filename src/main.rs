use clap::{App, Arg};
use log::info;
use tonic::{Request, Response, Status, transport::Server};

use proto::{IdentityRequest, IdentityResponse};
use proto::node_server::{Node, NodeServer};

mod state;
mod client;
mod protocol;
mod commands;

pub mod proto {
    tonic::include_proto!("mpcp");
}

#[derive(Debug, Default)]
pub struct NodeService {}

#[tonic::async_trait]
impl Node for NodeService {
    async fn get_identity(
        &self,
        request: Request<IdentityRequest>,
    ) -> Result<Response<IdentityResponse>, Status> {
        println!("Got a request: {:?}", request);

        let resp = proto::IdentityResponse {
            identity_key: "Response".into()
        };

        Ok(Response::new(resp))
    }
}


#[tokio::main]
async fn main() -> Result<(), String> {
    let matches = App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .arg(Arg::new("test")
            .long("test")
            .about("Run functionality tests and exit")
            .takes_value(false))
        .arg(Arg::new("command")
            .long("command")
            .short('c')
            .about("Send command to a running instance of mpcd")
        )
        .get_matches();

    env_logger::init();
    info!("Starting");

    if matches.is_present("test") {
        commands::test::run_tests()?;
    } else if matches.is_present("command") {
        // TODO command handling
    } else {
        let addr = "127.0.0.1:1337".parse().unwrap();

        let node = NodeService::default();

        Server::builder()
            .add_service(NodeServer::new(node))
            .serve(addr)
            .await
            .unwrap();
    }

    info!("Terminating");
    Ok(())
}
