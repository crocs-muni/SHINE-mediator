mod state;
mod client;
mod protocol;
mod commands;
mod rpc;

mod proto {
    tonic::include_proto!("mpcp");
}

use clap::{App, Arg};

use crate::state::State;

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
    let state = State::new();

    if matches.is_present("test") {
        commands::test::run_tests()
    } else if matches.is_present("command") {
        Ok(()) // TODO command handling
    } else {
        rpc::run_rpc(state).await
    }
}
