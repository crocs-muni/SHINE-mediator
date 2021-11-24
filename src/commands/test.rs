use crate::state::State;
use crate::client::simulated::SimulatedClient;
use log::{error, info};

#[cfg(feature = "smartcard")]
fn connect_smartcard_clients(state: &mut State) -> Result<(), String> {
    use crate::client::SmartcardClient;
    use pcsc::{Context, Scope, ShareMode, Protocols};

    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to establish context: {}", err);
            return Err(String::from("Failed to establish context"))
        }
    };

    let mut readers_buf = [0; 2048];
    let readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            error!("Failed to list readers: {}", err);
            return Err(String::from("Failed to list readers"))
        }
    };

    for reader in readers {
        let reader_name = reader.to_str().unwrap();
        info!("Discovered reader {}", reader_name);
        let card= match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => {
                info!("Card connected");
                card
            },
            Err(pcsc::Error::NoSmartcard) => {
                info!("No smartcard in reader {}", reader_name);
                continue;
            }
            Err(err) => {
                error!("Failed to connect to card: {}", err);
                continue;
            }
        };

        if let Ok(client) = SmartcardClient::new(card) {
            state.add_client(Box::new(client));
        }
    }

    Ok(())
}

pub fn run_tests() -> Result<(), String> {
    info!("Functionality tests start");

    let mut state = State::new();

    #[cfg(feature = "smartcard")]
        connect_smartcard_clients(&mut state)?;

    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));
    state.add_client(Box::new(SimulatedClient::new()));

    info!("Functionality tests ended");
    Ok(())
}
