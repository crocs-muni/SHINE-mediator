mod smartcard;

pub use smartcard::SmartcardClient;

pub trait Client {
    fn get_version(&self) -> String;
}