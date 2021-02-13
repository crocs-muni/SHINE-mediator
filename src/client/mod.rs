mod smartcard;

pub use smartcard::SmartcardClient;

pub trait Client {
    fn get_info(&mut self) -> Result<String, String>;
}