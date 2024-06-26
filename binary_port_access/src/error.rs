use casper_types::bytesrepr;
use thiserror::Error;

/// Possible errors that can occur when interacting with the binary port.
#[derive(Error, Debug)]
pub enum Error {
    /// Bytesrepr serialization error.
    #[error(transparent)]
    Bytesrepr(#[from] bytesrepr::Error),
    /// IO error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Error in the binary port.
    #[error(transparent)]
    BinaryPort(#[from] casper_binary_port::Error),
    /// Error when handling the response from the binary port.
    #[error("failed to handle response: {0}")]
    Response(String),
}
