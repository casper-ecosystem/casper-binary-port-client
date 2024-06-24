use casper_types::bytesrepr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Bytesrepr(#[from] bytesrepr::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BinaryPort(#[from] casper_binary_port::Error),
    #[error("failed to handle response: {0}")]
    Response(String),
    #[error("transaction failed: {0}")]
    TransactionFailed(String),
}
