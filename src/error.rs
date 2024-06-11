use casper_binary_port::UnknownRecordId;
use casper_types::{bytesrepr, DigestError, KeyFromStrError};
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Bytesrepr(#[from] bytesrepr::Error),
    #[error(transparent)]
    BinaryPort(#[from] casper_binary_port::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("failed to handle response: {0}")]
    Response(String),
    #[error("unknown record id: {0:?}")]
    Record(UnknownRecordId),
    #[error(transparent)]
    FromHex(#[from] FromHexError),
    #[error(transparent)]
    Digest(#[from] DigestError),
    #[error("failed to parse key: {0}")]
    KeyFromStr(KeyFromStrError),
}
