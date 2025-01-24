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
    #[error("unknown record id: {0:?}")]
    Record(UnknownRecordId),
    #[error(transparent)]
    FromHex(#[from] FromHexError),
    #[error(transparent)]
    Digest(#[from] DigestError),
    #[error("failed to parse key: {0}")]
    KeyFromStr(KeyFromStrError),
    #[error(transparent)]
    BinaryPortAccess(#[from] casper_binary_port_access::Error),
    #[error("need either a block hash or block height")]
    EitherHashOrHeightRequired,
    #[error("need either a key or key file")]
    EitherKeyOrKeyFileRequired,
    #[error(transparent)]
    CasperTypesExt(#[from] casper_types::ErrorExt),
    #[error(transparent)]
    CasperTypes(#[from] casper_types::Error),
    #[error("validator key required")]
    ValidatorKeyRequired,
    #[error("need era id, block hash or block height")]
    InvalidEraIdentifier,
    #[error("need state root hash, block hash or block height")]
    InvalidStateIdentifier,
    #[error(transparent)]
    JsonSerialization(#[from] serde_json::Error),
    #[error("need either raw hex-encoded bytes or filename to binary file")]
    EitherHexOrFileRequired,
    #[error("error when interacting with file (#{file_path}). Details: #{err}")]
    FromFile {
        file_path: String,
        err: std::io::Error,
    },
}
