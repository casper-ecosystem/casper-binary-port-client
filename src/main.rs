use core::fmt;
use std::{f32::consts::E, fmt::write, process::ExitCode};

use bytes::Bytes;
use casper_binary_port::{
    BinaryMessage, BinaryMessageCodec, BinaryRequest, BinaryRequestHeader, BinaryResponse,
    BinaryResponseAndRequest, BinaryResponseHeader, GetRequest, InformationRequest,
    InformationRequestTag, NodeStatus, PayloadEntity, RecordId,
};
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    BlockHash, BlockHeader, BlockIdentifier, ProtocolVersion,
};
use clap::{error, Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

// TODO[RC]: Get from command line
pub const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);

#[derive(Debug, Subcommand)]
enum Information {
    /// NodeStatus request.
    NodeStatus,
    /// Block header request.
    BlockHeader {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
}

impl Information {
    fn id(&self) -> InformationRequestTag {
        match self {
            Information::NodeStatus => InformationRequestTag::NodeStatus,
            Information::BlockHeader { .. } => InformationRequestTag::BlockHeader,
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Information::BlockHeader { hash, height } => {
                let block_id = match (hash, height) {
                    (None, None) => None,
                    (None, Some(height)) => Some(BlockIdentifier::Height(*height)),
                    (Some(hash), None) => {
                        let digest =
                            casper_types::Digest::from_hex(&hash).expect("failed to parse hash");
                        Some(BlockIdentifier::Hash(BlockHash::new(digest)))
                    }
                    (Some(_), Some(_)) => {
                        unreachable!("should not have both hash and height")
                    }
                };
                block_id.to_bytes().expect("should serialize")
            }
            Information::NodeStatus => Default::default(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Send information request with a given ID and key.
    #[clap(subcommand)]
    Information(Information),
    /// Send record request with a given ID and key.
    Record {
        #[clap(long, short)]
        id: u16,
        #[clap(long, short)]
        key: Option<String>,
    },
}

/// A request to the binary access interface.
#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    commands: Commands,
    #[clap(long, short, default_value = "false")]
    verbose: bool,
}

#[derive(Debug, Error)]
enum RequestConstructionError {
    #[error("invalid information type: {0}")]
    InvalidInfoType(u16),
    #[error("can not create request: {0:?}")]
    CannotCreateRequest(InformationRequestTag),
}

#[derive(Error, Debug)]
enum RequestError {
    #[error(transparent)]
    Bytesrepr(#[from] bytesrepr::Error),
    #[error(transparent)]
    BinaryPort(#[from] casper_binary_port::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("failed to handle response: {0}")]
    Response(String),
    #[error(transparent)]
    Construction(#[from] RequestConstructionError),
}

fn print_option<T: fmt::Debug>(opt: Option<T>) {
    match opt {
        Some(val) => println!("{:#?}", val),
        None => println!("[EMPTY]"),
    }
}

fn handle_info_response(
    tag: InformationRequestTag,
    response: &BinaryResponseAndRequest,
) -> Result<(), RequestError> {
    match tag {
        // TODO: Macro?
        InformationRequestTag::NodeStatus => {
            let res = parse_response::<NodeStatus>(response.response())?;
            print_option(res);
            Ok(())
        }
        InformationRequestTag::BlockHeader => {
            let res = parse_response::<BlockHeader>(response.response())?;
            print_option(res);
            Ok(())
        }
        _ => unimplemented!(),
    }
}

async fn handle_information_request(req: Information) -> Result<(), RequestError> {
    let id = req.id();
    let key = req.key();

    let request = make_info_get_request(id, &key)?;
    let response = send_request(request).await?;
    handle_info_response(id, &response);

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();

    let result = match args.commands {
        Commands::Information(req) => handle_information_request(req),
        Commands::Record { id, key } => todo!(),
    }
    .await;

    if let Err(err) = result {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }

    return ExitCode::SUCCESS;
}

fn parse_response<A: FromBytes + PayloadEntity>(
    response: &BinaryResponse,
) -> Result<Option<A>, RequestError> {
    match response.returned_data_type_tag() {
        Some(found) if found == u8::from(A::PAYLOAD_TYPE) => {
            Ok(Some(bytesrepr::deserialize_from_slice(response.payload())?))
        }
        Some(other) => Err(RequestError::Response(format!(
            "unsupported response type: {other}"
        ))),
        _ => Ok(None),
    }
}

async fn send_request(request: BinaryRequest) -> Result<BinaryResponseAndRequest, RequestError> {
    let payload =
        BinaryMessage::new(encode_request(&request).expect("should always serialize a request"));

    let mut client = connect_to_node().await?;
    client.send(payload).await?;
    let maybe_response = client.next().await;

    match maybe_response {
        Some(response) => {
            let response = response?;
            let payload = response.payload();
            return Ok(bytesrepr::deserialize_from_slice(payload)?);
        }
        None => return Err(RequestError::Response("empty response".to_string())),
    }
}

async fn connect_to_node() -> Result<Framed<TcpStream, BinaryMessageCodec>, RequestError> {
    // TODO[RC]: Get address from command line
    let stream = TcpStream::connect("127.0.0.1:28103").await?;
    Ok(Framed::new(stream, BinaryMessageCodec::new(4_194_304)))
}

fn encode_request(req: &BinaryRequest) -> Result<Vec<u8>, bytesrepr::Error> {
    let header = BinaryRequestHeader::new(SUPPORTED_PROTOCOL_VERSION, req.tag());
    let mut bytes = Vec::with_capacity(header.serialized_length() + req.serialized_length());
    header.write_bytes(&mut bytes)?;
    req.write_bytes(&mut bytes)?;
    Ok(bytes)
}

fn make_info_get_request(
    tag: InformationRequestTag,
    key: &[u8],
) -> Result<BinaryRequest, RequestConstructionError> {
    let Ok(information_request) = InformationRequest::try_from((tag, &key[..])) else {
        return Err(RequestConstructionError::CannotCreateRequest(tag));
    };
    let get_request = information_request
        .try_into()
        .expect("should always be able to convert");

    Ok(BinaryRequest::Get(get_request))
}
