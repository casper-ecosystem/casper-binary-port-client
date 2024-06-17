use casper_binary_port::{
    BinaryMessage, BinaryMessageCodec, BinaryRequest, BinaryRequestHeader, BinaryResponseAndRequest,
};
use casper_types::{
    bytesrepr::{self, ToBytes},
    ProtocolVersion,
};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::Error;

// TODO[RC]: Do not hardcode this.
pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);

async fn connect_to_node(
    node_address: &str,
) -> Result<Framed<TcpStream, BinaryMessageCodec>, Error> {
    let stream = TcpStream::connect(node_address).await?;
    Ok(Framed::new(stream, BinaryMessageCodec::new(4_194_304)))
}

fn encode_request(req: &BinaryRequest) -> Result<Vec<u8>, bytesrepr::Error> {
    let header = BinaryRequestHeader::new(SUPPORTED_PROTOCOL_VERSION, req.tag());
    let mut bytes = Vec::with_capacity(header.serialized_length() + req.serialized_length());
    header.write_bytes(&mut bytes)?;
    req.write_bytes(&mut bytes)?;
    Ok(bytes)
}

// TODO[RC]: Into "communication" module
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let payload =
        BinaryMessage::new(encode_request(&request).expect("should always serialize a request"));

    let mut client = connect_to_node(node_address).await?;
    client.send(payload).await?;
    let maybe_response = client.next().await;

    let Some(response) = maybe_response else {
        return Err(Error::Response("empty response".to_string()));
    };

    let response = response?;
    let payload = response.payload();
    Ok(bytesrepr::deserialize_from_slice(payload)?)
}
