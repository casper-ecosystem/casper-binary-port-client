use casper_binary_port::{
    BinaryMessage, BinaryMessageCodec, BinaryRequest, BinaryRequestHeader, BinaryResponseAndRequest,
};
use casper_types::bytesrepr::{self, ToBytes};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::{error::Error, utils::SUPPORTED_PROTOCOL_VERSION};

async fn connect_to_node() -> Result<Framed<TcpStream, BinaryMessageCodec>, Error> {
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

pub(crate) async fn send_request(
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let payload =
        BinaryMessage::new(encode_request(&request).expect("should always serialize a request"));

    let mut client = connect_to_node().await?;
    client.send(payload).await?;
    let maybe_response = client.next().await;

    let Some(response) = maybe_response else {
        return Err(Error::Response("empty response".to_string()));
    };

    let response = response?;
    let payload = response.payload();
    Ok(bytesrepr::deserialize_from_slice(payload)?)
}
