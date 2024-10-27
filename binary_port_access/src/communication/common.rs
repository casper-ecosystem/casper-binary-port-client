use crate::Error;
#[cfg(not(target_arch = "wasm32"))]
use casper_binary_port::BinaryMessage;
use casper_binary_port::{
    BinaryRequest, BinaryRequestHeader, BinaryResponse, BinaryResponseAndRequest, PayloadEntity,
};
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    ProtocolVersion,
};
#[cfg(not(target_arch = "wasm32"))]
use rand::Rng;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

// TODO[RC]: Do not hardcode this.
pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);
pub(crate) const LENGTH_FIELD_SIZE: usize = 4;
#[cfg(not(target_arch = "wasm32"))]
const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

#[cfg(not(target_arch = "wasm32"))]
async fn connect_to_node(node_address: &str) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(node_address).await?;
    Ok(stream)
}

/// Sends the payload length and data to the client.
#[cfg(not(target_arch = "wasm32"))]
async fn send_payload(client: &mut TcpStream, message: &BinaryMessage) -> Result<(), Error> {
    let payload_length = message.payload().len() as u32;
    let length_bytes = payload_length.to_le_bytes();

    let _ = timeout(TIMEOUT_DURATION, client.write_all(&length_bytes))
        .await
        .map_err(|e| Error::TimeoutError(e.to_string()))?;

    let _ = timeout(TIMEOUT_DURATION, client.write_all(message.payload()))
        .await
        .map_err(|e| Error::TimeoutError(e.to_string()))?;

    let _ = timeout(TIMEOUT_DURATION, client.flush())
        .await
        .map_err(|e| Error::TimeoutError(e.to_string()))?;

    Ok(())
}

/// Reads the response from the client and returns the response buffer.
#[cfg(not(target_arch = "wasm32"))]
async fn read_response(client: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut length_buf = [0u8; LENGTH_FIELD_SIZE];
    let _ = timeout(TIMEOUT_DURATION, client.read_exact(&mut length_buf))
        .await
        .map_err(|e| Error::TimeoutError(e.to_string()))?;

    let response_length = u32::from_le_bytes(length_buf) as usize;
    let mut response_buf = vec![0u8; response_length];
    let _ = timeout(TIMEOUT_DURATION, client.read_exact(&mut response_buf))
        .await
        .map_err(|e| Error::TimeoutError(e.to_string()))?;

    Ok(response_buf)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let request_id = rand::thread_rng().gen::<u16>();
    let payload =
        encode_request(&request, Some(request_id)).expect("should always serialize a request");
    let mut client = connect_to_node(node_address).await?;

    let message = BinaryMessage::new(payload);

    // Send the payload length and data
    send_payload(&mut client, &message).await?;

    // Read and process the response
    let response_buf = read_response(&mut client).await?;
    // Now process the response using the request_id
    process_response(response_buf, request_id).await
}

pub(crate) fn encode_request(
    req: &BinaryRequest,
    request_id: Option<u16>,
) -> Result<Vec<u8>, bytesrepr::Error> {
    let header = BinaryRequestHeader::new(
        SUPPORTED_PROTOCOL_VERSION,
        req.tag(),
        request_id.unwrap_or_default(),
    );
    let mut bytes = Vec::with_capacity(header.serialized_length() + req.serialized_length());
    header.write_bytes(&mut bytes)?;
    req.write_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Parse response
pub(crate) fn parse_response<A: FromBytes + PayloadEntity>(
    response: &BinaryResponse,
) -> Result<Option<A>, Error> {
    match response.returned_data_type_tag() {
        Some(found) if found == u8::from(A::RESPONSE_TYPE) => {
            // Verbose: Print length of payload
            let payload = response.payload();
            let _payload_length = payload.len();
            // TODO[GR] use tracing::info! instead of dbg!
            // dbg!(_payload_length);

            Ok(Some(bytesrepr::deserialize_from_slice(payload)?))
        }
        Some(other) => Err(Error::Response(format!(
            "unsupported response type: {other}"
        ))),
        _ => Ok(None),
    }
}

/// Processes the response buffer and checks for request ID mismatch.
pub(crate) async fn process_response(
    response_buf: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
    const REQUEST_ID_START: usize = 0;
    const REQUEST_ID_END: usize = REQUEST_ID_START + 2;

    // Extract Request ID from the response
    let _request_id = u16::from_le_bytes(
        response_buf[REQUEST_ID_START..REQUEST_ID_END]
            .try_into()
            .expect("Failed to extract Request ID"),
    );

    // Check if request_id matches _request_id and return an error if not
    if request_id != _request_id {
        return Err(Error::Response(format!(
            "Request ID mismatch: expected {}, got {}",
            request_id, _request_id
        )));
    }

    // Deserialize the remaining response data
    let response: BinaryResponseAndRequest = bytesrepr::deserialize_from_slice(response_buf)?;
    Ok(response)
}
