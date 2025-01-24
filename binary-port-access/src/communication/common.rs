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
use std::sync::atomic::AtomicU16;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::Ordering;
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

pub static COUNTER: AtomicU16 = AtomicU16::new(0);

/// Establishes an asynchronous TCP connection to a specified node address.
///
/// This function attempts to connect to a node using a TCP stream. It is only
/// compiled for non-WebAssembly (Wasm) targets, making it suitable for native
/// applications.
///
/// # Parameters
///
/// - `node_address`: A `&str` representing the address of the node to which
///   the connection will be made. This should include the host and port (e.g.,
///   "localhost:28101"). The default port to use is `28101`.
///
/// # Returns
///
/// This function returns a `Result` that, on success, contains a `TcpStream`
/// which represents the established connection. On failure, it returns a
/// `std::io::Error`.
///
/// # Errors
///
/// This function may return an error if:
/// - The connection to the specified `node_address` fails.
/// - There are network issues preventing the establishment of the connection.
/// - The address format is invalid.
///
/// # Notes
///
/// This function is only compiled for targets other than `wasm32`, ensuring it
/// is used in appropriate environments such as servers or local applications.
#[cfg(not(target_arch = "wasm32"))]
async fn connect_to_node(node_address: &str) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(node_address).await?;
    Ok(stream)
}

/// Sends the payload length and data to the connected TCP client.
///
/// This asynchronous function sends a binary message to a TCP client. It first sends
/// the length of the message payload as a 4-byte little-endian integer for Casper binary protocol, followed by
/// the actual payload data. This function is intended for use in non-WebAssembly (Wasm)
/// environments, typically on servers or local applications.
///
/// # Parameters
///
/// - `client`: A mutable reference to a `TcpStream` representing the connection
///   to the client to which the payload will be sent.
/// - `message`: A reference to a `BinaryMessage` containing the payload data to send.
///
/// # Returns
///
/// This function returns a `Result` indicating the outcome of the operation:
/// - `Ok(())`: Indicates the payload was sent successfully.
/// - `Err(Error)`: An error if any part of the send operation fails, including timeout errors.
///
/// # Errors
///
/// This function may return an error if:
/// - The write operations timeout, resulting in a `TimeoutError`.
/// - There are issues with the TCP stream that prevent data from being sent.
///
/// # Notes
///
/// The function ensures that the TCP connection remains responsive by enforcing a timeout
/// on each write operation. This prevents the function from hanging indefinitely in case
/// of network issues or an unresponsive client. The payload length is sent first, allowing
/// the client to know how many bytes to expect for the subsequent payload data.
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

/// Reads the response from a connected TCP client and returns the response buffer.
///
/// This asynchronous function reads a response from a TCP stream. It first reads
/// a length prefix to determine how many bytes to read for the actual response.
/// The function is only available for non-WebAssembly (Wasm) targets, ensuring
/// it is used in appropriate environments such as servers or local applications.
///
/// # Parameters
///
/// - `client`: A mutable reference to a `TcpStream` representing the connection
///   to the client from which the response will be read.
///
/// # Returns
///
/// This function returns a `Result` containing:
/// - `Ok(Vec<u8>)`: A vector of bytes representing the response data from the client.
/// - `Err(Error)`: An error if the read operation fails, including timeout errors.
///
/// # Errors
///
/// This function may return an error if:
/// - The read operation times out, resulting in a `TimeoutError`.
/// - There are issues reading from the TCP stream, which may yield an `Error`.
///
/// # Notes
///
/// The first 4 bytes read from the stream are interpreted as a little-endian
/// unsigned integer indicating the length of the subsequent response data.
/// The function enforces a timeout for read operations to prevent hanging
/// indefinitely on slow or unresponsive clients.
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

/// Sends a binary request to a node and waits for the response.
///
/// This asynchronous function establishes a TCP connection to the specified node address,
/// sends a serialized binary request, and processes the response. It generates a unique
/// request ID for each request to correlate with the response received.
///
/// # Parameters
///
/// - `node_address`: A string slice that holds the address of the node to connect to,
///   typically in the format "hostname:28101".
/// - `request`: An instance of `BinaryRequest` representing the request data to be sent.
///
/// # Returns
///
/// This function returns a `Result` that indicates the outcome of the operation:
/// - `Ok(BinaryResponseAndRequest)`: The processed response received from the node.
/// - `Err(Error)`: An error if any part of the operation fails, including connection issues,
///   serialization errors, or response processing errors.
///
/// # Errors
///
/// This function may return an error if:
/// - The connection to the node fails, returning an `Error::ConnectionError`.
/// - Serialization of the request fails, leading to an unwrapped panic in case of a serialization error.
/// - Sending the payload or reading the response times out, resulting in a `TimeoutError`.
///
/// # Notes
///
/// The function uses a unique request ID for each request, allowing the response to be
/// associated with the correct request. The payload is sent in two parts: first the length
/// of the payload as a 4-byte little-endian integer, and then the actual payload data.
/// After sending the request, it waits for the response and processes it accordingly.
/// This function is designed to be used in non-WebAssembly (Wasm) environments, typically
/// on servers or local applications.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let request_id = COUNTER.fetch_add(1, Ordering::SeqCst); // Atomically increment the counter

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

/// Encodes a binary request into a byte vector for transmission.
///
/// This function serializes a `BinaryRequest` along with a specified request ID (if provided)
/// into a byte vector. The encoded data includes a header containing the protocol version,
/// request tag, and the request ID. This byte vector can then be sent over a network connection.
///
/// # Parameters
///
/// - `req`: A reference to a `BinaryRequest` instance representing the request to be serialized.
/// - `request_id`: An optional `u16` representing the unique identifier for the request. If not provided,
///   a default value of `0` is used.
///
/// # Returns
///
/// This function returns a `Result` that indicates the outcome of the operation:
/// - `Ok(Vec<u8>)`: A vector of bytes representing the serialized request, including the header and payload.
/// - `Err(bytesrepr::Error)`: An error if the serialization process fails, indicating the nature of the issue.
///
/// # Errors
///
/// The function may return an error if:
/// - Writing the header or the request data to the byte vector fails, which could be due to various
///   reasons, such as insufficient memory or incorrect data structures.
///
/// # Notes
///
/// The request ID helps in tracking requests and their corresponding responses, allowing for easier
/// identification in asynchronous communication.
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

/// Parses a binary response and deserializes it into a specified type.
///
/// This function inspects the `BinaryResponse` to determine the type of returned data. If the
/// data type matches the expected type (specified by the generic type parameter `A`), it
/// deserializes the payload into an instance of `A`.
///
/// # Parameters
///
/// - `response`: A reference to a `BinaryResponse` instance containing the data to be parsed.
///
/// # Type Parameters
///
/// - `A`: A type that implements both `FromBytes` and `PayloadEntity` traits, indicating
///   that the type can be deserialized from a byte slice and represents a valid payload entity.
///
/// # Returns
///
/// This function returns a `Result` indicating the outcome of the operation:
/// - `Ok(Some(A))`: If the response type matches, the payload is successfully deserialized
///   into an instance of `A`.
/// - `Ok(None)`: If no data type tag is found in the response, indicating an empty or
///   invalid response payload.
/// - `Err(Error)`: If the data type tag does not match the expected type or if deserialization
///   fails, an error is returned providing details about the issue.
///
/// # Errors
///
/// The function may return an error if:
/// - The returned data type tag does not match the expected type.
/// - Deserialization of the payload into type `A` fails due to an invalid byte format or
///   insufficient data.
///
/// # Notes
///
/// This function is useful in scenarios where responses from a binary protocol need to be
/// dynamically parsed into specific types based on the data type tag. The use of the
/// `FromBytes` trait allows for flexible and type-safe deserialization.
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

/// Processes the response buffer and checks for a request ID mismatch.
///
/// This function takes a response buffer, extracts the request ID from the beginning of the buffer,
/// and checks it against the expected request ID. If the IDs match, it proceeds to deserialize the
/// remaining data in the buffer into a `BinaryResponseAndRequest` object.
///
/// # Parameters
///
/// - `response_buf`: A vector of bytes representing the response data received from the server.
/// - `request_id`: The expected request ID that was sent with the original request.
///
/// # Returns
///
/// This function returns a `Result` indicating the outcome of the operation:
/// - `Ok(BinaryResponseAndRequest)`: If the request ID matches and the response data is successfully
///   deserialized, it returns the deserialized `BinaryResponseAndRequest`.
/// - `Err(Error)`: If there is a mismatch in the request ID or if deserialization fails, an error
///   is returned providing details about the issue.
///
/// # Errors
///
/// The function may return an error if:
/// - The extracted request ID does not match the expected request ID, indicating a potential issue
///   with request handling or communication.
/// - Deserialization of the response buffer into `BinaryResponseAndRequest` fails due to an invalid
///   byte format or insufficient data.
pub(crate) async fn process_response(
    response_buf: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
    const REQUEST_ID_START: usize = 0;
    const REQUEST_ID_END: usize = REQUEST_ID_START + 2;

    // Check if the response buffer is at least the size of the request ID
    if response_buf.len() < REQUEST_ID_END {
        return Err(Error::Response(format!(
                "Response buffer is too small: expected at least {} bytes, got {}. Buffer contents: {:?}",
                REQUEST_ID_END,
                response_buf.len(),
                response_buf
            )));
    }

    // Extract Request ID from the response
    let response_request_id = u16::from_le_bytes(
        response_buf[REQUEST_ID_START..REQUEST_ID_END]
            .try_into()
            .expect("Failed to extract Request ID"),
    );

    // Check if request_id matches response_request_id and return an error if not
    if request_id != response_request_id {
        return Err(Error::Response(format!(
            "Request ID mismatch: expected {request_id}, got {response_request_id}"
        )));
    }

    // Deserialize the remaining response data
    let response: BinaryResponseAndRequest = bytesrepr::deserialize_from_slice(response_buf)?;
    Ok(response)
}
