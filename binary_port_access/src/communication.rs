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
use rand::Rng;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
#[cfg(target_arch = "wasm32")]
pub use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
mod wasm_config {
    pub use js_sys::Promise;
    pub use wasm_bindgen::prelude::Closure;

    pub use wasm_bindgen::JsValue;
    pub use wasm_bindgen_futures::JsFuture;
    pub use web_sys::{MessageEvent, WebSocket};
}

// TODO[RC]: Do not hardcode this.
pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);
const REQUEST_ID_START: usize = 0;
const REQUEST_ID_END: usize = REQUEST_ID_START + 2;
const LENGTH_OF_REQUEST_START: usize = REQUEST_ID_END;
const LENGTH_OF_REQUEST_END: usize = LENGTH_OF_REQUEST_START + 4;

#[cfg(not(target_arch = "wasm32"))]
const TIMEOUT_DURATION: Duration = Duration::from_secs(5);
#[cfg(not(target_arch = "wasm32"))]
const LENGTH_FIELD_SIZE: usize = 4;

// TODO[RC]: Into "communication" module

#[cfg(not(target_arch = "wasm32"))]
async fn connect_to_node(node_address: &str) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(node_address).await?;
    Ok(stream)
}

fn encode_request(
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
    process_response(response_buf, request_id).await
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let request_id = rand::thread_rng().gen::<u16>();
    let payload = encode_request(&request, Some(request_id))
        .map_err(|e| Error::Serialization(format!("Failed to serialize request: {}", e)))?;

    // Ensure the WebSocket URL is correct
    let ws_url = if node_address.starts_with("ws://") || node_address.starts_with("wss://") {
        node_address.to_string()
    } else {
        format!("ws://{}", node_address)
    };

    // Create a new WebSocket connection
    let ws = wasm_config::WebSocket::new(&ws_url)
        .map_err(|e| Error::WebSocketCreation(format!("Failed to create WebSocket: {:?}", e)))?;

    // Create a promise to handle incoming WebSocket messages
    let promise = wasm_config::Promise::new(&mut |resolve, reject| {
        // Clone ws and payload to avoid moving them into the closure
        let ws_clone = ws.clone();
        let payload_clone = payload.clone();

        // Clone resolve and reject so they aren't moved into the closure
        let resolve_clone = resolve.clone();
        let reject_clone = reject.clone();

        let onopen = wasm_config::Closure::wrap(Box::new(move || {
            // Send the payload once the connection is open
            if let Err(e) = ws_clone.send_with_u8_array(&payload_clone) {
                reject_clone
                    .call1(
                        &wasm_config::JsValue::NULL,
                        &wasm_config::JsValue::from_str(&format!(
                            "Failed to send message: {:?}",
                            e
                        )),
                    )
                    .unwrap();
            } else {
                // Set up onmessage and onerror handlers

                // Clone resolve again for the onmessage closure
                let resolve_clone_for_message = resolve_clone.clone();

                let onmessage =
                    wasm_config::Closure::wrap(Box::new(move |event: wasm_config::MessageEvent| {
                        let data = event.data().as_string().unwrap_or_default();
                        resolve_clone_for_message
                            .call1(
                                &wasm_config::JsValue::NULL,
                                &wasm_config::JsValue::from_str(&data),
                            )
                            .unwrap();
                    })
                        as Box<dyn FnMut(wasm_config::MessageEvent)>);

                ws_clone.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
                onmessage.forget();

                // Clone reject again for the onerror closure
                let reject_clone_for_error = reject_clone.clone();

                let onerror =
                    wasm_config::Closure::wrap(Box::new(move |event: wasm_config::JsValue| {
                        let error_msg = event
                            .as_string()
                            .unwrap_or_else(|| "WebSocket error".to_string());
                        reject_clone_for_error
                            .call1(
                                &wasm_config::JsValue::NULL,
                                &wasm_config::JsValue::from_str(&error_msg),
                            )
                            .unwrap();
                    })
                        as Box<dyn FnMut(wasm_config::JsValue)>);

                ws_clone.set_onerror(Some(onerror.as_ref().unchecked_ref()));
                onerror.forget();
            }
        }) as Box<dyn FnMut()>);

        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();
    });

    let js_future = wasm_config::JsFuture::from(wasm_config::Promise::resolve(&promise));
    let onmessage = js_future
        .await
        .map_err(|e| Error::Response(format!("Failed to receive message: {:?}", e)))?;

    // Cast the result to a MessageEvent
    let message_event = onmessage
        .dyn_into::<wasm_config::MessageEvent>()
        .map_err(|_| Error::Response("Failed to cast to MessageEvent".to_string()))?;

    // Extract the response data as a string
    let data = message_event
        .data()
        .as_string()
        .ok_or_else(|| Error::Response("Failed to parse response data".to_string()))?;

    // Process the response
    let response = process_response(data.as_bytes().to_vec(), request_id).await?;

    Ok(response)
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
async fn process_response(
    response_buf: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
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

    // Extract LengthOfRequest from the response
    let length_of_request = u32::from_le_bytes(
        response_buf[LENGTH_OF_REQUEST_START..LENGTH_OF_REQUEST_END]
            .try_into()
            .expect("Failed to extract LengthOfRequest"),
    ) as usize;

    // Extract remaining bytes from the response
    let remaining_response = &response_buf[length_of_request..];

    // Deserialize the remaining response data
    let response: BinaryResponseAndRequest = bytesrepr::deserialize_from_slice(remaining_response)?;
    Ok(response)
}
