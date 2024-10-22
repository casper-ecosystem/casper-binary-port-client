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

    pub use js_sys::JsString;
    pub use js_sys::Reflect;

    pub use gloo_utils::format::JsValueSerdeExt;
    pub use wasm_bindgen::JsValue;
    pub use wasm_bindgen_futures::JsFuture;
    pub use web_sys::{MessageEvent, WebSocket};
}
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_with_prefix(s: &str);
}
/// Logs an error message, prefixing it with "error wasm" and sends it to the console in JavaScript when running in a WebAssembly environment.
/// When running outside WebAssembly, it prints the error message to the standard output.
pub fn log(s: &str) {
    let prefixed_s = format!("log wasm {}", s);
    #[cfg(target_arch = "wasm32")]
    log_with_prefix(&prefixed_s);
}

// TODO[RC]: Do not hardcode this.
pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);

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

// TODO Documentation
/// DOC
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn is_node() -> bool {
    // Check if 'process' exists and if it has 'versions' property (which is present in Node.js)
    let is_node = js_sys::global()
        .dyn_into::<js_sys::Object>()
        .map(|global| {
            wasm_config::Reflect::has(&global, &wasm_config::JsString::from("process"))
                .unwrap_or(false)
                && wasm_config::Reflect::get(&global, &wasm_config::JsString::from("process"))
                    .map(|process| {
                        wasm_config::Reflect::has(
                            &process,
                            &wasm_config::JsString::from("versions"),
                        )
                        .unwrap_or(false)
                    })
                    .unwrap_or(false)
        })
        .unwrap_or(false);

    is_node
}

// TODO Documentation
/// DOC
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn load_ws_module() -> Result<JsValue, JsError> {
    // Dynamically import the 'ws' module using JavaScript's import() function
    let import_script = "import('ws')";

    // Evaluate the `import` script in the JavaScript environment
    let import_promise: wasm_config::Promise = js_sys::eval(import_script)
        .map_err(|_| JsError::new("Failed to execute import for 'ws'"))?
        .dyn_into()
        .map_err(|_| JsError::new("Failed to convert eval result to Promise"))?;

    // Wait for the Promise to resolve and load the WebSocket module
    let ws_module = wasm_config::JsFuture::from(import_promise)
        .await
        .map_err(|_| JsError::new("Failed to load ws module via import"))?;

    // Return the WebSocket module
    Ok(ws_module)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let request_id = rand::thread_rng().gen::<u16>();
    let payload = encode_request(&request, Some(request_id))
        .map_err(|e| Error::Serialization(format!("Failed to serialize request: {}", e)))?;

    let ws_url = if node_address.starts_with("ws://") || node_address.starts_with("wss://") {
        node_address.to_string()
    } else {
        format!("ws://{}", node_address)
    };

    //  let ws: wasm_config::JsValue = if is_node() {
    // In Node.js, use the 'ws' WebSocket library via require
    let ws_module = load_ws_module();
    // log(&format!("{:?}", ws_module.uwnrap()));

    //     ws_module
    //         .dyn_into::<js_sys::Function>()
    //         .map_err(|_| {
    //             Error::WebSocketCreation("Failed to cast ws module to function".to_string())
    //         })?
    //         .call1(
    //             &wasm_bindgen::JsValue::NULL,
    //             &wasm_config::JsString::from(ws_url.as_str()),
    //         )
    //         .map_err(|_| Error::WebSocketCreation("Failed to create WebSocket".to_string()))?

    // } else {
    //     // In the browser, use the native WebSocket
    //     wasm_config::WebSocket::new(&ws_url)
    //         .map_err(|e| Error::WebSocketCreation(format!("Failed to create WebSocket: {:?}", e)))?
    //         .into() // Cast the WebSocket to a JsValue for consistency
    // };

    // // Create a promise to handle incoming WebSocket messages
    // let promise = wasm_config::Promise::new(&mut |resolve, reject| {
    //     let ws_clone = ws.clone();
    //     let payload_clone = payload.clone();

    //     // Set up onopen, onmessage, and onerror handlers
    //     let onopen = wasm_config::Closure::wrap(Box::new(move || {
    //         // Convert payload to JsValue using gloo_utils::format::JsValueSerdeExt
    //         let payload_js_value = wasm_config::JsValue::from_serde(&payload_clone).unwrap();

    //         if let Err(e) = js_sys::Reflect::get(&ws_clone, &wasm_config::JsString::from("send"))
    //             .unwrap()
    //             .dyn_into::<js_sys::Function>()
    //             .unwrap()
    //             .call1(&ws_clone, &payload_js_value)
    //         {
    //             reject
    //                 .call1(
    //                     &wasm_bindgen::JsValue::NULL,
    //                     &wasm_bindgen::JsValue::from_str(&format!(
    //                         "Failed to send message: {:?}",
    //                         e
    //                     )),
    //                 )
    //                 .unwrap();
    //         } else {
    //             let resolve_clone = resolve.clone();
    //             let onmessage =
    //                 wasm_config::Closure::wrap(Box::new(move |event: wasm_config::MessageEvent| {
    //                     let data = event.data().as_string().unwrap_or_default();
    //                     resolve_clone
    //                         .call1(
    //                             &wasm_bindgen::JsValue::NULL,
    //                             &wasm_bindgen::JsValue::from_str(&data),
    //                         )
    //                         .unwrap();
    //                 }) as Box<dyn FnMut(_)>);

    //             let ws_ref = ws_clone.unchecked_ref::<wasm_config::WebSocket>();
    //             ws_ref.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    //             onmessage.forget();

    //             let reject_clone = reject.clone();
    //             let onerror =
    //                 wasm_config::Closure::wrap(Box::new(move |event: wasm_bindgen::JsValue| {
    //                     let error_msg = event
    //                         .as_string()
    //                         .unwrap_or_else(|| "WebSocket error".to_string());
    //                     reject_clone
    //                         .call1(
    //                             &wasm_bindgen::JsValue::NULL,
    //                             &wasm_bindgen::JsValue::from_str(&error_msg),
    //                         )
    //                         .unwrap();
    //                 }) as Box<dyn FnMut(_)>);

    //             ws_ref.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    //             onerror.forget();
    //         }
    //     }) as Box<dyn FnMut()>);

    //     let ws_ref = ws.unchecked_ref::<wasm_config::WebSocket>();
    //     ws_ref.set_onopen(Some(onopen.as_ref().unchecked_ref()));
    //     onopen.forget();
    // });

    // let js_future = wasm_config::JsFuture::from(js_sys::Promise::resolve(&promise));
    // let onmessage = js_future
    //     .await
    //     .map_err(|e| Error::Response(format!("Failed to receive message: {:?}", e)))?;

    // // Cast the result to a MessageEvent
    // let message_event = onmessage
    //     .dyn_into::<wasm_config::MessageEvent>()
    //     .map_err(|_| Error::Response("Failed to cast to MessageEvent".to_string()))?;

    // // Extract the response data as a string
    // let data = message_event
    //     .data()
    //     .as_string()
    //     .ok_or_else(|| Error::Response("Failed to parse response data".to_string()))?;

    // Process the response
    let response = process_response(vec![], request_id).await?;

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
    const REQUEST_ID_START: usize = 0;
    const REQUEST_ID_END: usize = REQUEST_ID_START + 2;

    // // Extract Request ID from the response
    // let _request_id = u16::from_le_bytes(
    //     response_buf[REQUEST_ID_START..REQUEST_ID_END]
    //         .try_into()
    //         .expect("Failed to extract Request ID"),
    // );

    // // Check if request_id matches _request_id and return an error if not
    // if request_id != _request_id {
    //     return Err(Error::Response(format!(
    //         "Request ID mismatch: expected {}, got {}",
    //         request_id, _request_id
    //     )));
    // }

    // Deserialize the remaining response data
    let response: BinaryResponseAndRequest = bytesrepr::deserialize_from_slice(response_buf)?;
    Ok(response)
}
