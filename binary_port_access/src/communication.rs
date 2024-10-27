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
#[cfg(target_arch = "wasm32")]
pub use gloo_utils::format::JsValueSerdeExt;
#[cfg(target_arch = "wasm32")]
pub use js_sys::{JsString, Promise, Reflect};
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
pub use wasm_bindgen::{prelude::Closure, prelude::*, JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
pub use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
pub use web_sys::{MessageEvent, WebSocket};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_with_prefix(s: &str);
}
/// Logs an error message, prefixing it with "error wasm" and sends it to the console in JavaScript when running in a WebAssembly environment.
/// When running outside WebAssembly, it prints the error message to the standard output.
pub fn log(s: &str) {
    #[cfg(target_arch = "wasm32")]
    let prefixed_s = format!("log wasm {}", s);
    #[cfg(target_arch = "wasm32")]
    log_with_prefix(&prefixed_s);
    #[cfg(not(target_arch = "wasm32"))]
    println!("{}", s);
}

// TODO[RC]: Do not hardcode this.
pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);

#[cfg(not(target_arch = "wasm32"))]
const TIMEOUT_DURATION: Duration = Duration::from_secs(5);
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
            Reflect::has(&global, &JsString::from("process")).unwrap_or(false)
                && Reflect::get(&global, &JsString::from("process"))
                    .map(|process| {
                        Reflect::has(&process, &JsString::from("versions")).unwrap_or(false)
                    })
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    // log(&format!("is_node {:?}", is_node));
    is_node
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let request_id = rand::thread_rng().gen::<u16>();
    let payload = encode_request(&request, Some(request_id))
        .map_err(|e| Error::Serialization(format!("Failed to serialize request: {}", e)))?;

    if is_node() {
        // In Node.js, use raw TCP with the `net` module for direct connection
        let tcp_result = open_tcp_connection(node_address, payload.clone(), request_id).await;
        match tcp_result {
            Ok(response) => return Ok(response),
            Err(e) => return Err(Error::Response(format!("TCP connection failed: {:?}", e))),
        }
    } else {
        // In the browser or non-Node.js environments, use WebSocket
        let ws_url = format!("ws://{}", node_address);
        let web_socket = WebSocket::new(&ws_url).map_err(|e| {
            Error::WebSocketCreation(format!("Failed to create WebSocket: {:?}", e))
        })?;

        let response = handle_websocket_connection(web_socket, payload, request_id).await?;
        return Ok(response);
    }
}

#[cfg(target_arch = "wasm32")]
async fn open_tcp_connection(
    node_address: &str,
    payload: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
    let tcp_script = format!(
        r#"
(async () => {{
    try {{
        const net = require('net');
        const client = new net.Socket();
        const payload = Buffer.from({:?});
        const node_address = '{node_address}';
        const [host, port] = node_address.split(':');

        // console.log('TCP Client created:');
        // console.log('Payload to send:', payload);
        // console.log('node_address', node_address);
        // console.log('host', host);
        // console.log('port', port);
        // console.log('Promise available:', typeof Promise !== 'undefined');

        return new Promise((resolve, reject) => {{
            // console.log('Connecting to TCP server at', host, port);

            const lengthBuffer = Buffer.alloc(4);
            lengthBuffer.writeUInt32LE(payload.length);
            client.connect(parseInt(port), host, () => {{
                // console.log('Connected to TCP server');

                // First, send the length of the payload
                client.write(lengthBuffer, (err) => {{
                    if (err) {{
                        console.error('Error sending length:', err.message);
                        client.destroy();
                        return;
                    }}
                    // console.log('Length of payload sent');

                    // Now, send the actual payload
                    client.write(payload, (err) => {{
                        if (err) {{
                            console.error('Error sending payload:', err.message);
                        }} else {{
                            // console.log('Payload sent');
                        }}
                    }});
                }});
            }});

            client.on('data', (data) => {{
                // console.log('Data received from server:', data);
                resolve(data);
                client.destroy();  // Close connection after receiving response
            }});

            client.on('error', (err) => {{
                console.error('TCP connection error:', err.message);
                reject(new Error('TCP connection error: ' + err.message));
            }});

            client.on('close', () => {{
                // console.log('TCP connection closed');
            }});
        }});
    }} catch (err) {{
        console.error('Error in TCP script:', err.message);
        throw new Error('Script execution error: ' + err.message);
    }}
}})();
    "#,
        payload
    );

    // Execute the script in JavaScript context using eval
    let tcp_promise: Promise = js_sys::eval(&tcp_script)
        .map_err(|err| {
            log("Failed to execute TCP script in eval");
            log(&err.as_string().unwrap());
            Error::Response("Failed to execute TCP script".to_string())
        })?
        .dyn_into()
        .map_err(|err| {
            log("Failed to cast eval result to Promise");
            log(&err.as_string().unwrap());
            Error::Response("Failed to cast eval result to Promise".to_string())
        })?;

    let js_future = JsFuture::from(tcp_promise);
    let tcp_response = js_future
        .await
        .map_err(|e| Error::Response(format!("TCP connection promise failed: {:?}", e)))?;

    // Since the resolved value is a Buffer, convert it to a byte slice
    let response_bytes = js_sys::Uint8Array::new(&tcp_response).to_vec();

    // Log the received response bytes for debugging
    // log(&format!("Received response data: {:?}", response_bytes));

    // Read and process the response
    let response_buf = read_response(response_bytes).await?;
    // Now process the response using the request_id
    process_response(response_buf.into(), request_id).await
}

#[cfg(target_arch = "wasm32")]
async fn handle_websocket_connection(
    web_socket: WebSocket,
    payload: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
    let promise = Promise::new(&mut |resolve, reject| {
        let ws_clone = web_socket.clone();
        let payload_clone = payload.clone();

        // Set up onopen, onmessage, and onerror handlers
        let onopen = Closure::wrap(Box::new(move || {
            log("WebSocket connection opened, attempting to send payload.");

            // Convert payload to JsValue using gloo_utils::format::JsValueSerdeExt
            let payload_js_value = wasm_bindgen::JsValue::from_serde(&payload_clone).unwrap();
            log("Payload serialized to JsValue.");

            // Send payload
            match js_sys::Reflect::get(&ws_clone, &JsString::from("send"))
                .and_then(|send_func| send_func.dyn_into::<js_sys::Function>())
            {
                Ok(send_func) => {
                    if let Err(e) = send_func.call1(&ws_clone, &payload_js_value) {
                        log(&format!("Failed to send payload: {:?}", e));
                        reject
                            .call1(
                                &wasm_bindgen::JsValue::NULL,
                                &wasm_bindgen::JsValue::from_str(&format!(
                                    "Failed to send message: {:?}",
                                    e
                                )),
                            )
                            .unwrap();
                    } else {
                        log("Payload sent successfully, setting up message handler.");

                        let resolve_clone = resolve.clone();
                        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
                            log("Message received from WebSocket.");

                            let data = event.data().as_string().unwrap_or_default();
                            resolve_clone
                                .call1(
                                    &wasm_bindgen::JsValue::NULL,
                                    &wasm_bindgen::JsValue::from_str(&data),
                                )
                                .unwrap();
                        })
                            as Box<dyn FnMut(_)>);

                        let ws_ref = ws_clone.unchecked_ref::<WebSocket>();
                        ws_ref.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
                        onmessage.forget();

                        let reject_clone = reject.clone();
                        let onerror = Closure::wrap(Box::new(move |event: wasm_bindgen::JsValue| {
                            let error_msg = event
                                .as_string()
                                .unwrap_or_else(|| "WebSocket error".to_string());
                            log(&format!("WebSocket error: {}", error_msg));
                            reject_clone
                                .call1(
                                    &wasm_bindgen::JsValue::NULL,
                                    &wasm_bindgen::JsValue::from_str(&error_msg),
                                )
                                .unwrap();
                        })
                            as Box<dyn FnMut(_)>);

                        ws_ref.set_onerror(Some(onerror.as_ref().unchecked_ref()));
                        onerror.forget();
                    }
                }
                Err(e) => {
                    log("Failed to find WebSocket send function.");
                    reject.call1(&wasm_bindgen::JsValue::NULL, &e).unwrap();
                }
            }
        }) as Box<dyn FnMut()>);

        let ws_ref = web_socket.unchecked_ref::<WebSocket>();
        ws_ref.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        log("WebSocket set_onopen event registered.");

        onopen.forget();
    });
    log("Promise created for WebSocket interaction.");

    let js_future = JsFuture::from(js_sys::Promise::resolve(&promise));
    let onmessage = js_future
        .await
        .map_err(|e| Error::Response(format!("Failed to receive message: {:?}", e)))?;

    // Cast the result to a MessageEvent
    let message_event = onmessage
        .dyn_into::<MessageEvent>()
        .map_err(|_| Error::Response("Failed to cast to MessageEvent".to_string()))?;

    // Extract the response data as a string
    let data = message_event
        .data()
        .as_string()
        .ok_or_else(|| Error::Response("Failed to parse response data".to_string()))?;

    // Process the response
    let response = process_response(data.as_bytes().into(), request_id).await?;
    log("response");
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

#[cfg(target_arch = "wasm32")]
#[cfg(target_arch = "wasm32")]
async fn read_response(response_bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    // Ensure we have enough bytes for the length field
    if response_bytes.len() < LENGTH_FIELD_SIZE {
        return Err(Error::Response(
            "Insufficient data for length prefix".to_string(),
        ));
    }

    // Read the length prefix (first 4 bytes) as a little-endian u32
    let response_length =
        u32::from_le_bytes(response_bytes[0..LENGTH_FIELD_SIZE].try_into().unwrap()) as usize;

    // Ensure the buffer is large enough for the specified length
    if response_bytes.len() < LENGTH_FIELD_SIZE + response_length {
        return Err(Error::Response("Incomplete response data".to_string()));
    }

    // Extract the actual response payload
    let response_buf =
        response_bytes[LENGTH_FIELD_SIZE..LENGTH_FIELD_SIZE + response_length].to_vec();

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
