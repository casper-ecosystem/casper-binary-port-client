#[cfg(target_arch = "wasm32")]
use crate::communication::common::{encode_request, process_response, LENGTH_FIELD_SIZE};
#[cfg(target_arch = "wasm32")]
use crate::Error;
#[cfg(target_arch = "wasm32")]
use casper_binary_port::{BinaryRequest, BinaryResponseAndRequest};
#[cfg(target_arch = "wasm32")]
use gloo_utils::format::JsValueSerdeExt;
#[cfg(target_arch = "wasm32")]
use js_sys::{JsString, Promise, Reflect};
#[cfg(target_arch = "wasm32")]
use rand::Rng;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{prelude::Closure, prelude::*, JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{MessageEvent, WebSocket};
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_with_prefix(s: &str);
}
/// Logs an error message, prefixing it with "error wasm" and sends it to the console in JavaScript when running in a WebAssembly environment.
/// When running outside WebAssembly, it prints the error message to the standard output.
#[cfg(target_arch = "wasm32")]
fn log(s: &str) {
    #[cfg(target_arch = "wasm32")]
    let prefixed_s = format!("log wasm {}", s);
    #[cfg(target_arch = "wasm32")]
    log_with_prefix(&prefixed_s);
    #[cfg(not(target_arch = "wasm32"))]
    println!("{}", s);
}

// TODO Documentation
/// DOC
#[cfg(target_arch = "wasm32")]
fn is_node() -> bool {
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
        let resolve_clone = resolve.clone(); // Clone to use later
        let reject_clone = reject.clone(); // Clone to use later

        // Prepare length buffer using LENGTH_FIELD_SIZE
        let payload_length = payload.len() as u32;
        let mut length_buffer = vec![0; LENGTH_FIELD_SIZE];
        length_buffer[..LENGTH_FIELD_SIZE].copy_from_slice(&payload_length.to_le_bytes());

        log("Payload length buffer prepared.");

        // 1. Send the length buffer first
        let length_js_value = js_sys::Uint8Array::from(length_buffer.as_slice());

        let payload_clone = payload.clone(); // Clone the payload for sending

        // Set up onopen handler to send length and then payload
        let onopen = Closure::wrap(Box::new(move || {
            log("WebSocket connection opened, attempting to send length buffer.");

            // Use ws_clone in the closure directly
            let send_func_result = js_sys::Reflect::get(&ws_clone, &JsString::from("send"))
                .and_then(|send_func| send_func.dyn_into::<js_sys::Function>());

            match send_func_result {
                Ok(send_func) => {
                    // Send length buffer
                    if let Err(e) = send_func.call1(&ws_clone, &length_js_value) {
                        log(&format!("Failed to send length buffer: {:?}", e));
                        reject_clone.call1(&JsValue::NULL, &e).unwrap();
                    } else {
                        log("Length buffer sent successfully, now sending payload.");

                        // 2. Send the payload after the length buffer has been sent
                        let payload_array = js_sys::Uint8Array::from(payload_clone.as_slice());

                        if let Err(e) = send_func.call1(&ws_clone, &payload_array) {
                            log(&format!("Failed to send payload: {:?}", e));
                            reject_clone.call1(&JsValue::NULL, &e).unwrap();
                        } else {
                            log("Payload sent successfully, setting up message handler.");

                            let onerror = {
                                let reject_clone = reject_clone.clone(); // Clone for use in onerror
                                Closure::wrap(Box::new(move |event: wasm_bindgen::JsValue| {
                                    let error_msg = event
                                        .as_string()
                                        .unwrap_or_else(|| "WebSocket error".to_string());
                                    log(&format!("WebSocket error: {}", error_msg));
                                    reject_clone
                                        .call1(&JsValue::NULL, &JsValue::from_str(&error_msg))
                                        .unwrap();
                                })
                                    as Box<dyn FnMut(_)>)
                            };

                            ws_clone.set_onerror(Some(onerror.as_ref().unchecked_ref()));
                            onerror.forget(); // Prevent memory leak by forgetting the closure

                            let onmessage = {
                                let resolve_clone = resolve_clone.clone(); // Clone for use in onmessage
                                Closure::wrap(Box::new(move |event: MessageEvent| {
                                    log("Message received from WebSocket.");

                                    // Convert the event data to Blob
                                    let data: web_sys::Blob =
                                        event.data().dyn_into::<web_sys::Blob>().unwrap();

                                    // Create a FileReader to read the Blob
                                    let file_reader = web_sys::FileReader::new().unwrap(); // Create FileReader
                                    let resolve_clone = resolve_clone.clone(); // Clone for use in onload

                                    // Set up the onload closure with the file_reader borrowed
                                    let onload = {
                                        let file_reader_clone = file_reader.clone(); // Clone here
                                        Closure::wrap(Box::new(move |_: web_sys::ProgressEvent| {
                                            // log(
                                            //     "Blob read successfully, converting to Uint8Array.",
                                            // );

                                            // Get the result of the FileReader as ArrayBuffer
                                            let result = file_reader_clone.result().unwrap();
                                            let array_buffer =
                                                result.dyn_into::<js_sys::ArrayBuffer>().unwrap();
                                            let uint8_array =
                                                js_sys::Uint8Array::new(&array_buffer);

                                            // Convert Uint8Array to Vec<u8>
                                            let response_bytes = uint8_array.to_vec();

                                            // log(&format!("Received bytes: {:?}", response_bytes));

                                            // Resolve with binary response
                                            resolve_clone
                                                .call1(
                                                    &JsValue::NULL,
                                                    &wasm_bindgen::JsValue::from_serde(
                                                        &response_bytes,
                                                    )
                                                    .unwrap_or_default(),
                                                )
                                                .unwrap();
                                        })
                                            as Box<dyn FnMut(_)>)
                                    };

                                    // Set up the onload event for the FileReader
                                    file_reader.set_onload(Some(onload.as_ref().unchecked_ref()));
                                    file_reader.read_as_array_buffer(&data).unwrap(); // Ensure read call
                                    onload.forget(); // Prevent memory leak by forgetting the closure
                                })
                                    as Box<dyn FnMut(_)>)
                            };

                            ws_clone.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
                            onmessage.forget(); // Prevent memory leak by forgetting the closure
                        }
                    }
                }
                Err(e) => {
                    log("Failed to find WebSocket send function.");
                    reject_clone.call1(&JsValue::NULL, &e).unwrap(); // Use the cloned reject
                }
            }
        }) as Box<dyn FnMut()>);

        let ws_ref = web_socket.unchecked_ref::<WebSocket>();
        ws_ref.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        log("WebSocket set_onopen event registered.");
        onopen.forget(); // Prevent memory leak by forgetting the closure
    });

    let js_future = JsFuture::from(js_sys::Promise::resolve(&promise));

    // Await the resolved value from the promise
    let onmessage = js_future
        .await
        .map_err(|e| Error::Response(format!("Failed to receive message: {:?}", e)))?;

    let response_data = onmessage
        .dyn_into::<js_sys::Array>()
        .map_err(|_| Error::Response("Expected Array format for TCP response data".to_string()))?
        .to_vec()
        .into_iter()
        .map(|val| val.as_f64().unwrap_or(0.0) as u8)
        .collect::<Vec<u8>>();

    log(&format!("read_response {:?}", response_data));

    // Process the response data as in the original function
    let response_buf = read_response(response_data).await?;
    process_response(response_buf.into(), request_id).await
}

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

// TODO Documentation
/// DOC
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
