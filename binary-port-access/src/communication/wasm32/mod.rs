use crate::communication::common::{encode_request, process_response, COUNTER, LENGTH_FIELD_SIZE};
use crate::Error;
use casper_binary_port::{BinaryRequest, BinaryResponseAndRequest};
use gloo_utils::format::JsValueSerdeExt;
use js_sys::{JsString, Promise, Reflect};
use node_tcp_helper::generate_tcp_script;
use std::cell::RefCell;
use wasm_bindgen::{prelude::Closure, prelude::*, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{MessageEvent, WebSocket};
pub mod node_tcp_helper;
use std::sync::atomic::Ordering;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_with_prefix(s: &str);
}
/// Logs an error message, prefixing it with "error wasm" and sends it to the console in JavaScript when running in a WebAssembly environment.
/// When running outside WebAssembly, it prints the error message to the standard output.
fn log(s: &str) {
    let prefixed_s = format!("log wasm {}", s);
    log_with_prefix(&prefixed_s);
}

/// Determines if the current environment is Node.js.
///
/// This function checks for the presence of the `process` global object and
/// verifies that it has a `versions` property, which is characteristic of
/// a Node.js environment.
///
/// # Returns
///
/// Returns `true` if the current environment is identified as Node.js, and
/// `false` otherwise.
///
/// # Notes
///
/// This function is compiled only when targeting the `wasm32` architecture,
/// ensuring that it is not included in builds for other targets.
fn is_node() -> bool {
    // Check if 'process' exists and if it has 'versions' property (which is present in Node.js)
    js_sys::global()
        .dyn_into::<js_sys::Object>()
        .map(|global| {
            Reflect::has(&global, &JsString::from("process")).unwrap_or(false)
                && Reflect::get(&global, &JsString::from("process"))
                    .map(|process| {
                        Reflect::has(&process, &JsString::from("versions")).unwrap_or(false)
                    })
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Opens a TCP connection to a specified binary server and sends a payload.
///
/// This asynchronous function establishes a TCP connection to a binary
/// server. It sends a specified payload and
/// waits for a response. The connection is made using a JavaScript script
/// executed in the WebAssembly context, leveraging Node.js's `net` module.
///
/// # Parameters
///
/// - `node_address`: A string that specifies the address of server
///   in the format "host:port". Typically "127.0.0.1:28101"
/// - `payload`: A `Vec<u8>` containing the data to be sent to the server.
/// - `request_id`: A unique identifier for the request, used to process
///   the response appropriately.
///
/// # Returns
///
/// This function returns a `Result` containing either a `BinaryResponseAndRequest`
/// on success or an `Error` on failure.
///
/// # Errors
///
/// This function may return an `Error` if:
/// - The JavaScript execution fails.
/// - The connection to the TCP server cannot be established.
/// - There is an error in sending or receiving data.
///
/// # Notes
///
/// This function is only compiled for the `wasm32` target, ensuring that
/// it does not affect builds for other architectures.
async fn open_tcp_connection(
    node_address: &str,
    payload: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
    use node_tcp_helper::sanitize_input;

    let parts: Vec<&str> = node_address.split(':').collect();
    let host = *parts
        .first()
        .ok_or_else(|| Error::Response("Missing host".to_string()))?;
    let port = *parts
        .last()
        .ok_or_else(|| Error::Response("Missing port".to_string()))?;

    // Prepare the payload buffer
    let buffer_payload = &format!("{payload:?}");

    let sanitized_buffer_payload = sanitize_input(buffer_payload);
    let sanitized_host = sanitize_input(host);
    let sanitized_port = sanitize_input(port);

    let tcp_script =
        generate_tcp_script(&sanitized_host, &sanitized_port, &sanitized_buffer_payload);

    // Execute the script in JavaScript context using eval (tcp_script is local but it requires "require" Js module not available in a classic function js_sys::Function)
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
        .map_err(|e| Error::Response(format!("TCP connection promise failed: {e:?}")))?;

    // Since the resolved value is a Buffer, convert it to a byte slice
    let response_bytes = js_sys::Uint8Array::new(&tcp_response).to_vec();

    // Read and process the response
    let response_buf = read_response(response_bytes).await?;
    // Now process the response using the request_id
    process_response(response_buf, request_id).await
}

/// Handles a WebSocket connection, sending a payload and awaiting a response.
///
/// This asynchronous function manages a WebSocket connection by sending a
/// specified payload to a server and waiting for a binary response. It first
/// sends the length of the payload, followed by the payload itself. The response
/// is received through a message event, processed, and returned.
///
/// # Parameters
///
/// - `web_socket`: An instance of `WebSocket` used to establish the connection
///   and communicate with the server.
/// - `payload`: A `Vec<u8>` containing the data to be sent over the WebSocket.
/// - `request_id`: A unique identifier for the request, used for processing the
///   response later.
///
/// # Returns
///
/// This function returns a `Result` that, on success, contains a
/// `BinaryResponseAndRequest`, and on failure, contains an `Error`.
///
/// # Errors
///
/// This function may return an `Error` if:
/// - The WebSocket connection fails to open.
/// - There is an error sending the length buffer or payload.
/// - The WebSocket encounters an error during communication.
/// - The received message cannot be processed correctly.
///
/// # Notes
///
/// This function is only compiled for the `wasm32` target, making it suitable
/// for WebAssembly applications where WebSocket communication is required.
async fn handle_websocket_connection(
    web_socket: &WebSocket,
    payload: Vec<u8>,
    request_id: u16,
) -> Result<BinaryResponseAndRequest, Error> {
    let payload_length = payload.len() as u32;
    let length_buffer = create_length_buffer(payload_length);

    let length_js_value = js_sys::Uint8Array::from(length_buffer.as_slice());

    // If socket is not opened
    let promise: Promise = if web_socket.ready_state() != WebSocket::OPEN {
        Promise::new(&mut |resolve, reject| {
            let web_socket_clone = web_socket.clone(); // Clone for the open closure
            let length_js_value = length_js_value.clone(); // Clone for the open closure
            let payload_clone = payload.clone(); // Clone for the open closure

            let reject_clone = reject.clone(); // Clone for the onerror closure
            let onerror = Closure::wrap(Box::new(move || {
                log("WebSocket encountered an error.");
                reject_clone
                    .call1(&JsValue::NULL, &"WebSocket error".into())
                    .unwrap();
            }) as Box<dyn FnMut()>);

            let reject_clone = reject.clone(); // Clone for the onclose closure
            let onclose = Closure::wrap(Box::new(move || {
                log("WebSocket was closed");
                reject_clone
                    .call1(&JsValue::NULL, &"WebSocket closed".into())
                    .unwrap();
            }) as Box<dyn FnMut()>);

            web_socket_clone.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            web_socket_clone.set_onclose(Some(onclose.as_ref().unchecked_ref()));
            onerror.forget(); // Prevent memory leak by forgetting the closure
            onclose.forget(); // Prevent memory leak by forgetting the closure

            // Set up onopen handler to send length and then payload
            let onopen = {
                Closure::wrap(Box::new(move || {
                    send_length_and_payload(
                        &web_socket_clone,
                        &length_js_value,
                        &payload_clone,
                        &resolve,
                        &reject,
                    );
                }) as Box<dyn FnMut()>)
            };
            web_socket.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget(); // Prevent memory leak by forgetting the closure
        })
    }
    // Socket is already opened
    else {
        Promise::new(&mut |resolve, reject| {
            let web_socket_clone = web_socket.clone(); // Clone for the closure
            let length_js_value = length_js_value.clone(); // Clone for the closure
            let payload_clone = payload.clone(); // Clone for the closure

            // Directly send length and payload
            send_length_and_payload(
                &web_socket_clone,
                &length_js_value,
                &payload_clone,
                &resolve,
                &reject,
            );
        })
    };
    let js_future = JsFuture::from(js_sys::Promise::resolve(&promise));

    // Await the resolved value from the promise
    match js_future.await {
        Ok(onmessage) => {
            // Read and process the response
            let response_bytes = extract_response_bytes(onmessage)?;
            let response_buf = read_response(response_bytes).await?;
            // Now process the response using the request_id
            process_response(response_buf, request_id).await
        }
        Err(e) => {
            log(&format!("Promise was rejected or failed: {:?}", e));
            Err(Error::Response(format!(
                "Failed to receive message due to rejection or error: {:?}",
                e
            )))
        }
    }
}

/// Creates a length buffer to represent the size of the payload.
///
/// This function initializes a buffer of fixed size, which is used to store
/// the length of the payload in little-endian byte order. It ensures that
/// the length can be correctly interpreted
///
/// # Parameters
///
/// - `payload_length`: The length of the payload to be encoded in the buffer,
///   represented as a `u32`. This value is converted to a byte array and
///   stored in the buffer.
///
/// # Returns
///
/// Returns a `Vec<u8>` containing the byte representation of the payload length,
/// with the length stored in little-endian format. The size of the vector is
/// determined by `LENGTH_FIELD_SIZE`.
fn create_length_buffer(payload_length: u32) -> Vec<u8> {
    let mut length_buffer = vec![0; LENGTH_FIELD_SIZE];
    length_buffer[..LENGTH_FIELD_SIZE].copy_from_slice(&payload_length.to_le_bytes());
    length_buffer
}

/// Sends the length of the payload followed by the payload itself over the WebSocket.
///
/// This function retrieves the WebSocket's `send` method and sends the specified
/// length and payload. It first sends the length of the payload encoded as a
/// `Uint8Array`, and then, upon successful transmission, it invokes the
/// `send_payload` function to send the actual payload data.
///
/// # Parameters
///
/// - `web_socket`: A reference to the `WebSocket` instance to which the data will be sent.
/// - `length_js_value`: A reference to a `Uint8Array` that contains the length of the payload,
///   which will be sent first.
/// - `payload`: A reference to the `Vec<u8>` containing the actual payload data
///   to be sent after the length.
/// - `resolve`: A reference to a JavaScript function that will be called to resolve the
///   promise if the send operation is successful.
/// - `reject`: A reference to a JavaScript function that will be called to reject the
///   promise if an error occurs during the send operation.
///
/// # Behavior
///
/// - If the WebSocket's `send` method is successfully retrieved and called with the
///   `length_js_value`, the function proceeds to send the actual payload using the
///   `send_payload` function.
/// - If an error occurs while sending the length, it logs the error and calls the
///   `reject` function, passing the error as an argument.
/// - If the `send` method cannot be found, it logs an error message and calls the
///   `reject` function with the corresponding error.
fn send_length_and_payload(
    web_socket: &WebSocket,
    length_js_value: &js_sys::Uint8Array,
    payload: &Vec<u8>,
    resolve: &js_sys::Function,
    reject: &js_sys::Function,
) {
    let send_func_result = js_sys::Reflect::get(web_socket, &JsString::from("send"))
        .and_then(|send_func| send_func.dyn_into::<js_sys::Function>());

    match send_func_result {
        Ok(send_func) => {
            if let Err(e) = send_func.call1(web_socket, length_js_value) {
                log(&format!("Failed to send length buffer: {:?}", e));
                reject.call1(&JsValue::NULL, &e).unwrap();
            } else {
                send_payload(&send_func, web_socket, payload, resolve, reject);
            }
        }
        Err(e) => {
            log("Failed to find WebSocket send function.");
            reject.call1(&JsValue::NULL, &e).unwrap(); // Use the cloned reject
        }
    }
}

/// Sends the payload data over the specified WebSocket.
///
/// This function converts the provided payload into a `Uint8Array` and uses the
/// provided `send_func` to send it over the WebSocket. If the send operation is
/// successful, it sets up a message handler; otherwise, it logs the error and
/// calls the provided reject function.
///
/// # Parameters
///
/// - `send_func`: A reference to the JavaScript function used to send data over the WebSocket.
/// - `web_socket`: A reference to the `WebSocket` instance through which the payload will be sent.
/// - `payload`: A reference to a `Vec<u8>` containing the data to be sent.
/// - `resolve`: A reference to a JavaScript function that will be called to resolve the
///   promise if the send operation is successful.
/// - `reject`: A reference to a JavaScript function that will be called to reject the
///   promise if an error occurs during the send operation.
fn send_payload(
    send_func: &js_sys::Function,
    web_socket: &WebSocket,
    payload: &Vec<u8>,
    resolve: &js_sys::Function,
    reject: &js_sys::Function,
) {
    let payload_array = js_sys::Uint8Array::from(payload.as_slice());
    if let Err(e) = send_func.call1(web_socket, &payload_array) {
        log(&format!("Failed to send payload: {:?}", e));
        reject.call1(&JsValue::NULL, &e).unwrap();
    } else {
        setup_message_handler(web_socket, resolve, reject);
    }
}

/// Sets up message and error handlers for the specified WebSocket.
///
/// This function configures the WebSocket to handle incoming messages and errors.
/// It defines two closures: one for handling WebSocket errors and another for
/// processing incoming messages. If an error occurs, it logs the error and calls
/// the provided reject function. When a message is received, it calls the
/// provided resolve function to process the message.
///
/// # Parameters
///
/// - `web_socket`: A reference to the `WebSocket` instance for which the handlers are being set up.
/// - `resolve`: A reference to a JavaScript function that will be called to resolve the
///   promise when a message is received.
/// - `reject`: A reference to a JavaScript function that will be called to reject the
///   promise if an error occurs during WebSocket communication.
fn setup_message_handler(
    web_socket: &WebSocket,
    resolve: &js_sys::Function,
    reject: &js_sys::Function,
) {
    let onerror = {
        let reject = reject.clone(); // Clone for use in onerror
        Closure::wrap(Box::new(move |event: wasm_bindgen::JsValue| {
            let error_msg = event
                .as_string()
                .unwrap_or_else(|| "WebSocket error".to_string());
            log(&format!("WebSocket error: {}", error_msg));
            reject
                .call1(&JsValue::NULL, &JsValue::from_str(&error_msg))
                .unwrap();
        }) as Box<dyn FnMut(_)>)
    };

    web_socket.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    onerror.forget(); // Prevent memory leak by forgetting the closure

    let onmessage = {
        let resolve = resolve.clone(); // Clone for use in onmessage
        Closure::wrap(Box::new(move |event: MessageEvent| {
            handle_message(event, resolve.clone());
        }) as Box<dyn FnMut(_)>)
    };
    web_socket.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget(); // Prevent memory leak by forgetting the closure
}

/// Handles incoming messages from the WebSocket.
///
/// This function is triggered when a message event occurs. It extracts the data
/// from the message event, which is expected to be a `Blob`. It then uses a
/// `FileReader` to read the `Blob` data as an `ArrayBuffer`. Upon successful
/// reading, it converts the data to a `Uint8Array` and resolves the provided
/// function with the binary response.
///
/// # Parameters
///
/// - `event`: The `MessageEvent` that contains the incoming data from the WebSocket.
/// - `resolve`: A reference to a JavaScript function that will be called with the
///   binary response once the `Blob` data has been successfully read.
fn handle_message(event: MessageEvent, resolve: js_sys::Function) {
    // Convert the event data to Blob
    let data: web_sys::Blob = event.data().dyn_into::<web_sys::Blob>().unwrap();

    // Create a FileReader to read the Blob
    let file_reader = web_sys::FileReader::new().unwrap(); // Create FileReader
    let resolve = resolve.clone(); // Clone for use in onload

    // Set up the onload closure
    let onload = {
        let file_reader = file_reader.clone(); // Clone here
        Closure::wrap(Box::new(move |_: web_sys::ProgressEvent| {
            let result = file_reader.result().unwrap();
            let array_buffer = result.dyn_into::<js_sys::ArrayBuffer>().unwrap();
            let uint8_array = js_sys::Uint8Array::new(&array_buffer);
            let response_bytes = uint8_array.to_vec();

            // Resolve with binary response
            resolve
                .call1(
                    &JsValue::NULL,
                    &wasm_bindgen::JsValue::from_serde(&response_bytes).unwrap_or_default(),
                )
                .unwrap();
        }) as Box<dyn FnMut(_)>)
    };

    // Set up the onload event for the FileReader
    file_reader.set_onload(Some(onload.as_ref().unchecked_ref()));
    file_reader.read_as_array_buffer(&data).unwrap(); // Ensure read call
    onload.forget(); // Prevent memory leak by forgetting the closure
}

/// Extracts response bytes from a JavaScript value.
///
/// This function takes a JavaScript value expected to be an `Array`, converts it
/// into a Rust vector of bytes, and returns it. If the conversion fails, it returns
/// an `Error` indicating that the expected format was not met.
///
/// # Parameters
///
/// - `onmessage`: A `JsValue` that should contain the response data in the form of a JavaScript `Array`.
///
/// # Returns
///
/// A `Result<Vec<u8>, Error>`, where the `Ok` variant contains the extracted bytes as a `Vec<u8>`,
/// and the `Err` variant contains an `Error` if the conversion fails.
fn extract_response_bytes(onmessage: JsValue) -> Result<Vec<u8>, Error> {
    let response_bytes = onmessage
        .dyn_into::<js_sys::Array>()
        .map_err(|_| Error::Response("Expected Array format for TCP response data".to_string()))?
        .to_vec()
        .into_iter()
        .map(|val| val.as_f64().unwrap_or(0.0) as u8)
        .collect::<Vec<u8>>();
    Ok(response_bytes)
}

/// Reads and processes a response from a byte vector, extracting the payload
/// based on a length prefix.
///
/// This asynchronous function reads a response in the form of a byte vector
/// that includes a length prefix. The length prefix indicates the size of the
/// actual payload that follows. The function validates the response format
/// and returns the extracted payload if the format is correct.
///
/// # Parameters
///
/// - `response_bytes`: A `Vec<u8>` containing the raw bytes of the response
///   received from a server. The first `LENGTH_FIELD_SIZE` bytes represent
///   the length of the subsequent payload.
///
/// # Returns
///
/// This function returns a `Result` that, on success, contains a `Vec<u8>`
/// representing the extracted payload. On failure, it contains an `Error`.
///
/// # Errors
///
/// This function may return an `Error` if:
/// - The input `response_bytes` does not contain enough bytes to read the
///   length prefix.
/// - The specified length of the payload exceeds the total number of bytes
///   available, indicating that the response is incomplete.
///
/// # Notes
///
/// Ensure that the `LENGTH_FIELD_SIZE` constant is properly defined to
/// match the expected size of the length prefix (4 bytes for
/// a `u32` for Casper binary protocol). This function is only compiled for the `wasm32` target,
/// making it suitable for WebAssembly applications where binary data
/// processing is required.
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

/// Sends a binary request to a specified node address, either via TCP or WebSocket.
///
/// This asynchronous function generates a unique request ID, encodes the given
/// binary request into a payload, and then sends the request to the specified
/// `node_address`. The method of transmission depends on the environment:
/// - In Node.js, it uses raw TCP connections via the `net` module.
/// - In non-Node.js environments (typically browsers), it uses WebSockets.
///   Note that browsers have CORS (Cross-Origin Resource Sharing) restrictions,
///   so the WebSocket requests should/may be addressed to a WebSocket proxy that
///   redirects the requests to the node's binary port.
///
/// # Parameters
///
/// - `node_address`: A `&str` representing the address of the node to which
///   the request will be sent. This should include the host and port (e.g.,
///   "localhost:28101").
/// - `request`: A `BinaryRequest` instance containing the data to be sent.
///
/// # Returns
///
/// This function returns a `Result` that, on success, contains a `BinaryResponseAndRequest`
/// indicating the response received from the node. On failure, it returns an `Error`.
///
/// # Errors
///
/// This function may return an `Error` if:
/// - There is an issue serializing the request into a binary format.
/// - The connection fails when trying to open a TCP connection in Node.js.
/// - The WebSocket connection cannot be created in non-Node.js environments.
/// - There are issues handling the WebSocket connection.
///
/// # Notes
///
/// This function is only compiled for the `wasm32` target, making it suitable
/// for WebAssembly applications where communication with a node server is required.
pub(crate) async fn send_request(
    node_address: &str,
    request: BinaryRequest,
) -> Result<BinaryResponseAndRequest, Error> {
    let request_id = COUNTER.fetch_add(1, Ordering::SeqCst); // Atomically increment the counter

    let payload = encode_request(&request, Some(request_id))
        .map_err(|e| Error::Serialization(format!("Failed to serialize request: {}", e)))?;

    thread_local! {
        static WS: RefCell<Option<WebSocket>> = const { RefCell::new(None) };
    }

    if is_node() {
        // In Node.js, use raw TCP with the `net` module for direct connection
        let tcp_result = open_tcp_connection(node_address, payload.clone(), request_id).await;
        match tcp_result {
            Ok(response) => Ok(response),
            Err(e) => Err(Error::Response(format!("TCP connection failed: {:?}", e))),
        }
    } else {
        let web_socket_url = if node_address.starts_with("ws://") {
            node_address.to_string()
        } else {
            format!("ws://{}", node_address)
        };

        // Check if WebSocket is already initialized and if it is open
        let mut web_socket = WS.with(|ws| ws.borrow_mut().clone());

        // Check if requested web_socket_url is still current_url or close it
        if web_socket.is_some() {
            let current_url = web_socket.as_ref().unwrap().url();

            let web_socket_url = if web_socket_url.contains("?") {
                // Add `/` only if there’s a query string but no `/` after the port
                let parts: Vec<&str> = web_socket_url.splitn(2, '?').collect();
                let base = parts[0];
                let query = parts[1];

                if base.ends_with('/') {
                    web_socket_url.clone()
                } else if base.contains(':') {
                    format!("{}/?{}", base, query)
                } else {
                    web_socket_url.clone()
                }
            } else {
                // If no query string, just ensure `/` exists
                if web_socket_url.ends_with('/') {
                    web_socket_url.clone()
                } else {
                    format!("{}/", web_socket_url)
                }
            };
            if current_url != web_socket_url {
                web_socket.as_ref().unwrap().close().map_err(|e| {
                    Error::WebSocketClose(format!("Failed to close WebSocket: {:?}", e))
                })?;
                web_socket = None;
            }
        }

        if web_socket.is_none()
            || web_socket.as_ref().unwrap().ready_state() == WebSocket::CLOSED
            || web_socket.as_ref().unwrap().ready_state() == WebSocket::CLOSING
        {
            // Create a new WebSocket if it doesn't exist or is not open
            web_socket = Some(WebSocket::new(&web_socket_url).map_err(|e| {
                Error::WebSocketCreation(format!("Failed to create WebSocket: {:?}", e))
            })?);

            let web_socket_clone = web_socket.clone();
            // Save the new WebSocket in the thread-local variable
            WS.with(|ws| {
                *ws.borrow_mut() = web_socket_clone;
            });
        }

        let web_socket_ref = web_socket.as_ref().unwrap();
        if web_socket_ref.ready_state() == WebSocket::CONNECTING
            || web_socket_ref.ready_state() == WebSocket::OPEN
        {
            // Setup error and close event handlers to update WebSocket state
            let response = handle_websocket_connection(web_socket_ref, payload, request_id).await?;
            Ok(response)
        } else {
            Err(Error::WebSocketSend("WebSocket is not open".to_string()))
        }
    }
}
