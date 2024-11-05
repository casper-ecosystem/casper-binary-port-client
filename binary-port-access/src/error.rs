use casper_types::bytesrepr;
use thiserror::Error;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

#[derive(Error, Debug)]
/// Errors
pub enum Error {
    /// Bytesrepr serialization error.
    #[error(transparent)]
    Bytesrepr(#[from] bytesrepr::Error),

    /// IO error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error in the binary port.
    #[error(transparent)]
    BinaryPort(#[from] casper_binary_port::Error),

    /// Error when handling the response from the binary port.
    #[error("Failed to handle response: {0}")]
    Response(String),

    /// Error related to network timeout.
    #[error("Failed to handle network response: {0}")]
    TimeoutError(String),

    /// Error related to http request.
    #[error("Failed to send http request: {0}")]
    HttpRequest(String),

    /// Error related to http response.
    #[error("Failed to handle http response: {0}")]
    HttpResponse(String),

    /// WebSocket creation error.
    #[error("Failed to create WebSocket: {0}")]
    WebSocketCreation(String),

    /// WebSocket creation error.
    #[error("Failed to create WebSocket: {0}")]
    WebSocketSend(String),

    /// JavaScript-related error.
    #[error("JavaScript error: {0}")]
    JsError(String),

    /// General serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Generic error for other cases.
    #[error("Other error: {0}")]
    Other(String),
}

#[cfg(target_arch = "wasm32")]
impl From<JsValue> for Error {
    fn from(js_value: JsValue) -> Self {
        Error::JsError(
            js_value
                .as_string()
                .unwrap_or_else(|| "Unknown JavaScript error".to_string()),
        )
    }
}
