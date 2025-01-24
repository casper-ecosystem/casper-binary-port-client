#[cfg(target_arch = "wasm32")]
const NODE_TCP_HELPER: &str = include_str!("node_tcp_helper.js");
#[cfg(target_arch = "wasm32")]
pub(crate) fn generate_tcp_script(host: &str, port: &str, buffer_payload: &str) -> String {
    let script = NODE_TCP_HELPER
        .replace("{host_placeholder}", host)
        .replace("{port_placeholder}", port)
        .replace("buffer_payload_placeholder", buffer_payload);
    script
}

pub(crate) fn sanitize_input(input: &str) -> String {
    input
        .replace("\\", "\\\\") // Escape backslashes
        .replace("'", "\\'") // Escape single quotes
        .replace("\"", "\\\"") // Escape double quotes
        .replace("\n", "\\n") // Escape newlines
        .replace("\r", "\\r") // Escape carriage returns
        .replace("<", "\\<") // Escape less than
        .replace(">", "\\>") // Escape greater than
}
