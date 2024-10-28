#[cfg(target_arch = "wasm32")]
pub(crate) const NODE_TCP_HELPER: &str = r#"
(async () => {{
    try {{
        const net = require('net');
        const client = new net.Socket();
        const payload = Buffer.from({buffer_payload});
        const host = '{host}';
        const port = '{port}';

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
    }}
)();"#;

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
