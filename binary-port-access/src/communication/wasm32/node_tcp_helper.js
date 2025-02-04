(async () => {
  try {
    const net = require('net');
    const client = new net.Socket();
    const payload = Buffer.from(buffer_payload_placeholder);
    const host = '{host_placeholder}';
    const port = '{port_placeholder}';

    return new Promise((resolve, reject) => {
      const lengthBuffer = Buffer.alloc(4);
      lengthBuffer.writeUInt32LE(payload.length);
      client.connect(parseInt(port), host, () => {
        // Send the length of the payload
        client.write(lengthBuffer, (err) => {
          if (err) {
            console.error('Error sending length:', err.message);
            client.destroy();
            return;
          }
          // Now, send the actual payload
          client.write(payload, (err) => {
            if (err) {
              console.error('Error sending payload:', err.message);
            }
          });
        });
      });
      client.on('data', (data) => {
        resolve(data);
        client.destroy(); // Close connection after receiving response
      });
      client.on('error', (err) => {
        console.error('TCP connection error:', err.message);
        reject(new Error('TCP connection error: ' + err.message));
      });
      client.on('close', () => {});
    });
  } catch (err) {
    console.error('Error in TCP script:', err.message);
    throw new Error('Script execution error: ' + err.message);
  }
})();
