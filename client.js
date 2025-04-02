const WebSocket = require('ws');

// Replace with your server URL and port
const ws = new WebSocket('ws://localhost:5001');

ws.on('open', function open() {
    console.log('Connected to the WebSocket server');
    // Send a message to the server
    ws.send(JSON.stringify({ type: 'BLOCKCHAIN', data: 'Requesting Blockchain' }));
});

ws.on('message', function incoming(data) {
    console.log('Received data: ', data);
});

ws.on('close', function close() {
    console.log('Connection closed');
});
