const WebSocket = require('ws');
const { SecureWallet, Transaction, Blockchain } = require('./bitcoin');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const crypto = require('crypto');
const EventEmitter = require('events');
const readline = require('readline');

const AUTH_TOKEN = "secure-p2p-token";  // Change this to a strong secret token

// P2P Network Class with WebSocket & I2P Support
class I2PP2PNetwork extends EventEmitter {
    constructor(port) {
        super();
        this.sockets = new Map();  // Store active peer connections
        this.port = port;
        this.peerList = new Set();  // Track connected peers
        this.server = new WebSocket.Server({ port: this.port });

        // Handle incoming WebSocket connections
        this.server.on('connection', (socket, req) => this.initConnection(socket, req));

        // Handle WebSocket server errors
        this.server.on('error', (err) => this.emit('error', err));

        console.log(`P2P Server running on port ${port} (I2P Network Only)`);
    }

    // Connect to a new peer
    connectToPeer(peerUrl) {
        if (this.peerList.has(peerUrl)) {
            console.log(`Already connected to ${peerUrl}`);
            return;
        }

        try {
            const socket = new WebSocket(peerUrl);
            socket.on('open', () => {
                socket.send(JSON.stringify({ type: 'AUTH', token: AUTH_TOKEN }));
                this.initConnection(socket);
            });
            socket.on('error', (err) => console.log(`Connection error: ${err.message}`));
        } catch (err) {
            console.error(`Connection error: ${err.message}`);
        }
    }

    // Initialize the connection to a new peer
    initConnection(socket, req = null) {
        const peerAddress = req ? req.socket.remoteAddress : socket.url;
        const socketId = crypto.randomBytes(8).toString('hex');
        
        console.log(`New peer connected: ${peerAddress}`);

        // Wait for authentication
        socket.once('message', (message) => {
            try {
                const parsed = JSON.parse(message);
                if (parsed.type !== 'AUTH' || parsed.token !== AUTH_TOKEN) {
                    console.log(`Unauthorized peer rejected: ${peerAddress}`);
                    socket.close();
                    return;
                }

                // Add peer to active connections
                this.sockets.set(socket, { id: socketId, address: peerAddress, isAlive: true });
                console.log(`Peer authenticated: ${peerAddress}`);

                // Handle incoming messages
                socket.on('message', (message) => this.handleMessage(message, socket));
                socket.on('close', () => {
                    console.log(`Peer disconnected: ${peerAddress}`);
                    this.sockets.delete(socket);
                });
            } catch (err) {
                console.error('Authentication error:', err);
                socket.close();
            }
        });
    }

    // Handle incoming WebSocket messages
    handleMessage(message, senderSocket) {
        console.log("Received message:", message); // Debugging output
        
        try {
            const parsed = JSON.parse(message);

            if (parsed.type === 'BLOCKCHAIN') {
                this.syncBlockchain(parsed.data);
            }

            if (parsed.type === 'TRANSACTION') {
                this.handleTransaction(parsed.data);
            }
        } catch (err) {
            console.error('Message parsing error:', err);
        }
    }

    // Synchronize blockchain data from peers
    syncBlockchain(receivedChain) {
        try {
            if (typeof receivedChain !== "string") {
                console.error("Invalid blockchain data received:", receivedChain);
                return;
            }

            const parsedChain = JSON.parse(receivedChain);
            if (parsedChain.length > savjeeCoin.chain.length) {
                savjeeCoin.chain = parsedChain;
                console.log('Updated blockchain with a longer chain');
            }
        } catch (err) {
            console.error('Blockchain synchronization error:', err);
        }
    }

    // Handle incoming transaction
    handleTransaction(transactionData) {
        const tx = new Transaction();
        tx.fromJSON(transactionData);  // Assuming you have a method to parse transaction
        console.log(`Received new transaction: ${JSON.stringify(tx)}`);

        // Add to the local blockchain (this is simplified, you would need to do more here)
        savjeeCoin.addTransaction(tx);
    }
}

// Initialize and run the P2P network
const port = process.argv[2] || 5001;  // Allow port to be passed in as an argument, default is 5001
const myP2P = new I2PP2PNetwork(port);

// Automatically connect to another node if not the first instance
if (port !== 5001) {
    myP2P.connectToPeer(`ws://127.0.0.1:5001`);
} else {
    console.log("Waiting for other peers to connect...");
}

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down P2P network...');
    myP2P.server.close(() => {
        console.log('Server closed');
        process.exit();
    });
});

console.log(`P2P Blockchain node running on port ${port} (I2P Network Only)...`);
