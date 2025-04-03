# **Bitcoin**
This Bitcoin code uses blockchain technology with secure wallet creation, key encryption, and peer-to-peer networking. It includes an encrypted wallet class, a P2P server for blockchain management, and a WebSocket client for network interaction. This project demonstrates blockchain concepts in JavaScript.

## **Table of Contents**
- **Overview**
- **Setup**
- **Code Functions**
  - **Bitcoin.js Functions**
  - **SecureWallet.js Functions**
  - **Server.js Functions**
  - **Client.js Functions**
- **Testing the Wallet**
- **Testing the Blockchain**
- **Expected Results**

## **Overview**
This repository simulates a decentralized Bitcoin-like blockchain network. The project consists of four primary components:

- **Bitcoin.js**: Core blockchain functionality.
- **SecureWallet.js**: Handles wallet creation, encryption, and decryption.
- **Server.js**: Implements a P2P server to simulate blockchain nodes.
- **Client.js**: A WebSocket client that connects to the server and requests blockchain data.

### **Key Features:**
- **P2P Network**: Peers connect to each other to share blockchain data.
- **Wallet Generation**: Create a secure wallet with a unique address and private key.
- **Transaction Creation**: Generate, sign, and broadcast transactions between wallets.
- **Blockchain Syncing**: Synchronize the blockchain data across connected peers.
- **WebSocket Client**: A client script that can connect to a blockchain server and request blockchain data.

## **Setup**
### **Clone the repository:**
```bash
git clone https://github.com/m91nq1/Bitcoin.git
cd Bitcoin
```
### **Install dependencies:**
```bash
npm install
```
### **Run the server:**
```bash
node server.js 5001  # Run the server on port 5001
```
### **To simulate additional peers, run:**
```bash
node server.js 5002  # Run the server on port 5002
```
### **To test wallet functionality, run:**
```bash
node testWallet.js
```
### **To run the WebSocket client that connects to the server and requests blockchain data:**
```bash
node client.js
```

## **Code Functions**
### **Bitcoin.js Functions**
#### **1. Transaction:**
- **Description**: Handles the creation and management of transactions.
- **Functions:**
  - `addInput(address)`: Adds a transaction input.
  - `addOutput(address, amount)`: Adds a transaction output.
  - `sign(privateKey)`: Signs the transaction with the wallet's private key.
- **Expected Results**: A transaction object with inputs, outputs, and a valid signature.

#### **2. Blockchain:**
- **Description**: Contains the blockchain's logic, such as adding blocks and validating the chain.
- **Functions:**
  - `addTransaction(transaction)`: Adds a transaction to the blockchain.
  - `validateTransaction(transaction)`: Validates a transaction before adding it to the blockchain.
- **Expected Results**: A properly structured blockchain with valid transactions.

#### **3. syncBlockchain:**
- **Description**: Synchronizes the blockchain across multiple peers.
- **Expected Results**: The blockchain is updated if a peer's chain is longer or contains valid new blocks.

### **SecureWallet.js Functions**
#### **1. generateMnemonic():**
- **Description**: Generates a 256-bit mnemonic phrase for the wallet.
- **Expected Results**: A 256-bit mnemonic phrase used to create a wallet.

#### **2. generateFromMnemonic(mnemonic, password):**
- **Description**: Creates a wallet from a mnemonic phrase and encrypts the private key using a password.
- **Expected Results**: A wallet object with an encrypted private key and a mnemonic phrase.

#### **3. encryptPrivateKey(privateKey, password):**
- **Description**: Encrypts the wallet's private key using the password.
- **Expected Results**: The private key is encrypted and stored securely.

#### **4. decryptPrivateKey(password):**
- **Description**: Decrypts the wallet's private key using the provided password.
- **Expected Results**: Returns the decrypted private key if the password is correct.

#### **5. getAddress():**
- **Description**: Returns the wallet's public address derived from the mnemonic.
- **Expected Results**: A unique Ethereum-style address for the wallet.

#### **6. lock() & unlock(password):**
- **Description**: Locks and unlocks the wallet for added security.
- **Expected Results**: The wallet is locked after use, and can only be unlocked using the correct password.

### **Server.js Functions**
#### **1. I2PP2PNetwork:**
- **Description**: Manages the P2P network of blockchain nodes using WebSocket for peer communication.
- **Functions:**
  - `connectToPeer(peerUrl)`: Connects the node to another peer.
  - `initConnection(socket, req)`: Initializes a connection with a new peer.
  - `handleMessage(message, senderSocket)`: Handles incoming messages (transactions, blocks) from peers.
  - `syncBlockchain(receivedChain)`: Syncs the blockchain if the received chain is longer.
- **Expected Results**: Nodes can connect, send, and receive blockchain data.

#### **2. broadcastTransaction(tx):**
- **Description**: Broadcasts a transaction to all connected peers.
- **Expected Results**: All connected peers will receive the transaction and update their local blockchain.

### **Client.js Functions**
#### **1. WebSocket Client:**
- **Description**: A simple WebSocket client that connects to a WebSocket server, sends a message to request the blockchain, and listens for responses.
- **Expected Results:**
  - The WebSocket client connects to the server and sends a request to receive the blockchain.
  - The server responds with the blockchain data, and the client logs the received data.

## **Testing the Wallet**
To test wallet creation and encryption, run:
```bash
node testWallet.js
```
- **Wallet Generation**: The wallet will generate a unique address and encrypt the private key.
- **Unlocking the Wallet**: The wallet can be unlocked with the correct password, and you will see the address after unlocking.
- **Locking the Wallet**: Once locked, the wallet cannot be used until it is unlocked again.

## **Testing the Blockchain**
### **Run Multiple Nodes:**
- Start two or more peers by running:
```bash
node server.js 5001
node server.js 5002
```
- **Broadcast Transactions:**
  - Use the `sendtx` command to send a transaction from one wallet to another.
- **Syncing Blockchain:**
  - As peers receive the transaction, they will validate it and update their blockchain if necessary.






