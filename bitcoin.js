const crypto = require('crypto');
const bip39 = require('bip39');
const { hdkey } = require('ethereumjs-wallet');
const scrypt = require('scrypt-js');
const aesjs = require('aes-js');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

const CONFIG = {
    MINING_DIFFICULTY: 4,
    MINING_REWARD: 100,
    STAKE_REWARD_PERCENTAGE: 0.1,
    TRANSACTION_FEE_PERCENTAGE: 0.01,
    BLOCK_TIME_TARGET: 60000,
    SESSION_TIMEOUT: 300000 
};

class SecureWallet {
    constructor() {
        this.mnemonic = bip39.generateMnemonic(256);
        this.encryptedData = null;
        this.salt = crypto.randomBytes(32);
        this.derivationPath = "m/44'/60'/0'/0/0";
        this.locked = true;
        this.lastActivity = Date.now();
    }

    async generateFromMnemonic(mnemonic, password) {
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }

        this.mnemonic = mnemonic;
        const seed = await bip39.mnemonicToSeed(mnemonic);
        const hdWallet = hdkey.fromMasterSeed(seed);
        const wallet = hdWallet.derivePath(this.derivationPath).getWallet();
        const privateKey = wallet.getPrivateKey();

        await this.encryptPrivateKey(privateKey, password);
        privateKey.fill(0);
        this.locked = false;
        this.lastActivity = Date.now();
    }

    async encryptPrivateKey(privateKey, password) {
        const iv = crypto.randomBytes(16);
        const key = await this.deriveKey(password);
        const privateKeyBytes = aesjs.utils.hex.toBytes(privateKey.toString('hex'));
        const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(iv));
        const encryptedBytes = aesCtr.encrypt(privateKeyBytes);
        this.encryptedData = Buffer.concat([iv, Buffer.from(encryptedBytes)]).toString('hex');
    }

    async decryptPrivateKey(password) {
        if (Date.now() - this.lastActivity > CONFIG.SESSION_TIMEOUT) {
            this.locked = true;
            throw new Error('Session expired. Please unlock wallet again.');
        }

        const encryptedBuffer = Buffer.from(this.encryptedData, 'hex');
        const iv = encryptedBuffer.slice(0, 16);
        const encrypted = encryptedBuffer.slice(16);
        const key = await this.deriveKey(password);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(iv));
        const decryptedBytes = aesCtr.decrypt(aesjs.utils.hex.toBytes(encrypted.toString('hex')));

        this.lastActivity = Date.now();
        return Buffer.from(decryptedBytes);
    }

    async deriveKey(password) {
        return Buffer.from(
            await scrypt.scrypt(Buffer.from(password), this.salt, 32768, 8, 2, 32)
        );
    }

    getAddress() {
        const seed = bip39.mnemonicToSeedSync(this.mnemonic);
        const hdWallet = hdkey.fromMasterSeed(seed);
        return hdWallet.derivePath(this.derivationPath).getWallet().getAddressString();
    }

    lock() {
        this.locked = true;
    }
}

class Transaction {
    constructor(fromAddress, toAddress, amount, nonce = 0) {
        if (amount <= 0) throw new Error('Amount must be positive');
        if (!toAddress) throw new Error('Recipient address required');

        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
        this.amount = amount;
        this.nonce = nonce;
        this.timestamp = Date.now();
        this.fee = Math.max(1, amount * CONFIG.TRANSACTION_FEE_PERCENTAGE);
        this.hash = this.calculateHash();
        this.signature = null;
    }

    calculateHash() {
        return crypto.createHash('sha3-256')
            .update(this.fromAddress + this.toAddress + this.amount + this.nonce + this.timestamp + this.fee)
            .digest('hex');
    }
}

class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.pendingTransactions = [];
    }

    createGenesisBlock() {
        return new Block(Date.now(), [new Transaction(null, '0x000...', 1000000)], '0', 'genesis');
    }
}

module.exports = { SecureWallet, Transaction, Blockchain };
