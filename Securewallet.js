const crypto = require('crypto');
const bip39 = require('bip39');
const { hdkey } = require('ethereumjs-wallet');
const scrypt = require('scrypt-js');
const aesjs = require('aes-js');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

// Enhanced configuration
const CONFIG = {
    MINING_DIFFICULTY: 4,
    MINING_REWARD: 100,
    STAKE_REWARD_PERCENTAGE: 0.1, // 10% of mining reward
    TRANSACTION_FEE_PERCENTAGE: 0.01, // 1% transaction fee
    BLOCK_TIME_TARGET: 60000, // 1 minute in ms
    SESSION_TIMEOUT: 300000 // 5 minutes
};

class SecureWallet {
    constructor() {
        this.mnemonic = bip39.generateMnemonic(256); 
        this.encryptedData = null;
        this.salt = crypto.randomBytes(32); 
        this.derivationPath = "m/44'/60'/0'/0/0";
        this.locked = true; 
        this.lastActivity = Date.now();
        this.privateKey = null;
    }

    async generateFromMnemonic(mnemonic, password) {
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }

        try {
            this.mnemonic = mnemonic;
            const seed = await bip39.mnemonicToSeed(mnemonic);
            const hdWallet = hdkey.fromMasterSeed(seed);
            const wallet = hdWallet.derivePath(this.derivationPath).getWallet();
            
            this.privateKey = wallet.getPrivateKey();
            try {
                await this.encryptPrivateKey(this.privateKey, password);
                this.locked = false;
                this.lastActivity = Date.now();
            } finally {
                this.privateKey.fill(0); 
            }
        } catch (err) {
            throw new Error(`Wallet generation failed: ${err.message}`);
        }
    }

    async encryptPrivateKey(privateKey, password) {
        try {
            const iv = crypto.randomBytes(16); 
            const key = await this.deriveKey(password);
            
            const privateKeyBytes = aesjs.utils.hex.toBytes(privateKey.toString('hex'));
            const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(iv.readUInt32BE(0))); 
            const encryptedBytes = aesCtr.encrypt(privateKeyBytes);
            
            this.encryptedData = Buffer.concat([iv, Buffer.from(encryptedBytes)]).toString('hex');
        } catch (err) {
            throw new Error(`Encryption failed: ${err.message}`);
        }
    }

    
    async decryptPrivateKey(password) {
        if (Date.now() - this.lastActivity > CONFIG.SESSION_TIMEOUT) {
            this.locked = true;
            throw new Error('Session expired. Please unlock wallet again.');
        }

        try {
            const encryptedBuffer = Buffer.from(this.encryptedData, 'hex');
            const iv = encryptedBuffer.slice(0, 16); 
            const encrypted = encryptedBuffer.slice(16); 
            
            const key = await this.deriveKey(password);
            const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(iv.readUInt32BE(0)));
            
            const decryptedBytes = aesCtr.decrypt(aesjs.utils.hex.toBytes(encrypted.toString('hex')));
            const decryptedKey = Buffer.from(decryptedBytes);
            
            this.lastActivity = Date.now();
            return decryptedKey;
        } catch (err) {
            throw new Error(`Decryption failed: ${err.message}`);
        }
    }

   
    async deriveKey(password) {
        const N = 32768, r = 8, p = 2; 
        return Buffer.from(
            await scrypt.scrypt(
                Buffer.from(password), 
                this.salt, 
                N, r, p, 32
            )
        );
    }

   
    getAddress() {
        const seed = bip39.mnemonicToSeedSync(this.mnemonic);
        const hdWallet = hdkey.fromMasterSeed(seed);
        return hdWallet.derivePath(this.derivationPath)
            .getWallet()
            .getAddressString();
    }

  
    lock() {
        this.locked = true;
    }

    
    async unlock(password) {
        try {
            await this.decryptPrivateKey(password); 
            this.locked = false;
            this.lastActivity = Date.now();
            return true;
        } catch (err) {
            throw new Error('Invalid password or decryption failed.');
        }
    }
}

module.exports = { SecureWallet };
