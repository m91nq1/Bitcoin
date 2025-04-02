const { SecureWallet } = require('./Securewallet'); 

async function testWallet() {
    const myWallet = new SecureWallet();

    console.log("New Wallet Address:", myWallet.getAddress());
    
    const password = 'myStrongPassword123'; 
    
    
    await myWallet.generateFromMnemonic(myWallet.mnemonic, password);
    console.log("Wallet generated and encrypted.");
    
    // Attempt to unlock with the correct password
    const unlocked = await myWallet.unlock(password);
    if (unlocked) {
        console.log("Wallet unlocked successfully!");
        console.log("Wallet Address after unlocking:", myWallet.getAddress());
    } else {
        console.log("Failed to unlock wallet.");
    }

    
    myWallet.lock();
    console.log("Wallet locked.");

    
    try {
        await myWallet.unlock('wrongPassword');
    } catch (err) {
        console.log("Error unlocking wallet with wrong password:", err.message);
    }
}

testWallet().catch(err => console.error("Error:", err));
