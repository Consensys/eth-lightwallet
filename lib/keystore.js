var CryptoJS = require("crypto-js")
var Transaction = require('ethereumjs-tx')
var EC = require('elliptic').ec
var ec = new EC('secp256k1')
var Mnemonic = require('bitcore-mnemonic')

var KeyStore = function(mnemonic, password) {

    // Check if mnemonic is valid
    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH)){
      throw new Error("KeyStore: Invalid mnuemonic");
    }

    this.encSeed = KeyStore._encryptSeed(mnemonic, password);
    this.hdIndex = 0;
    this.encPrivKeys = {};
    this.addresses = [];

    // Initialize KeyStore with an address
    this.generateNewAddress(password);
}

KeyStore._encryptSeed = function (seed, password) {
    return CryptoJS.AES.encrypt(seed, password);
}

KeyStore._decryptSeed = function (encryptedKey, password) {
    var decryptedSeed = CryptoJS.AES.decrypt(encryptedKey, password);
    return decryptedSeed.toString(CryptoJS.enc.Latin1);
}

KeyStore._encryptKey = function (privKey, password) {
    var privKeyWordArray = CryptoJS.enc.Hex.parse(privKey)
    var encryptedKey = CryptoJS.AES.encrypt(privKeyWordArray, password);
    return encryptedKey;
}

KeyStore._decryptKey = function (encryptedKey, password) {
    var decryptedKey = CryptoJS.AES.decrypt(encryptedKey, password);
    return decryptedKey.toString(CryptoJS.enc.Hex);
}

KeyStore._computeAddressFromPrivKey = function (privKey) {
    var keyPair = ec.genKeyPair()
    keyPair._importPrivate(privKey, 'hex')
    var compact = false
    var pubKey = keyPair.getPublic(compact, 'hex').slice(2)
    var pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey)
    var hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 })
    var address = hash.toString(CryptoJS.enc.Hex).slice(24)

    return address
}

KeyStore.prototype._addPrivateKey = function (privKey, password) {

    var address = KeyStore._computeAddressFromPrivKey(privKey)
    var encPrivKey = KeyStore._encryptKey(privKey, password)

    this.encPrivKeys[address] = encPrivKey
    this.addresses.push(address)
}

// External API functions

KeyStore.prototype.getAddresses = function () {
    return this.addresses;
}

KeyStore.prototype.getSeed = function (password) {
  return KeyStore._decryptSeed(this.encSeed, password);
}

KeyStore.prototype.generateNewAddress = function(password) {
    if (!this.encSeed) {
        throw new Error("KeyStore.generateNewAddress: No seed set");
    }
    var words = KeyStore._decryptSeed(this.encSeed, password);
    var mn = new Mnemonic(words);
    var key = mn.toHDPrivateKey().derive(this.hdIndex++);

    this._addPrivateKey(key.privateKey.toString(), password);
}

KeyStore.prototype.signTx = function (rawTx, password, signingAddress) {

    if (this.addresses.length === 0) {
        throw new Error("KeyStore.signTx: No private keys in KeyStore.")
    }
    
    var address = ''
    if (signingAddress === undefined) {
        address = this.addresses[0]
    }
    else {
        if (this.encPrivKeys[signingAddress] === undefined) {
            throw new Error("KeyStore.signTx: Address not found in KeyStore")
        }
        address = signingAddress
    }

    var txCopy = new Transaction(new Buffer(rawTx, 'hex'))
    var encPrivKey = this.encPrivKeys[address]
    var privKey = KeyStore._decryptKey(encPrivKey, password)
    var addrFromPrivKey = KeyStore._computeAddressFromPrivKey(privKey)
    if (addrFromPrivKey !== address) {
        throw new Error("KeyStore.signTx: Decrypting private key failed!")
    }
    txCopy.sign(new Buffer(privKey, 'hex'));
    privKey = ''

    return txCopy.serialize().toString('hex')
}

module.exports = KeyStore;
