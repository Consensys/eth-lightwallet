var CryptoJS = require("crypto-js")
var Transaction = require('ethereumjs-tx')
var EC = require('elliptic').ec
var ec = new EC('secp256k1')
var Mnemonic = require('bitcore-mnemonic')

// If node map storage to node-persist, if browser map storage to localStorage
if (process.env.NODE_ENV === 'browser'){
  var storage = window.localStorage
} else {
  var storage = require('node-persist')
  storage.initSync()
}

var KeyStore = function(persist, password, mnemonic) {

    // Enforces singleton
    if (typeof KeyStore.instance === 'object') {
        return KeyStore.instance;
    }

    this.encSeed = null
    this.hdIndex = 0;
    this.encPrivKeys = {};
    this.addresses = [];

    var passwordExist = (typeof password !== 'undefined')
    var mnemonicExist = (typeof mnemonic !== 'undefined')

    if (passwordExist && mnemonicExist) {
        this._constructFromMnemonic(mnemonic, password)
    }

    if (passwordExist && !mnemonicExist) {
        this._constructFromGenSeed(password)
    }

    if (!passwordExist && !mnemonicExist) {
        this._constructFromStorage()
    }

    if (persist) {
        this._constructPersistentStorage()
    }

    KeyStore.instance = this

    return this
}

KeyStore.prototype._constructFromMnemonic = function (mnemonic, password) {
    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH)){
      throw new Error("KeyStore: Invalid mnuemonic");
    }

    this.encSeed = KeyStore._encryptSeed(mnemonic, password);
}

KeyStore.prototype._constructFromGenSeed = function (password) {
    var mnemonic = KeyStore.generateRandomSeed()
    this.encSeed = KeyStore._encryptSeed(mnemonic, password);
}

KeyStore.prototype._constructFromStorage = function () {
    var item = storage.getItem('eljs.encSeed')

    if (item === null || typeof item === 'undefined') {
      throw new Error("KeyStore._constructFromStorage: No stored wallet exists");
    }

    this.encSeed = storage.getItem('eljs.encSeed')
    this.hdIndex = storage.getItem('eljs.hdIndex')
    this.encPrivKeys = storage.getItem('eljs.encPrivKeys')
    this.addresses = storage.getItem('eljs.addresses')
}

KeyStore.prototype._constructPersistentStorage = function () {

    // Set initial values to storage
    this._saveToStorage()

    var origGenerateNewAddress = KeyStore.prototype.generateNewAddress

    // Modifies functions which change the object and saves them to storage
    KeyStore.prototype.generateNewAddress = function() {
        origGenerateNewAddress.apply(this, arguments);
        this._saveToStorage()
    }

}

KeyStore.prototype._saveToStorage = function () {
    storage.setItem('eljs.encSeed', this.encSeed)
    storage.setItem('eljs.hdIndex', this.hdIndex)
    storage.setItem('eljs.encPrivKeys', this.encPrivKeys)
    storage.setItem('eljs.addresses', this.addresses)
}

KeyStore._encryptSeed = function (seed, password) {
    var encObj = CryptoJS.AES.encrypt(seed, password);
    var encSeed = { 'seed': encObj.toString(),
                    'iv': encObj.iv.toString(),
                    'salt': encObj.salt.toString()}
    return encSeed
}

KeyStore._decryptSeed = function (encryptedSeed, password) {
    var decryptedSeed = CryptoJS.AES.decrypt(encryptedSeed.seed, password, {'iv': encryptedSeed.iv, 'salt': encryptedSeed.salt });
    return decryptedSeed.toString(CryptoJS.enc.Latin1);
}

KeyStore._encryptKey = function (privKey, password) {
    var privKeyWordArray = CryptoJS.enc.Hex.parse(privKey)
    var encKey = CryptoJS.AES.encrypt(privKeyWordArray, password);
    var encKey = { 'seed': encKey.toString(),
                    'iv': encKey.iv.toString(),
                    'salt': encKey.salt.toString()}
    return encKey
}

KeyStore._decryptKey = function (encryptedKey, password) {
    var decryptedKey = CryptoJS.AES.decrypt(encryptedKey.seed, password, {'iv': encryptedKey.iv, 'salt': encryptedKey.salt });
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

// External static functions
KeyStore.generateRandomSeed = function() {
    var seed = new Mnemonic(Mnemonic.Words.ENGLISH)
    return seed.toString()
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
