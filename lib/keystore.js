var CryptoJS = require("crypto-js")
var Transaction = require('ethereumjs-tx')
var EC = require('elliptic').ec
var ec = new EC('secp256k1')
var Mnemonic = require('bitcore-mnemonic')
var bitcore = require('bitcore')

var KeyStore = function(mnemonic, password) {

    this.encSeed = undefined;
    this.encMasterPriv = undefined;
    this.masterPub = undefined;
    this.hdIndex = 0;
    this.addresses = [];

    if ((typeof password !== 'undefined') && (typeof mnemonic !== 'undefined')){

      if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH)){
        throw new Error("KeyStore: Invalid mnemonic");
      }

      this.encSeed = KeyStore._encryptString(mnemonic, password);
      var privKey = new Mnemonic(mnemonic).toHDPrivateKey();
      this.encMasterPriv = KeyStore._encryptString(privKey.xprivkey, password);
      this.masterPub = privKey.xpubkey;
    }
}

KeyStore._encryptString = function (string, password) {
    var encObj = CryptoJS.AES.encrypt(string, password);
    var encSeed = { 'string': encObj.toString(),
                    'iv': encObj.iv.toString(),
                    'salt': encObj.salt.toString()}
    return encSeed
}

KeyStore._decryptString = function (encryptedStr, password) {
    var decryptedStr = CryptoJS.AES.decrypt(encryptedStr.string, password, {'iv': encryptedStr.iv, 'salt': encryptedStr.salt });
    return decryptedStr.toString(CryptoJS.enc.Latin1);
}

KeyStore._computeAddressFromPrivKey = function (privKey) {
    var keyPair = ec.genKeyPair()
    keyPair._importPrivate(privKey, 'hex')
    var compact = false
    var pubKey = keyPair.getPublic(compact, 'hex')

    return KeyStore._computeAddressFromPubKey(pubKey)
}

KeyStore._computeAddressFromPubKey = function(pubKey) {
    var pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey.slice(2))
    var hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 })
    var address = hash.toString(CryptoJS.enc.Hex).slice(24)

    return address
}

KeyStore._uncompressPubKey = function (pubKey) {
    var x = pubKey.point.x.toString('hex');
    var y = pubKey.point.y.toString('hex');

    return '04' + x + y;
}

KeyStore.prototype._getPrivKeyFromIndex = function(index, password) {
    var master = KeyStore._decryptString(this.encMasterPriv, password);
    var key = new bitcore.HDPrivateKey(master).derive(index);

    return key.privateKey.toString()
}

KeyStore.prototype._generatePubKey = function() {
    var master = new bitcore.HDPublicKey(this.masterPub);
    var key = master.derive(this.hdIndex++).publicKey;

    return KeyStore._uncompressPubKey(key);
}

// External static functions

KeyStore.generateRandomSeed = function() {
    var seed = new Mnemonic(Mnemonic.Words.ENGLISH)
    return seed.toString()
}

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
    jsonKS = JSON.parse(keystore)

    // Create keystore
    var keystore = new KeyStore()

    keystore.encSeed = jsonKS.encSeed
    keystore.encMasterPriv = jsonKS.encMasterPriv;
    keystore.masterPub = jsonKS.masterPub;
    keystore.hdIndex = jsonKS.hdIndex
    keystore.addresses = jsonKS.addresses

    return keystore
}

// External API functions

KeyStore.prototype.serialize = function () {
    var jsonKS = {"encSeed": this.encSeed,
                "encMasterPriv": this.encMasterPriv,
                "masterPub": this.masterPub,
                "hdIndex": this.hdIndex,
                "addresses": this.addresses}

    return JSON.stringify(jsonKS)
}

KeyStore.prototype.getAddresses = function () {
    return this.addresses;
}

KeyStore.prototype.getSeed = function (password) {
    var seed = KeyStore._decryptString(this.encSeed, password);
    if (!Mnemonic.isValid(seed, Mnemonic.Words.ENGLISH)){
        throw new Error("Invalid Password");
    }
    return seed;
}

KeyStore.prototype.generateNewAddress = function() {
    if (!this.encSeed) {
        throw new Error("KeyStore.generateNewAddress: No seed set");
    }

    var publicKey = this._generatePubKey();
    var address = KeyStore._computeAddressFromPubKey(publicKey);
    this.addresses.push(address);

    return address
}

KeyStore.prototype.signTx = function (rawTx, password, signingAddress) {

    if (this.addresses.length === 0) {
        throw new Error("KeyStore.signTx: No private keys in KeyStore.")
    }

    var index = this.addresses.indexOf(signingAddress);
    if (index === -1) {
        throw new Error("KeyStore.signTx: Address not found in KeyStore");
    }
    if (signingAddress === undefined) {
        index = 0;
        signingAddress = this.addresses[0];
    }

    var txCopy = new Transaction(new Buffer(rawTx, 'hex'))
    var privKey = this._getPrivKeyFromIndex(index, password);
    var addrFromPrivKey = KeyStore._computeAddressFromPrivKey(privKey)
    if (addrFromPrivKey !== signingAddress) {
        throw new Error("KeyStore.signTx: Decrypting private key failed!")
    }
    txCopy.sign(new Buffer(privKey, 'hex'));
    privKey = ''

    return txCopy.serialize().toString('hex')
}

module.exports = KeyStore;
