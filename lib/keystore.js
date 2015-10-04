var CryptoJS = require('crypto-js');
var Transaction = require('ethereumjs-tx');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var Mnemonic = require('bitcore-mnemonic');
var bitcore = require('bitcore');
var Random = bitcore.crypto.Random;
var Hash = bitcore.crypto.Hash;

function strip0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length >= 2 && input.slice(0,2) === '0x') {
    return input.slice(2);
  }
  else {
    return input;
  }
}


var KeyStore = function(mnemonic, password) {

  this.encSeed = undefined;
  this.encHdRootPriv = undefined;
  this.keyHash = undefined;
  this.salt = undefined;
  this.hdIndex = 0;
  this.encPrivKeys = {};
  this.addresses = [];
  if ( (typeof password !== 'undefined') && (typeof mnemonic !== 'undefined') ){

    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH)){
      throw new Error('KeyStore: Invalid mnemonic');
    }
    this.salt = CryptoJS.lib.WordArray.random(128 / 8);
    var encKey = this.generateEncKey(password);

    this.encSeed = KeyStore._encryptString(mnemonic, encKey);

    // hdRoot is the relative root from which we derive the keys using
    // generateNewAddress(). The derived keys are then
    // `hdRoot/hdIndex`.
    //
    // Default hdRoot is m/0'/0'/0', the overall logic is
    // m/0'/Persona'/Purpose', where the 0' purpose is
    // for standard Ethereum accounts.

    var hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().derive("m/0'/0'/0'").xprivkey;
    this.encHdRootPriv = KeyStore._encryptString(hdRoot, encKey);
  }
};

KeyStore._encryptString = function (string, password) {
  var encObj = CryptoJS.AES.encrypt(string, password);
  var encString = { 'encStr': encObj.toString(),
                    'iv': encObj.iv.toString(),
                    'salt': encObj.salt.toString()};
  return encString;
};

KeyStore._decryptString = function (encryptedStr, password) {
  var decryptedStr = CryptoJS.AES.decrypt(encryptedStr.encStr, password, {'iv': encryptedStr.iv, 'salt': encryptedStr.salt });
  return decryptedStr.toString(CryptoJS.enc.Latin1);
};

KeyStore._encryptKey = function (privKey, password) {
  var privKeyWordArray = CryptoJS.enc.Hex.parse(privKey);
  var encKey = CryptoJS.AES.encrypt(privKeyWordArray, password);
  encKey = { 'key': encKey.toString(), 'iv': encKey.iv.toString(), 'salt': encKey.salt.toString()};
  return encKey;
};

KeyStore._decryptKey = function (encryptedKey, password) {
  var decryptedKey = CryptoJS.AES.decrypt(encryptedKey.key, password, {'iv': encryptedKey.iv, 'salt': encryptedKey.salt });
  return decryptedKey.toString(CryptoJS.enc.Hex);
};

KeyStore._computeAddressFromPrivKey = function (privKey) {
  var keyPair = ec.genKeyPair();
  keyPair._importPrivate(privKey, 'hex');
  var compact = false;
  var pubKey = keyPair.getPublic(compact, 'hex').slice(2);
  var pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey);
  var hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 });
  var address = hash.toString(CryptoJS.enc.Hex).slice(24);

  return address;
};

KeyStore.prototype._generatePrivKeys = function(password, n) {
  var encKey = this.generateEncKey(password);
  var hdRoot = KeyStore._decryptString(this.encHdRootPriv, encKey);
  var keys = [];
  for (var i = 0; i < n; i++){
    var key = new bitcore.HDPrivateKey(hdRoot).derive(this.hdIndex++);
    var encPrivKey = KeyStore._encryptKey(key.privateKey.toString(), encKey);

    keys[i] = {
      privKey: key.privateKey.toString(),
      encPrivKey: encPrivKey
    }
  }

  return keys;
};


// This function is tested using the test vectors here:
// http://www.di-mgt.com.au/sha_testvectors.html
KeyStore._concatAndSha256 = function(entropyBuf0, entropyBuf1) {

  var totalEnt = Buffer.concat([entropyBuf0, entropyBuf1]);
  if (totalEnt.length !== entropyBuf0.length + entropyBuf1.length) {
    throw new Error('generateRandomSeed: Logic error! Concatenation of entropy sources failed.')
  }
  
  var hashedEnt = Hash.sha256(totalEnt);

  return hashedEnt;
}

// External static functions


// Generates a random seed. If the optional string
// extraEntropy is set, a random set of entropy
// is created, then concatenated with extraEntropy
// and hashed to produce the entropy that gives the seed.
// Thus if extraEntropy comes from a high-entropy source
// (like dice) it can give some protection from a bad RNG.
// If extraEntropy is not set, the random number generator
// is used directly.

KeyStore.generateRandomSeed = function(extraEntropy) {

  var seed = '';
  if (extraEntropy === undefined) {
    seed = new Mnemonic(Mnemonic.Words.ENGLISH);
  }
  else if (typeof extraEntropy === 'string') {
    var entBuf = new Buffer(extraEntropy);
    var randBuf = Random.getRandomBuffer(256 / 8);
    var hashedEnt = this._concatAndSha256(randBuf, entBuf).slice(0, 128 / 8);
    seed = new Mnemonic(hashedEnt, Mnemonic.Words.ENGLISH);
  }
  else {
    throw new Error('generateRandomSeed: extraEntropy is set but not a string.')
  }

  return seed.toString();
};

KeyStore.isSeedValid = function(seed) {
  return Mnemonic.isValid(seed, Mnemonic.Words.ENGLISH)
};

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
  var jsonKS = JSON.parse(keystore);

  // Create keystore
  var keystoreX = new KeyStore();

  keystoreX.encSeed       = jsonKS.encSeed;
  keystoreX.encHdRootPriv = jsonKS.encHdRootPriv;
  keystoreX.hdIndex       = jsonKS.hdIndex;
  keystoreX.encPrivKeys   = jsonKS.encPrivKeys;
  keystoreX.addresses     = jsonKS.addresses;
  keystoreX.keyHash       = jsonKS.keyHash;
  keystoreX.salt          = jsonKS.salt;

  return keystoreX;
};

// External API functions

KeyStore.prototype.serialize = function () {
  var jsonKS = {'encSeed': this.encSeed,
                'encHdRootPriv': this.encHdRootPriv,
                'hdIndex': this.hdIndex,
                'encPrivKeys': this.encPrivKeys,
                'addresses': this.addresses,
                'keyHash': this.keyHash,
                'salt': this.salt};

  return JSON.stringify(jsonKS);
};

KeyStore.prototype.getAddresses = function () {
  return this.addresses;
};

KeyStore.prototype.getSeed = function (password) {
  var encKey = this.generateEncKey(password);
  var seed = KeyStore._decryptString(this.encSeed, encKey);
  return seed;
};

KeyStore.prototype.exportPrivateKey = function (address, password) {
  if (this.encPrivKeys[address] === undefined) {
    throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
  }
  var encKey = this.generateEncKey(password);
  var encPrivKey = this.encPrivKeys[address];
  var privKey = KeyStore._decryptKey(encPrivKey, encKey);

  return privKey;
};

KeyStore.prototype.generateNewAddress = function(password, n) {
  if (!this.encSeed) {
    throw new Error('KeyStore.generateNewAddress: No seed set');
  }
  n = n || 1;
  var keys = this._generatePrivKeys(password, n);

  for (var i = 0; i < n; i++) {
    var keyObj = keys[i];
    var address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);
    this.encPrivKeys[address] = keyObj.encPrivKey;
    this.addresses.push(address);
  }

};

KeyStore.prototype.signTx = function (rawTx, password, signingAddress) {

  rawTx = strip0x(rawTx);
  signingAddress = strip0x(signingAddress);

  if (this.addresses.length === 0) {
    throw new Error('KeyStore.signTx: No private keys in KeyStore.');
  }

  var address = '';
  if (signingAddress === undefined) {
    address = this.addresses[0];
  }
  else {
    if (this.encPrivKeys[signingAddress] === undefined) {
      throw new Error('KeyStore.signTx: Address not found in KeyStore');
    }
    address = signingAddress;
  }
  var encKey = this.generateEncKey(password);
  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));
  var encPrivKey = this.encPrivKeys[address];
  var privKey = KeyStore._decryptKey(encPrivKey, encKey);
  var addrFromPrivKey = KeyStore._computeAddressFromPrivKey(privKey);
  if (addrFromPrivKey !== address) {
    throw new Error('KeyStore.signTx: Decrypting private key failed!');
  }
  txCopy.sign(new Buffer(privKey, 'hex'));
  privKey = '';

  return txCopy.serialize().toString('hex');
};

KeyStore.prototype.generateEncKey = function(password) {
  var encKey = CryptoJS.PBKDF2(password, this.salt, { keySize: 512 / 32, iterations: 150 }).toString();
  var hash = CryptoJS.SHA3(encKey).toString();
  if (this.keyHash === undefined){
    this.keyHash = hash;
    return encKey;
  } else if (this.keyHash !== hash){
      throw new Error('Invalid Password');
  }
  return encKey;
};

// Async functions exposed for Hooked Web3-provider
// hasAddress(address, callback)
// signTransaction(txParams, callback)
//
// The function signTransaction() needs the
// function KeyStore.prototype.passwordProvider(callback)
// to be set in order to run properly.
// The function passwordProvider is an async function
// that calls the callback(err, password) with a password
// supplied by the user or by other means.
// The user of the hooked web3-provider is encouraged
// to write their own passwordProvider.

KeyStore.prototype.passwordProvider = function (callback) {
  
  var password = prompt("Enter password to continue","Enter password");
  callback(null, password);

}

KeyStore.prototype.hasAddress = function (address, callback) {

  var addrToCheck = strip0x(address);

  if (this.encPrivKeys[addrToCheck] === undefined) {
    callback('Address not found!', false);
  }
  else {
    callback(null, true);
  }

};

KeyStore.prototype.signTransaction = function (txParams, callback) {

  var ethjsTxParams = {};
  
  ethjsTxParams.from = strip0x(txParams.from);
  ethjsTxParams.to = strip0x(txParams.to);
  ethjsTxParams.gasLimit = strip0x(txParams.gas);
  ethjsTxParams.gasPrice = strip0x(txParams.gasPrice);
  ethjsTxParams.nonce = strip0x(txParams.nonce);
  ethjsTxParams.value = strip0x(txParams.value);
  ethjsTxParams.data = strip0x(txParams.data);
  
  var txObj = new Transaction(ethjsTxParams);
  var rawTx = txObj.serialize().toString('hex');
  var signingAddress = strip0x(txParams.from);
  
  var self = this;
  this.passwordProvider( function (err, password) {
    var signedTx = self.signTx(rawTx, password, signingAddress);
    callback(err, '0x' + signedTx);
  })

};


module.exports = KeyStore;
