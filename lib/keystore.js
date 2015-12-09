var CryptoJS = require('crypto-js');
var Transaction = require('ethereumjs-tx');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var bitcore = require('bitcore-lib');
var Random = bitcore.crypto.Random;
var Hash = bitcore.crypto.Hash;
var Mnemonic = require('bitcore-mnemonic');
var nacl = require('tweetnacl');

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

function add0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length < 2 || input.slice(0,2) !== '0x') {
    return '0x' + input;
  }
  else {
    return input;
  }
}

function nacl_encodeHex(msgUInt8Arr) {
  var msgBase64 = nacl.util.encodeBase64(msgBase64);  
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}


var KeyStore = function(mnemonic, password, hdPathString) {

  this.defaultHdPathString = "m/0'/0'/0'";

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  // TODO: finish up the encryption parameters
  // this.cryptoParams = {};
  // this.cryptoParams.algorithm = "aes-cbc";
  // this.cryptoParams.keyDerivation = {};
  // this.cryptoParams.keyDerivation.algorithm = "pbkdf2";
  // this.cryptoParams.keyDerivation.salt = "";
  // this.cryptoParams.keyDerivation.iterations = 2048;

  this.ksData = {};
  this.ksData[hdPathString] = {};
  pathKsData = this.ksData[hdPathString];
  pathKsData.info = {curve: 'secp256k1', purpose: 'sign'};

  this.encSeed = undefined;
  this.encHdRootPriv = undefined;
  this.keyHash = undefined;
  this.salt = undefined;
  this.version = 1;

  pathKsData.encHdPathPriv = undefined;
  pathKsData.hdIndex = 0;
  pathKsData.encPrivKeys = {};
  pathKsData.addresses = [];

  if ( (typeof password !== 'undefined') && (typeof mnemonic !== 'undefined') ){

    var words = mnemonic.split(' ');
    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH) || words.length !== 12){
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

    var hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    this.encHdRootPriv = KeyStore._encryptString(hdRoot, encKey);

    var hdRootKey = new bitcore.HDPrivateKey(hdRoot);
    var hdPath = hdRootKey.derive(hdPathString).xprivkey;
    pathKsData.encHdPathPriv = KeyStore._encryptString(hdPath, encKey);
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

KeyStore._computePubkeyFromPrivKey = function (privKey, curve) {

  if (curve !== 'curve25519') {
    throw new Error('KeyStore._computePubkeyFromPrivKey: Only "curve25519" supported.')
  }

  var privKeyBase64 = (new Buffer(privKey, 'hex')).toString('base64')
  var privKeyUInt8Array = nacl.util.decodeBase64(privKeyBase64);
  var pubKey = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey;
  var pubKeyBase64 = nacl.util.encodeBase64(pubKey);
  var pubKeyHex = (new Buffer(pubKeyBase64, 'base64')).toString('hex');
  
  return pubKeyHex;
}

KeyStore.prototype.addHdDerivationPath = function (hdPathString, password, info) {

  if (info.purpose !== 'sign' && info.purpose !== 'asymEncrypt') {
    throw new Error("KeyStore.addHdDerivationPath: info.purpose is '" + info.purpose + "' but must be either 'sign' or 'asymEncrypt'.");
  }

  if (info.curve !== 'secp256k1' && info.curve !== 'curve25519') {
    throw new Error("KeyStore.addHdDerivationPath: info.curve is '" + info.curve + "' but must be either 'secp256k1' or 'curve25519'.");
  }

  var encKey = this.generateEncKey(password);
  var hdRoot = KeyStore._decryptString(this.encHdRootPriv, encKey);
  var hdRootKey = new bitcore.HDPrivateKey(hdRoot);
  var hdPath = hdRootKey.derive(hdPathString).xprivkey;

  this.ksData[hdPathString] = {};
  this.ksData[hdPathString].info = info;
  this.ksData[hdPathString].encHdPathPriv = KeyStore._encryptString(hdPath, encKey);
  this.ksData[hdPathString].hdIndex = 0;
  this.ksData[hdPathString].encPrivKeys = {};

  if (info.purpose === 'sign') {
    this.ksData[hdPathString].addresses = [];
  }
  else if (info.purpose === 'asymEncrypt') {
    this.ksData[hdPathString].pubKeys = [];
  }
  
}

KeyStore.prototype.setDefaultHdDerivationPath = function (hdPathString) {

  if (this.ksData[hdPathString] === undefined) {
    throw new Error('setDefaultHdDerivationPath: HD path does not exist. Cannot set default.');
  }

  this.defaultHdPathString = hdPathString;
}

KeyStore.prototype._generatePrivKeys = function(password, n, hdPathString) {
  var encKey = this.generateEncKey(password);

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  var hdRoot = KeyStore._decryptString(this.ksData[hdPathString].encHdPathPriv, encKey);
  var keys = [];
  for (var i = 0; i < n; i++){
    var key = new bitcore.HDPrivateKey(hdRoot).derive(this.ksData[hdPathString].hdIndex++);
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

  if (jsonKS.version === undefined) {
    throw new Error('Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.')
  }

  // Create keystore
  var keystoreX = new KeyStore();

  keystoreX.encSeed       = jsonKS.encSeed;
  keystoreX.encHdRootPriv = jsonKS.encHdRootPriv;
  keystoreX.keyHash       = jsonKS.keyHash;
  keystoreX.salt          = jsonKS.salt;
  keystoreX.ksData        = jsonKS.ksData;

  return keystoreX;
};

KeyStore.upgradeOldSerialized = function (oldKS, password) {
  
  // Upgrades old serialized version of the keystore
  // to the latest version
  if (oldKS.version === undefined) {
    var tempKeyStore = new KeyStore();
    tempKeyStore.salt = oldKS.salt;
    tempKeyStore.keyHash = oldKS.keyHash;
    tempKeyStore.encSeed = oldKS.encSeed;
    var seed = tempKeyStore.getSeed(password);
    var newKeyStore = new KeyStore(seed, password);
    var hdIndex = oldKS.hdIndex;
    newKeyStore.generateNewAddress(password, hdIndex);
    
    return newKeyStore.serialize();
  }
  else {
    throw new Error('Keystore is not of correct version.')
  }
}


// External API functions

KeyStore.prototype.serialize = function () {
  var jsonKS = {'encSeed': this.encSeed,
                'keyHash': this.keyHash,
                'salt': this.salt,
                'ksData' : this.ksData,
                'version' : this.version};

  return JSON.stringify(jsonKS);
};

KeyStore.prototype.getAddresses = function (hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].info.purpose !== 'sign') {
    throw new Error('KeyStore.getAddresses: Addresses not defined when purpose is not "sign"');
  }

  return this.ksData[hdPathString].addresses;

};

KeyStore.prototype.getSeed = function (password) {
  var encKey = this.generateEncKey(password);
  var seed = KeyStore._decryptString(this.encSeed, encKey);
  return seed;
};

KeyStore.prototype.exportPrivateKey = function (address, password, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].encPrivKeys[address] === undefined) {
    throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
  }

  var encKey = this.generateEncKey(password);
  var encPrivKey = this.ksData[hdPathString].encPrivKeys[address];
  var privKey = KeyStore._decryptKey(encPrivKey, encKey);

  return privKey;
};

KeyStore.prototype.generateNewAddress = function(password, n, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].info.purpose !== 'sign') {
    throw new Error('KeyStore.generateNewAddress: Address not defined when purpose is not "sign"');
  }

  if (!this.encSeed) {
    throw new Error('KeyStore.generateNewAddress: No seed set');
  }
  n = n || 1;
  var keys = this._generatePrivKeys(password, n, hdPathString);

  for (var i = 0; i < n; i++) {
    var keyObj = keys[i];
    var address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);
    this.ksData[hdPathString].encPrivKeys[address] = keyObj.encPrivKey;
    this.ksData[hdPathString].addresses.push(address);
  }

};

KeyStore.prototype.generateNewEncryptionKeys = function(password, n, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].info.purpose !== 'asymEncrypt') {
    throw new Error('KeyStore.generateNewEncryptionKeys: Address not defined when purpose is not "asymEncrypt"');
  }

  if (!this.encSeed) {
    throw new Error('KeyStore.generateNewEncryptionKeys: No seed set');
  }
  n = n || 1;
  var keys = this._generatePrivKeys(password, n, hdPathString);
  
  var curve = this.ksData[hdPathString].info.curve;
  for (var i = 0; i < n; i++) {
    var keyObj = keys[i];
    var pubkey = KeyStore._computePubkeyFromPrivKey(keyObj.privKey, curve);
    this.ksData[hdPathString].encPrivKeys[pubkey] = keyObj.encPrivKey;
    this.ksData[hdPathString].pubKeys.push(pubkey);
  }

};

KeyStore.prototype.getPubKeys = function (hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].info.purpose !== 'asymEncrypt') {
    throw new Error('KeyStore.getPubKeys: Not defined when purpose is not "asymEncrypt"');
  }

  if (this.ksData[hdPathString].pubKeys === undefined) {
    throw new Error('KeyStore.getPubKeys: No pubKeys data found!');
  }
  
  return this.ksData[hdPathString].pubKeys;
}

KeyStore.prototype._asymEncryptRaw = function (msgUint8Array, myPubKey, theirPubKey, password, hdPathString) {
  
  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].info.purpose !== 'asymEncrypt') {
    throw new Error('KeyStore._asymEncryptRaw: Function not defined when purpose is not "asymEncrypt"');
  }
  
  if (this.ksData[hdPathString].encPrivKeys[myPubKey] === undefined) {
    throw new Error('KeyStore._asymEncryptRaw: public key not found in KeyStore');
  }

  var encKey = this.generateEncKey(password);
  var encPrivKey = this.ksData[hdPathString].encPrivKeys[myPubKey];
  var privKey = KeyStore._decryptKey(encPrivKey, encKey);
  var privKeyUInt8Array = nacl_decodeHex(privKey);
  var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);
  var nonce = nacl.randomBytes(nacl.box.nonceLength);
  var encryptedMessage = nacl.box(msgUint8Array, nonce, pubKeyUInt8Array, privKeyUInt8Array);
  
  var output = {
    alg: 'curve25519-xsalsa20-poly1305',
    nonce: nacl.util.encodeBase64(nonce),
    ciphertext: nacl.util.encodeBase64(encryptedMessage)
  };

  return output;
}

KeyStore.prototype._asymDecryptRaw = function (encMsg, theirPubKey, myPubKey, password, hdPathString) {
  
  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  if (this.ksData[hdPathString].info.purpose !== 'asymEncrypt') {
    throw new Error('KeyStore._asymDecryptRaw: Function not defined when purpose is not "asymEncrypt"');
  }
  
  if (this.ksData[hdPathString].encPrivKeys[myPubKey] === undefined) {
    throw new Error('KeyStore._asymDecryptRaw: public key not found in KeyStore');
  }

  var encKey = this.generateEncKey(password);
  var encPrivKey = this.ksData[hdPathString].encPrivKeys[myPubKey];
  var privKey = KeyStore._decryptKey(encPrivKey, encKey);
  var privKeyUInt8Array = nacl_decodeHex(privKey);
  var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

  var nonce = nacl.util.decodeBase64(encMsg.nonce);
  var ciphertext = nacl.util.decodeBase64(encMsg.ciphertext);
  var cleartext = nacl.box.open(ciphertext, nonce, pubKeyUInt8Array, privKeyUInt8Array);

  return cleartext;
  
}

KeyStore.prototype.asymEncryptString = function (msg, myPubKey, theirPubKey, password, hdPathString) {

  var messageUInt8Array = nacl.util.decodeUTF8(msg);

  return this._asymEncryptRaw(messageUInt8Array, myPubKey, theirPubKey, password, hdPathString);

}

KeyStore.prototype.asymDecryptString = function (encMsg, theirPubKey, myPubKey, password, hdPathString) {

  var cleartext = this._asymDecryptRaw(encMsg, theirPubKey, myPubKey, password, hdPathString);

  if (cleartext === false) {
    return false;
  }
  else {
    return nacl.util.encodeUTF8(cleartext);
  }

}

KeyStore.prototype.multiEncryptString = function (msg, myPubKey, theirPubKeyArray, password, hdPathString) {

  var messageUInt8Array = nacl.util.decodeUTF8(msg);
  var symEncryptionKey = nacl.randomBytes(nacl.secretbox.keyLength);
  var symNonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  var symEncMessage = nacl.secretbox(messageUInt8Array, symNonce, symEncryptionKey);

  if (theirPubKeyArray.length < 1) {
    throw new Error('Found no pubkeys to encrypt to.');
  }

  var encryptedSymKey = {};
  encryptedSymKey = []
  for (var i=0; i<theirPubKeyArray.length; i++) {
    
    var encSymKey = this._asymEncryptRaw(symEncryptionKey, myPubKey, theirPubKeyArray[i], password, hdPathString);

    delete encSymKey['alg'];
    encryptedSymKey.push(encSymKey);
  }
  
  var output = {};
  output.version = 1;
  output.asymAlg = 'curve25519-xsalsa20-poly1305';
  output.symAlg = 'xsalsa20-poly1305';
  output.symNonce = nacl.util.encodeBase64(symNonce);
  output.symEncMessage = nacl.util.encodeBase64(symEncMessage);
  output.encryptedSymKey = encryptedSymKey;

  return output;
}

KeyStore.prototype.multiDecryptString = function (encMsg, theirPubKey, myPubKey, password, hdPathString) {

  var symKey = false;
  for (var i=0; i < encMsg.encryptedSymKey.length; i++) {
    var result = this._asymDecryptRaw(encMsg.encryptedSymKey[i], theirPubKey, myPubKey, password, hdPathString)
    if (result !== false) {
      symKey = result;
      break;
    }
  }

  if (symKey === false) {
    return false;
  }
  else {
    var symNonce = nacl.util.decodeBase64(encMsg.symNonce);
    var symEncMessage = nacl.util.decodeBase64(encMsg.symEncMessage);
    var msg = nacl.secretbox.open(symEncMessage, symNonce, symKey);
    
    if (msg === false) {
      return false;
    }
    else {
      return nacl.util.encodeUTF8(msg);
    }
  }

}



KeyStore.prototype.signTx = function (rawTx, password, signingAddress, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  rawTx = strip0x(rawTx);
  signingAddress = strip0x(signingAddress);

  if (this.ksData[hdPathString].addresses.length === 0) {
    throw new Error('KeyStore.signTx: No private keys in KeyStore.');
  }

  var address = '';
  if (signingAddress === undefined) {
    address = this.ksData[hdPathString].addresses[0];
  }
  else {
    if (this.ksData[hdPathString].encPrivKeys[signingAddress] === undefined) {
      throw new Error('KeyStore.signTx: Address not found in KeyStore');
    }
    address = signingAddress;
  }
  var encKey = this.generateEncKey(password);
  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));
  var encPrivKey = this.ksData[hdPathString].encPrivKeys[address];
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
//
// Uses defaultHdPathString for the addresses.

KeyStore.prototype.passwordProvider = function (callback) {
  
  var password = prompt("Enter password to continue","Enter password");
  callback(null, password);

}

KeyStore.prototype.hasAddress = function (address, callback) {

  var addrToCheck = strip0x(address);

  if (this.ksData[this.defaultHdPathString].encPrivKeys[addrToCheck] === undefined) {
    callback('Address not found!', false);
  }
  else {
    callback(null, true);
  }

};

KeyStore.prototype.signTransaction = function (txParams, callback) {

  var ethjsTxParams = {};
  
  ethjsTxParams.from = add0x(txParams.from);
  ethjsTxParams.to = add0x(txParams.to);
  ethjsTxParams.gasLimit = add0x(txParams.gas);
  ethjsTxParams.gasPrice = add0x(txParams.gasPrice);
  ethjsTxParams.nonce = add0x(txParams.nonce);
  ethjsTxParams.value = add0x(txParams.value);
  ethjsTxParams.data = add0x(txParams.data);
  
  var txObj = new Transaction(ethjsTxParams);
  var rawTx = txObj.serialize().toString('hex');
  var signingAddress = strip0x(txParams.from);
  
  var self = this;
  this.passwordProvider( function (err, password) {
    var signedTx = self.signTx(rawTx, password, signingAddress, this.defaultHdPathString);
    callback(err, '0x' + signedTx);
  })

};


module.exports = KeyStore;
