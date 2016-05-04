var CryptoJS = require('crypto-js');
var Transaction = require('ethereumjs-tx');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var bitcore = require('bitcore-lib');
var Random = bitcore.crypto.Random;
var Hash = bitcore.crypto.Hash;
var Mnemonic = require('bitcore-mnemonic');
var nacl = require('tweetnacl');
var scrypt = require('scrypt-async');

var encryption = require('./encryption');
var signing = require('./signing');

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

function leftPadString (stringToPad, padChar, length) {

  var repreatedPadChar = '';
  for (var i=0; i<length; i++) {
    repreatedPadChar += padChar;
  }

  return ( (repreatedPadChar + stringToPad).slice(-length) );
}

function nacl_encodeHex(msgUInt8Arr) {
  var msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}


var KeyStore = function(mnemonic, pwDerivedKey, hdPathString) {

  this.defaultHdPathString = "m/0'/0'/0'";

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  this.ksData = {};
  this.ksData[hdPathString] = {};
  var pathKsData = this.ksData[hdPathString];
  pathKsData.info = {curve: 'secp256k1', purpose: 'sign'};

  this.encSeed = undefined;
  this.encHdRootPriv = undefined;
  this.version = 2;

  pathKsData.encHdPathPriv = undefined;
  pathKsData.hdIndex = 0;
  pathKsData.encPrivKeys = {};
  pathKsData.addresses = [];

  if ( (typeof pwDerivedKey !== 'undefined') && (typeof mnemonic !== 'undefined') ){

    var words = mnemonic.split(' ');
    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH) || words.length !== 12){
      throw new Error('KeyStore: Invalid mnemonic');
    }

    // Pad the seed to length 120 before encrypting
    var paddedSeed = leftPadString(mnemonic, ' ', 120);
    this.encSeed = KeyStore._encryptString(paddedSeed, pwDerivedKey);

    // hdRoot is the relative root from which we derive the keys using
    // generateNewAddress(). The derived keys are then
    // `hdRoot/hdIndex`.
    //
    // Default hdRoot is m/0'/0'/0', the overall logic is
    // m/0'/Persona'/Purpose', where the 0' purpose is
    // for standard Ethereum accounts.

    var hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    this.encHdRootPriv = KeyStore._encryptString(hdRoot, pwDerivedKey);

    var hdRootKey = new bitcore.HDPrivateKey(hdRoot);
    var hdPath = hdRootKey.derive(hdPathString).xprivkey;
    pathKsData.encHdPathPriv = KeyStore._encryptString(hdPath, pwDerivedKey);
  }
};

KeyStore._encryptString = function (string, pwDerivedKey) {

  var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  var encObj = nacl.secretbox(nacl.util.decodeUTF8(string), nonce, pwDerivedKey);
  var encString = { 'encStr': nacl.util.encodeBase64(encObj),
                    'nonce': nacl.util.encodeBase64(nonce)};
  return encString;
};

KeyStore._decryptString = function (encryptedStr, pwDerivedKey) {

  var secretbox = nacl.util.decodeBase64(encryptedStr.encStr);
  var nonce = nacl.util.decodeBase64(encryptedStr.nonce);

  var decryptedStr = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  return nacl.util.encodeUTF8(decryptedStr);
};

KeyStore._encryptKey = function (privKey, pwDerivedKey) {

  var privKeyArray = nacl_decodeHex(privKey);
  var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  var encKey = nacl.secretbox(privKeyArray, nonce, pwDerivedKey);
  encKey = { 'key': nacl.util.encodeBase64(encKey), 'nonce': nacl.util.encodeBase64(nonce)};

  return encKey;
};

KeyStore._decryptKey = function (encryptedKey, pwDerivedKey) {

  var secretbox = nacl.util.decodeBase64(encryptedKey.key);
  var nonce = nacl.util.decodeBase64(encryptedKey.nonce);
  var decryptedKey = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  return nacl_encodeHex(decryptedKey);
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

KeyStore.prototype.addHdDerivationPath = function (hdPathString, pwDerivedKey, info) {

  if (info.purpose !== 'sign' && info.purpose !== 'asymEncrypt') {
    throw new Error("KeyStore.addHdDerivationPath: info.purpose is '" + info.purpose + "' but must be either 'sign' or 'asymEncrypt'.");
  }

  if (info.curve !== 'secp256k1' && info.curve !== 'curve25519') {
    throw new Error("KeyStore.addHdDerivationPath: info.curve is '" + info.curve + "' but must be either 'secp256k1' or 'curve25519'.");
  }

  var hdRoot = KeyStore._decryptString(this.encHdRootPriv, pwDerivedKey);
  var hdRootKey = new bitcore.HDPrivateKey(hdRoot);
  var hdPath = hdRootKey.derive(hdPathString).xprivkey;

  this.ksData[hdPathString] = {};
  this.ksData[hdPathString].info = info;
  this.ksData[hdPathString].encHdPathPriv = KeyStore._encryptString(hdPath, pwDerivedKey);
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

KeyStore.prototype._generatePrivKeys = function(pwDerivedKey, n, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  var hdRoot = KeyStore._decryptString(this.ksData[hdPathString].encHdPathPriv, pwDerivedKey);
  var keys = [];
  for (var i = 0; i < n; i++){
    var hdprivkey = new bitcore.HDPrivateKey(hdRoot).derive(this.ksData[hdPathString].hdIndex++);
    var privkeyBuf = hdprivkey.privateKey.toBuffer();
    
    var privkeyHex = privkeyBuf.toString('hex');
    if (privkeyBuf.length < 16) {
      // Way too small key, something must have gone wrong
      // Halt and catch fire
      throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
    }
    else if (privkeyBuf.length < 32) {
      // Pad private key if too short
      // bitcore has a bug where it sometimes returns
      // truncated keys
      privkeyHex = leftPadString(privkeyBuf.toString('hex'), '0', 64);
    }
    else if (privkeyBuf.length > 32) {
      throw new Error('Private key larger than 32 bytes. Aborting!');
    }

    var encPrivKey = KeyStore._encryptKey(privkeyHex, pwDerivedKey);
    keys[i] = {
      privKey: privkeyHex,
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

KeyStore.prototype.isDerivedKeyCorrect = function(pwDerivedKey) {

  var paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);
  if (paddedSeed.length > 0) {
    return true;
  }

  return false;
  
};

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
  var jsonKS = JSON.parse(keystore);

  if (jsonKS.version === undefined || jsonKS.version === 1) {
    throw new Error('Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.')
  }

  // Create keystore
  var keystoreX = new KeyStore();

  keystoreX.encSeed       = jsonKS.encSeed;
  keystoreX.encHdRootPriv = jsonKS.encHdRootPriv;
  keystoreX.ksData        = jsonKS.ksData;

  return keystoreX;
};

// External API functions

KeyStore.prototype.serialize = function () {
  var jsonKS = {'encSeed': this.encSeed,
                'ksData' : this.ksData,
                'encHdRootPriv' : this.encHdRootPriv,
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

KeyStore.prototype.getSeed = function (pwDerivedKey) {
  var paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);
  return paddedSeed.trim();
};

KeyStore.prototype.exportPrivateKey = function (address, pwDerivedKey, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  var address = strip0x(address);
  if (this.ksData[hdPathString].encPrivKeys[address] === undefined) {
    throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
  }

  var encPrivKey = this.ksData[hdPathString].encPrivKeys[address];
  var privKey = KeyStore._decryptKey(encPrivKey, pwDerivedKey);

  return privKey;
};

KeyStore.prototype.generateNewAddress = function(pwDerivedKey, n, hdPathString) {

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
  var keys = this._generatePrivKeys(pwDerivedKey, n, hdPathString);

  for (var i = 0; i < n; i++) {
    var keyObj = keys[i];
    var address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);
    this.ksData[hdPathString].encPrivKeys[address] = keyObj.encPrivKey;
    this.ksData[hdPathString].addresses.push(address);
  }

};

KeyStore.prototype.generateNewEncryptionKeys = function(pwDerivedKey, n, hdPathString) {

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
  var keys = this._generatePrivKeys(pwDerivedKey, n, hdPathString);

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

KeyStore.deriveKeyFromPassword = function(password, callback) {

  var salt = 'lightwalletSalt'; // should we have user-defined salt?
  var logN = 14;
  var r = 8;
  var dkLen = 32;
  var interruptStep = 200;

  var cb = function(derKey) {
    try{
      var ui8arr = (new Uint8Array(derKey));
      callback(null, ui8arr);
    } catch (err) {
      callback(err);
    }
  }

  scrypt(password, salt, logN, r, dkLen, interruptStep, cb, null);
}



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
    if (err) return callback(err);
    KeyStore.deriveKeyFromPassword(password, function (err, pwDerivedKey) {
      if (err) return callback(err);
      var signedTx = signing.signTx(self, pwDerivedKey, rawTx, signingAddress, self.defaultHdPathString);
      callback(null, '0x' + signedTx);
    })
  })

};


module.exports = KeyStore;
