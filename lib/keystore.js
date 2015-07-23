var CryptoJS = require('crypto-js');
var Transaction = require('ethereumjs-tx');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var Mnemonic = require('bitcore-mnemonic');
var bitcore = require('bitcore');

var KeyStore = function(mnemonic, password) {

  this.encSeed = undefined;
  this.encMasterPriv = undefined;
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
    var master = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    this.encMasterPriv = KeyStore._encryptString(master, encKey);
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

KeyStore.prototype._addKeyPair = function (encPrivKey, address) {
  this.encPrivKeys[address] = encPrivKey;
  this.addresses.push(address);
};

KeyStore.prototype._generatePrivKey = function(password) {
  var encKey = this.generateEncKey(password);
  var master = KeyStore._decryptString(this.encMasterPriv, encKey);
  var key = new bitcore.HDPrivateKey(master).derive(this.hdIndex++);
  var encPrivKey = KeyStore._encryptKey(key.privateKey.toString(), encKey);

  return {
    privKey: key.privateKey.toString(),
    encPrivKey: encPrivKey
  }
};

KeyStore.prototype._generatePrivKeys = function(password, n) {
  var encKey = this.generateEncKey(password);
  var master = KeyStore._decryptString(this.encMasterPriv, encKey);
  var keys = [];
  for (var i = 0; i < n; i++){
    var key = new bitcore.HDPrivateKey(master).derive(this.hdIndex++);
    var encPrivKey = KeyStore._encryptKey(key.privateKey.toString(), encKey);

    keys[i] = {
      privKey: key.privateKey.toString(),
      encPrivKey: encPrivKey
    }
  }

  return keys;
};

// External static functions

KeyStore.generateRandomSeed = function() {
  var seed = new Mnemonic(Mnemonic.Words.ENGLISH);
  return seed.toString();
};

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
  var jsonKS = JSON.parse(keystore);

  // Create keystore
  var keystoreX = new KeyStore();

  keystoreX.encSeed       = jsonKS.encSeed;
  keystoreX.encMasterPriv = jsonKS.encMasterPriv;
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
                'encMasterPriv': this.encMasterPriv,
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

  for (var i = 0; i < n; i++){
    var keyObj = keys[i];
    var address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);
    this._addKeyPair(keyObj.encPrivKey, address);
  }

  return address;
};

KeyStore.prototype.signTx = function (rawTx, password, signingAddress) {

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

module.exports = KeyStore;
