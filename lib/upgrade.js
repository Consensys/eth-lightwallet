var CryptoJS = require('crypto-js');
var keystore = require('./keystore');

var Transaction = require('ethereumjs-tx');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var bitcore = require('bitcore-lib');
var Random = bitcore.crypto.Random;
var Hash = bitcore.crypto.Hash;
var Mnemonic = require('bitcore-mnemonic');
var nacl = require('tweetnacl');
var scrypt = require('scrypt-async');

var legacyDecryptString = function (encryptedStr, password) {
  var decryptedStr = CryptoJS.AES.decrypt(encryptedStr.encStr, password, {'iv': encryptedStr.iv, 'salt': encryptedStr.salt });
  return decryptedStr.toString(CryptoJS.enc.Latin1);
};

var legacyGenerateEncKey = function(password, salt, keyHash) {
  var encKey = CryptoJS.PBKDF2(password, salt, { keySize: 512 / 32, iterations: 150 }).toString();
  var hash = CryptoJS.SHA3(encKey).toString();
  if (keyHash !== hash){
      throw new Error('Invalid Password');
  }
  return encKey;
};

var upgradeOldSerialized = function (oldSerialized, password, callback) {

  // Upgrades old serialized version of the keystore
  // to the latest version
  var oldKS = JSON.parse(oldSerialized);

  if (oldKS.version === undefined || oldKS.version === 1) {

    var derivedKey = legacyGenerateEncKey(password, oldKS.salt, oldKS.keyHash);
    var seed = legacyDecryptString(oldKS.encSeed, derivedKey);
    keystore.deriveKeyFromPassword(password, function(err, pwDerivedKey) {
      var newKeyStore = new keystore(seed, pwDerivedKey);
      var hdIndex = oldKS.hdIndex;
      newKeyStore.generateNewAddress(pwDerivedKey, hdIndex);

      callback(null, newKeyStore.serialize());
    })
  }
  else {
    throw new Error('Keystore is not of correct version.')
  }
}


module.exports.upgradeOldSerialized = upgradeOldSerialized;
