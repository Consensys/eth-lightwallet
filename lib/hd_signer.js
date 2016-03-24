var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var SimpleSigner = require('./simple_signer');
var KeyPair = require('./generators/key_pair');
var bitcore = require('bitcore-lib');
var HDPrivateKey = bitcore.HDPrivateKey;
var HDPublicKey = bitcore.HDPublicKey;

// Simple unencrypted HD signer

var HDSigner = function(hdprivatekey,path) {
  this.hdprivatekey = hdprivatekey;
  this.path = path || "m/0'/0'/0'";
  var key = this.hdprivatekey.derive(this.path);
  this.signer = new SimpleSigner(KeyPair.fromPrivateKey(key.privateKey.toBuffer()))
}

HDSigner.prototype.hasAddress = function(address, callback) {
  this.signer.hasAddress(address,callback);
}

HDSigner.prototype.getAddresses = function(callback) {
  this.signer.getAddresses(callback);
}

HDSigner.prototype.signRawTx = function(rawTx, callback) {
  this.signer.signRawTx(rawTx,callback);
}

function bip44path(index) {
  return ["m","44'", "60'", "0'","0", index].join("/");
}

HDSigner.bip44 = function(hdprivatekey, index) {
  index = index || 0;
  return new HDSigner(hdprivatekey, bip44path(index));
}

module.exports = HDSigner;