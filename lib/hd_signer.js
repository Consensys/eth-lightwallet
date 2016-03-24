var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var SimpleSigner = require('./simple_signer');
var KeyPair = require('./generators/key_pair');
var bitcore = require('bitcore-lib');
var HDPrivateKey = bitcore.HDPrivateKey;
var HDPublicKey = bitcore.HDPublicKey;

// Simple unencrypted HD signer

var HDSigner = function(seed,path) {
  this.hdprivatekey = new HDPrivateKey(seed);
  this.path = path || "m/0'/0'/0'";
}

HDSigner.prototype.derivedSigner = function() {
  if (!this.signer) {
    var key = this.hdprivatekey.derive(this.path);
    this.signer = new SimpleSigner(KeyPair.fromPrivateKey(key.privateKey.toBuffer()))
  }
  return this.signer;
}

HDSigner.prototype.setPath = function(path) {
  this.path = path;
  this.signer = null;
}

HDSigner.prototype.hasAddress = function(address, callback) {
  this.derivedSigner().hasAddress(address,callback);
}

HDSigner.prototype.getAddresses = function(callback) {
  this.derivedSigner().getAddresses(callback);
}

HDSigner.prototype.signRawTx = function(rawTx, callback) {
  this.derivedSigner().signRawTx(rawTx,callback);
}

module.exports = HDSigner;