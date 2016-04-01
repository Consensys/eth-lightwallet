var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var SimpleSigner = require('./simple_signer');
var KeyPair = require('./generators/key_pair');
var bitcore = require('bitcore-lib');
var HDPrivateKey = bitcore.HDPrivateKey;
var HDPublicKey = bitcore.HDPublicKey;

// Simple unencrypted HD signer

var HDSigner = function(hdprivatekey, path) {
  this.hdprivatekey = hdprivatekey;
  if (path == null || Number.isInteger(path)) {
    this.path = bip44path(path || 0);
  } else {
    this.path = path;
  }
  var key = this.hdprivatekey.derive(this.path);
  this.signer = new SimpleSigner(KeyPair.fromPrivateKey(key.privateKey.toBuffer()))
}

HDSigner.prototype.getAddress = function() {
  return this.signer.getAddress();
}

HDSigner.prototype.signRawTx = function(rawTx, callback) {
  this.signer.signRawTx(rawTx,callback);
}

function bip44path(index) {
  return ["m","44'", "60'", "0'","0", index].join("/");
}
module.exports = HDSigner;