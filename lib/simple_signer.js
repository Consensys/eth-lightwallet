var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var secp256k1 = util.secp256k1;

// Simple unencrypted signer, not to be used in the browser

var SimpleSigner = function(keypair) {
  this.keypair = keypair;
}

SimpleSigner.prototype.getAddress = function() {
  return this.keypair.address;
}

SimpleSigner.prototype.signRawTx = function(rawTx, callback) {
  var rawTx = util.stripHexPrefix(rawTx);
  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));
  txCopy.sign(new Buffer(util.stripHexPrefix(this.keypair.privateKey), 'hex'));
  callback(null, txCopy.serialize().toString('hex'));
}


module.exports = SimpleSigner;