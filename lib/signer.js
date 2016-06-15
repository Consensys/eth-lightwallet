var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
// Implementation should support 3 functions:
//
// - getAddress() // returns it's address
// - signRawTx(rawTx, callback) // sings rawTx and calls callback with the raw signed tx

var Signer = function(implementation) {
  this.implementation = implementation;
}

Signer.prototype.hasAddress = function(address,callback) {
  callback(null, this.getAddress() === address);
};

Signer.prototype.getAddress = function() {
  return this.implementation.getAddress();
}

Signer.prototype.getAccounts = function(callback) {
  var address = this.getAddress();
  callback(null, address ? [address] : []);
}

Signer.prototype.signTransaction = function (txParams, callback) {
  var ethjsTxParams = {};
  ethjsTxParams.from = util.addHexPrefix(txParams.from);
  ethjsTxParams.to = util.addHexPrefix(txParams.to);
  ethjsTxParams.gasLimit = util.addHexPrefix(txParams.gas);
  ethjsTxParams.gasPrice = util.addHexPrefix(txParams.gasPrice);
  ethjsTxParams.nonce = util.addHexPrefix(txParams.nonce);
  ethjsTxParams.value = util.addHexPrefix(txParams.value);
  ethjsTxParams.data = util.addHexPrefix(txParams.data);

  var txObj = new Transaction(ethjsTxParams);
  var rawTx = txObj.serialize().toString('hex');
  this.implementation.signRawTx(rawTx, function(e,signedTx) {
    if (e)
      callback(e,null)
    else
      callback(null, '0x' + signedTx);
  });
};

module.exports = Signer;