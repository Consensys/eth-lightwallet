var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
// Implementation should support 3 functions:
//
// - hasAddress(address,callback) // calls callback(null,true) if it can sign for address
// - getAddresses(callback) // calls callback(null, [address1, address2, ...]) with addresses it can sign for
// - signRawTx(rawTx, callback) // sings rawTx and calls callback with the raw signed tx

var Signer = function(implementation) {
  this.implementation = implementation;
}

Signer.prototype.hasAddress = function(address, callback) {
  this.implementation.hasAddress(address,callback);
};

Signer.prototype.getAddresses = function(callback) {
  this.implementation.getAddresses(callback);
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