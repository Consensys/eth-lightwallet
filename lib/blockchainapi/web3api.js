var web3 = require('web3');
var rm = require('web3/lib/web3/requestmanager');

var web3api = function(provider) {

  this.requestmanager = rm.getInstance();

  try {
    web3.setProvider(new web3.providers.HttpProvider(provider));
  } catch(e) {
    console.error('Could not connect: %s', e);
  }
};

web3api.prototype.getBalance = function(address, callback) {
  web3.eth.getBalance('0x' + address, callback);
};

web3api.prototype.injectTransaction = function(signedTx, callback) {
  // this function will only work if you run the go client

  var data = {
    method: 'eth_sendRawTransaction',
    params: ['0x' + signedTx]
  };

  this.requestmanager.sendAsync(data, callback);
};

web3api.prototype.getNonce = function(address, callback) {
  return web3.eth.getTransactionCount('0x' + address, callback);
};

web3api.prototype.estimateGas = function(txObject, callback) {
  return web3.eth.estimateGas(txObject, callback);
};

web3api.prototype.getWeb3 = function() {
  return web3;
};

module.exports = web3api;
