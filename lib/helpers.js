var keystoreModule = require('./keystore.js');
var txutils = require('./txutils.js');

function _setRemainingTxData(txObject) {

  if (txObject.gasPrice === undefined) { txObject.gasPrice = 10000000000000; }

  // Use the max gaslimit.
  // This is OK if there is enough ether in the account
  // but we might need to do something more clever in general.
  // For 10 szabo gas price we would need ~30 ether in the account.
  if (txObject.gasLimit === undefined) { txObject.gasLimit = 3141592; }

  if (txObject.value === undefined) { txObject.value = 0; }

  return txObject;
}

function _setTxData (blockchainApi, fromAddr, txObject, callback) {
  if (txObject.nonce === undefined) {
    blockchainApi.getNonce(fromAddr, function(err, nonce){
      txObject.nonce = nonce;
      callback(err, _setRemainingTxData(txObject));
    });
  } else {
    callback(undefined, _setRemainingTxData(txObject));
  }
}

function sendFunctionTx (abi, contractAddr, functionName, args, fromAddr, txData, blockchainApi, keystore, password, callback) {
  // txData contains optional values gasPrice, gasLimit, nonce, value
  _setTxData(blockchainApi, fromAddr, txData, function(err, data){
    if(err){throw new Error('Fire!'); }
    var txObject = data;
    txObject.to = contractAddr;
    var tx = txutils.functionTx(abi, functionName, args, txObject);
    var signedTx = keystore.signTx(tx, password, fromAddr);
    blockchainApi.injectTransaction(signedTx, callback);
  });
}

function sendCreateContractTx (bytecode, fromAddr, txData, blockchainApi, keystore, password, callback) {
  // txData contains optional values gasPrice, gasLimit, nonce, value
  _setTxData(blockchainApi, fromAddr, txData, function(err, data){
    if(err){throw new Error('Fire!'); }
    var txObject = data;
    txObject.data = bytecode;
    var out = txutils.createContractTx(fromAddr, txObject);
    var signedTx = keystore.signTx(out.tx, password, fromAddr);
    blockchainApi.injectTransaction(signedTx, function(err2, data2){
      if(err2){throw new Error('Fire!'); }
      callback(err2, out.addr);
    });
  });
}

function sendValueTx (fromAddr, toAddr, value, txData, blockchainApi, keystore, password, callback) {
  _setTxData(blockchainApi, fromAddr, txData, function(err, data){
    if(err){throw new Error('Fire!'); }
    var txObject = data;
    txObject.value = value;
    txObject.to = toAddr;
    var tx = txutils.valueTx(txObject);
    var signedTx = keystore.signTx(tx, password, fromAddr);
    blockchainApi.injectTransaction(signedTx, callback);
  });
}

module.exports = {
  _setTxData: _setTxData,
  sendFunctionTx: sendFunctionTx,
  sendCreateContractTx: sendCreateContractTx,
  sendValueTx: sendValueTx
};
