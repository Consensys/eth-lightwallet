var keystore = require('./keystore.js')
var txutils = require('./txutils.js')
var Transaction = require('ethereumjs-tx')

function _setTxData (blockchainApi, fromAddr, txObject) {

    var txObjectCopy = {}

    if (txObject.nonce === undefined) {
        txObjectCopy.nonce = blockchainApi.getNonce(fromAddr)
    }
    else {
        txObjectCopy.nonce = txObject.nonce
    }

    if (txObject.gasPrice === undefined) {
        txObjectCopy.gasPrice = 10000000000000
    }
    else {
        txObjectCopy.gasPrice = txObject.gasPrice
    }

    if (txObject.gasLimit === undefined) {
        // Use the max gaslimit.
	// This is OK if there is enough ether in the account
	// but we might need to do something more clever in general.
	// For 10 szabo gas price we would need ~30 ether in the account.

        txObjectCopy.gasLimit = 3141592 
    }
    else {
        txObjectCopy.gasLimit = txObject.gasLimit
    }

    if (txObject.value === undefined) {
	txObjectCopy.value = 0
    }
    else {
	txObjectCopy.value = txObject.value
    }

    return txObjectCopy
}

function sendFunctionTx (abi, contractAddr, functionName, args, fromAddr, txData, blockchainApi, keystore, password) {
    // txData contains optional values gasPrice, gasLimit, nonce, value

    var txObjectCopy = _setTxData(blockchainApi, fromAddr, txData)
    txObjectCopy.to = contractAddr
    var tx = txutils.functionTx(abi, functionName, args, txObjectCopy)
    var signedTx = keystore.signTx(tx, password, fromAddr)

    return blockchainApi.injectTransaction(signedTx)
}

function sendCreateContractTx (bytecode, fromAddr, txData, blockchainApi, keystore, password) {
    // txData contains optional values gasPrice, gasLimit, nonce, value

    var txObjectCopy = _setTxData(blockchainApi, fromAddr, txData)
    txObjectCopy.data = bytecode
    var out = txutils.createContractTx(fromAddr, txObjectCopy)
    var signedTx = keystore.signTx(out.tx, password, fromAddr)

    blockchainApi.injectTransaction(signedTx)

    return out.addr
}

function sendValueTx (fromAddr, toAddr, value, txData, blockchainApi, keystore, password) {
    // txData contains optional values gasPrice, gasLimit, nonce

    var txObjectCopy = _setTxData(blockchainApi, fromAddr, txData)
    txObjectCopy.value = value
    txObjectCopy.to = toAddr
    var tx = txutils.valueTx(txObjectCopy)
    var signedTx = keystore.signTx(tx, password, fromAddr)

    return blockchainApi.injectTransaction(signedTx)
}

module.exports = {
  _setTxData: _setTxData,
  sendFunctionTx: sendFunctionTx,
  sendCreateContractTx: sendCreateContractTx,
  sendValueTx: sendValueTx
}
