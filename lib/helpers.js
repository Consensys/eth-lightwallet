var keystore = require('./keystore.js')
var txutils = require('./txutils.js')

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
        // Use the highest gaslimit that can be afforded
        var balance = blockchainApi.getBalance(fromAddr)
        var gasLimit = balance / txObjectCopy.gasPrice

        txObjectCopy.gasLimit = Math.min(3000000, gasLimit)
    }
    else {
        txObjectCopy.gasLimit = txObject.gasLimit
    }

    txObjectCopy.value = txObject.value

    return txObjectCopy
}

function sendFunctionTx (abi, contractAddr, functionName, args, fromAddr, txData, blockchainApi, keystore, password) {
    // txData contains optional values gasPrice, gasLimit, nonce, value

    var txObjectCopy = helpers._setTxData(blockchainApi, fromAddr, txData)
    txObjectCopy.to = contractAddr
    var tx = txutils.functionTx(abi, functionName, args, txObjectCopy)
    var signedTx = keystore.signTx(tx, password, fromAddr)

    blockchainApi.injectTransaction(signedTx)
}

function sendCreateContractTx (bytecode, fromAddr, txData, blockchainApi, keystore, password) {
    // txData contains optional values gasPrice, gasLimit, nonce, value

    var txObjectCopy = helpers._setTxData(blockchainApi, fromAddr, txData)
    txObjectCopy.data = bytecode
    var out = txutils.createContractTx(fromAddr, txObjectCopy)
    var signedTx = keystore.signTx(out.tx, password, fromAddr)

    blockchainApi.injectTransaction(signedTx)

    return out.addr
}

function sendValueTx (fromAddr, value, txData, blockchainApi, keystore, password) {
    // txData contains optional values gasPrice, gasLimit, nonce

    var txObjectCopy = helpers._setTxData(blockchainApi, fromAddr, txData)
    txObjectCopy.value = value
    var tx = txutils.valueTx(txObjectCopy)
    var signedTx = keystore.signTx(tx, password, fromAddr)

    blockchainApi.injectTransaction(signedTx)
}

module.exports = {
  _setTxData: _setTxData,
  sendFunctionTx: sendFunctionTx,
  sendCreateContractTx: sendCreateContractTx,
  sendValueTx: sendValueTx
}