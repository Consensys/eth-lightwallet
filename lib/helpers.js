var ethlightjs = require("ethlightjs")
var keystore = ethlightjs.keystore
var txutils = ethlightjs.txutils

var LightWalletHelpers = module.exports = (function () {

    var helpers = {}

    helpers._setTxData = function (blockchainApi, fromAddr, txObject) {

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

    helpers.sendFunctionTx = function (abi, contractAddr, functionName, args, fromAddr, txData, blockchainApi, keystore, password) {
        // txData contains optional values gasPrice, gasLimit, nonce, value

        var txObjectCopy = helpers._setTxData(blockchainApi, fromAddr, txData)
        txObjectCopy.to = contractAddr
        var tx = txutils.functionTx(abi, functionName, args, txObjectCopy)
        var signedTx = keystore.signTx(tx, password, fromAddr)

        blockchainApi.injectTransaction(signedTx)
    }

    helpers.sendCreateContractTx = function (bytecode, fromAddr, txData, blockchainApi, keystore, password) {
        // txData contains optional values gasPrice, gasLimit, nonce, value

        var txObjectCopy = helpers._setTxData(blockchainApi, fromAddr, txData)
        txObjectCopy.data = bytecode
        var out = txutils.createContractTx(fromAddr, txObjectCopy)
        var signedTx = keystore.signTx(out.tx, password, fromAddr)

        blockchainApi.injectTransaction(signedTx)

        return out.addr
    }

    helpers.sendValueTx = function (fromAddr, value, txData, blockchainApi, keystore, password) {
        // txData contains optional values gasPrice, gasLimit, nonce

        var txObjectCopy = helpers._setTxData(blockchainApi, fromAddr, txData)
        txObjectCopy.value = value
        var tx = txutils.valueTx(txObjectCopy)
        var signedTx = keystore.signTx(tx, password, fromAddr)

        blockchainApi.injectTransaction(signedTx)
    }

    return helpers;

}());
