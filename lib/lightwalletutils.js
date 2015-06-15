
var Transaction = require('ethereumjs-tx')
var coder = require('web3/lib/solidity/coder')
var rlp = require('rlp')
var CryptoJS = require('crypto-js')

var LightWalletUtils = module.exports = (function () {

    var lw = {}

    lw._encodeFunctionTxData = function (functionName, types, args) {

        var fullName = functionName + '(' + types.join() + ')'
        var signature = CryptoJS.SHA3(fullName, { outputLength: 256 }).toString(CryptoJS.enc.Hex).slice(0, 8)
        var dataHex = signature + coder.encodeParams(types, args)

        return dataHex
    }

    lw._getTypesFromAbi = function (abi, functionName) {

        function matchesFunctionName(json) {
            return (json.name === functionName && json.type === "function")
        }

        function getTypes(json) {
            return json.type
        }

        var funcJson = abi.filter(matchesFunctionName)[0]

        return (funcJson.inputs).map(getTypes)
    }

    lw.functionTx = function (abi, functionName, args, txObject) {
        // txObject contains gasPrice, gasLimit, nonce, to, value

        var types = lw._getTypesFromAbi(abi, functionName)
        var txData = lw._encodeFunctionTxData(functionName, types, args)

        var txObjectCopy = {}
        txObjectCopy.to = txObject.to
        txObjectCopy.gasPrice = txObject.gasPrice
        txObjectCopy.gasLimit = txObject.gasLimit
        txObjectCopy.nonce = txObject.nonce
        txObjectCopy.data = txData
        if (txObject.value !== undefined && txObject.value > 0) {
            txObjectCopy.value = txObject.value
        }

        return (new Transaction(txObjectCopy)).serialize().toString('hex')
    }

    lw.createdContractAddress = function (fromAddress, nonce) {
        var rlpEncodedHex = rlp.encode([new Buffer(fromAddress, 'hex'), nonce]).toString('hex')
	var rlpEncodedWordArray = CryptoJS.enc.Hex.parse(rlpEncodedHex)
	var hash = CryptoJS.SHA3(rlpEncodedWordArray, {outputLength: 256}).toString(CryptoJS.enc.Hex)

        return hash.slice(24)
    }

    lw.createContractTx = function (fromAddress, txObject) {
        // txObject contains gasPrice, gasLimit, value, data, nonce

        var contractAddress = lw.createdContractAddress(fromAddress, txObject.nonce)
        var tx = new Transaction(txObject)

        return {tx: tx.serialize().toString('hex'), addr: contractAddress}
    }

    lw.valueTx = function (txObject) {
        // txObject contains gasPrice, gasLimit, value, nonce
        var tx = new Transaction(txObject)

        return tx.serialize().toString('hex')
    }


    return lw;

}());
