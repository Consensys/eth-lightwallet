var Transaction = require('ethereumjs-tx');
var coder = require('web3/lib/solidity/coder');
// When updating to web3 1.0.0, replace by
// var coder = require('web3-eth-abi');
var rlp = require('rlp');
var CryptoJS = require('crypto-js');

function add0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  if (input.length < 2 || input.slice(0,2) !== '0x') {
    return '0x' + input;
  }

  return input;
}

function strip0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length >= 2 && input.slice(0,2) === '0x') {
    return input.slice(2);
  }
  else {
    return input;
  }
}

function _encodeFunctionTxData (functionName, types, args) {

  var fullName = functionName + '(' + types.join() + ')';
  var signature = CryptoJS.SHA3(fullName, { outputLength: 256 }).toString(CryptoJS.enc.Hex).slice(0, 8);
  var dataHex = '0x' + signature + coder.encodeParams(types, args);
// When updating to web3 1.0.0, replace by
// var dataHex = coder.encodeFunctionSignature(fullName) + coder.encodeParameters(types, args).replace('0x','')

  return dataHex;
}

function _getTypesFromAbi (abi, functionName) {

  function matchesFunctionName(json) {
    return (json.name === functionName && json.type === 'function');
  }

  function getTypes(json) {
    return json.type;
  }

  var funcJson = abi.filter(matchesFunctionName)[0];

  return (funcJson.inputs).map(getTypes);
}

function functionTx (abi, functionName, args, txObject) {
  // txObject contains gasPrice, gasLimit, nonce, to, value

  var types = _getTypesFromAbi(abi, functionName);
  var txData = _encodeFunctionTxData(functionName, types, args);

  var txObjectCopy = {};
  txObjectCopy.to = add0x(txObject.to);
  txObjectCopy.gasPrice = add0x(txObject.gasPrice);
  txObjectCopy.gasLimit = add0x(txObject.gasLimit);
  txObjectCopy.nonce = add0x(txObject.nonce);
  txObjectCopy.data = add0x(txData);
  txObjectCopy.value = add0x(txObject.value);

  return '0x' + (new Transaction(txObjectCopy)).serialize().toString('hex');
}

function createdContractAddress (fromAddress, nonce) {
  var rlpEncodedHex = rlp.encode([new Buffer(strip0x(fromAddress), 'hex'), nonce]).toString('hex');
  var rlpEncodedWordArray = CryptoJS.enc.Hex.parse(rlpEncodedHex);
  var hash = CryptoJS.SHA3(rlpEncodedWordArray, {outputLength: 256}).toString(CryptoJS.enc.Hex);

  return '0x' + hash.slice(24);
}

function createContractTx (fromAddress, txObject) {
  // txObject contains gasPrice, gasLimit, value, data, nonce

  var txObjectCopy = {};
  txObjectCopy.to = add0x(txObject.to);
  txObjectCopy.gasPrice = add0x(txObject.gasPrice);
  txObjectCopy.gasLimit = add0x(txObject.gasLimit);
  txObjectCopy.nonce = add0x(txObject.nonce);
  txObjectCopy.data = add0x(txObject.data);
  txObjectCopy.value = add0x(txObject.value);

  var contractAddress = createdContractAddress(fromAddress, txObject.nonce);
  var tx = new Transaction(txObjectCopy);

  return {tx: '0x' + tx.serialize().toString('hex'), addr: contractAddress};
}

function valueTx (txObject) {
  // txObject contains gasPrice, gasLimit, value, nonce

  var txObjectCopy = {};
  txObjectCopy.to = add0x(txObject.to);
  txObjectCopy.gasPrice = add0x(txObject.gasPrice);
  txObjectCopy.gasLimit = add0x(txObject.gasLimit);
  txObjectCopy.nonce = add0x(txObject.nonce);
  txObjectCopy.value = add0x(txObject.value);

  var tx = new Transaction(txObjectCopy);

  return '0x' + tx.serialize().toString('hex');
}

module.exports = {
  _encodeFunctionTxData: _encodeFunctionTxData,
  _getTypesFromAbi: _getTypesFromAbi,
  functionTx: functionTx,
  createdContractAddress: createdContractAddress,
  createContractTx: createContractTx,
  valueTx: valueTx
};
