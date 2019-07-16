const Transaction = require('ethereumjs-tx');
const Util = require('ethereumjs-util');
const Coder = require('web3/lib/solidity/coder');
const Rlp = require('rlp');
const CryptoJS = require('crypto-js');

function createTx(txObject) {
  return new Transaction({
    ...txObject.from && { from: Util.addHexPrefix(txObject.from) },
    ...txObject.to && { to: Util.addHexPrefix(txObject.to) },
    ...txObject.gasPrice && { gasPrice: Util.addHexPrefix(txObject.gasPrice) },
    ...txObject.gasLimit && { gasLimit: Util.addHexPrefix(txObject.gasLimit) },
    ...txObject.nonce && { nonce: Util.addHexPrefix(txObject.nonce) },
    ...txObject.value && { value: Util.addHexPrefix(txObject.value) },
    ...txObject.data && { data: Util.addHexPrefix(txObject.data) },
  });
}

function txToHexString(tx) {
  return Util.addHexPrefix(tx.serialize().toString('hex'));
}

function _getTypesFromAbi(abi, functionName) {
  const funcJson = abi.filter(json => json.type === 'function' && json.name === functionName)[0];

  return (funcJson.inputs).map(json => json.type);
}

function _encodeFunctionTxData(functionName, types, args) {
  const fullName = `${functionName}(${types.join()})`;
  const signature = CryptoJS.SHA3(fullName, { outputLength: 256 }).toString(CryptoJS.enc.Hex).slice(0, 8);
  const encodeParams = Coder.encodeParams(types, args);
  const dataHex = Util.addHexPrefix(`${signature}${encodeParams}`);

  return dataHex;
}

function functionTx(abi, functionName, args, txObject) {
  const types = _getTypesFromAbi(abi, functionName);
  const txData = _encodeFunctionTxData(functionName, types, args);
  const tx = createTx({
    ...txObject,
    data: txData,
  });

  return txToHexString(tx);
}

function valueTx(txObject) {
  const tx = createTx(txObject);

  return txToHexString(tx);
}

function createdContractAddress(fromAddress, nonce) {
  const addressBuf = new Buffer(Util.stripHexPrefix(fromAddress), 'hex');
  const rlpEncodedHex = Rlp.encode([addressBuf, nonce]).toString('hex');
  const rlpEncodedWordArray = CryptoJS.enc.Hex.parse(rlpEncodedHex);
  const hash = CryptoJS.SHA3(rlpEncodedWordArray, { outputLength: 256 }).toString(CryptoJS.enc.Hex);

  return Util.addHexPrefix(hash.slice(24));
}

function createContractTx(fromAddress, txObject) {
  const tx = createTx(txObject);
  const contractAddress = createdContractAddress(fromAddress, txObject.nonce);

  return {
    tx: txToHexString(tx),
    addr: contractAddress,
  };
}

module.exports = {
  _encodeFunctionTxData,
  _getTypesFromAbi,
  createTx,
  txToHexString,
  functionTx,
  createdContractAddress,
  createContractTx,
  valueTx,
};
