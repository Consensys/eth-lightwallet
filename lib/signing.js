
var Transaction = require("ethereumjs-tx")
var util = require("ethereumjs-util")

signTx = function (keystore, pwDerivedKey, rawTx, signingAddress, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  rawTx = util.stripHexPrefix(rawTx);
  signingAddress = util.stripHexPrefix(signingAddress);

  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey, hdPathString);

  txCopy.sign(new Buffer(privKey, 'hex'));
  privKey = '';

  return txCopy.serialize().toString('hex');
};

module.exports.signTx = signTx;

signMsg = function (keystore, pwDerivedKey, rawMsg, signingAddress, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  signingAddress = util.stripHexPrefix(signingAddress);

  var msgHash = util.sha3(rawMsg);

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey, hdPathString);

  return util.ecsign(msgHash, new Buffer(privKey, 'hex'));
};

module.exports.signMsg = signMsg;

recoverMsg = function (rawMsg, v, r, s) {

  var msgHash = util.sha3(rawMsg);

  return util.pubToAddress(util.ecrecover(msgHash, v, r, s));
};

module.exports.recoverMsg = recoverMsg;
