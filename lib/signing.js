
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
