
var Transaction = require("ethereumjs-tx")
var util = require("ethereumjs-util")

var signTx = function (keystore, pwDerivedKey, rawTx, signingAddress, hdPathString) {

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

var signMsg = function (keystore, pwDerivedKey, rawMsg, signingAddress, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  signingAddress = util.stripHexPrefix(signingAddress);

  var msgHash = util.sha3(rawMsg);

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey, hdPathString);

  return util.ecsign(msgHash, new Buffer(privKey, 'hex'));
};

module.exports.signMsg = signMsg;

var recoverAddress = function (rawMsg, v, r, s) {

  var msgHash = util.sha3(rawMsg);

  return util.pubToAddress(util.ecrecover(msgHash, v, r, s));
};

module.exports.recoverAddress = recoverAddress;

var concatSig = function (v, r, s) {
  r = util.fromSigned(r);
  s = util.fromSigned(s);
  v = util.bufferToInt(v);
  r = util.toUnsigned(r).toString('hex');
  s = util.toUnsigned(s).toString('hex');
  v = util.stripHexPrefix(util.intToHex(v));
  return util.addHexPrefix(r.concat(s, v).toString("hex"));
};

module.exports.concatSig = concatSig;
