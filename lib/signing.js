var Transaction = require("ethereumjs-tx")
var util = require("ethereumjs-util")

var signTx = function (keystore, pwDerivedKey, rawTx, signingAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }
  
  rawTx = util.stripHexPrefix(rawTx);
  signingAddress = util.stripHexPrefix(signingAddress);

  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey);

  txCopy.sign(new Buffer(privKey, 'hex'));
  privKey = '';

  return txCopy.serialize().toString('hex');
};

module.exports.signTx = signTx;

var signMsg = function (keystore, pwDerivedKey, rawMsg, signingAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var msgHash = util.addHexPrefix(util.sha3(rawMsg).toString('hex'));
  return this.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress);
};

module.exports.signMsg = signMsg;

var signMsgHash = function (keystore, pwDerivedKey, msgHash, signingAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  signingAddress = util.stripHexPrefix(signingAddress);

  var privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey);

  return util.ecsign(new Buffer(util.stripHexPrefix(msgHash), 'hex'), new Buffer(privKey, 'hex'));
};

module.exports.signMsgHash = signMsgHash;

var recoverAddress = function (rawMsg, v, r, s) {

  var msgHash = util.sha3(rawMsg);

  return util.pubToAddress(util.ecrecover(msgHash, v, r, s));
};

module.exports.recoverAddress = recoverAddress;

var concatSig = function (signature) {
  var v = signature.v;
  var r = signature.r;
  var s = signature.s;
  r = util.fromSigned(r);
  s = util.fromSigned(s);
  v = util.bufferToInt(v);
  r = util.setLengthLeft(util.toUnsigned(r), 32).toString('hex');
  s = util.setLengthLeft(util.toUnsigned(s), 32).toString('hex');
  v = util.stripHexPrefix(util.intToHex(v));
  return util.addHexPrefix(r.concat(s, v).toString("hex"));
};

module.exports.concatSig = concatSig;
