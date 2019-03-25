const Transaction = require('ethereumjs-tx');
const Util = require('ethereumjs-util');
const Assert = require('./assert');

function getPrivateKeyBuff(keystore, pwDerivedKey, address) {
  const privateKey = keystore.exportPrivateKey(Util.stripHexPrefix(address), pwDerivedKey);

  return new Buffer(privateKey, 'hex');
}

function signTx(keystore, pwDerivedKey, rawTx, signingAddress) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const tx = new Transaction(new Buffer(Util.stripHexPrefix(rawTx), 'hex'));
  const privateKeyBuff = getPrivateKeyBuff(keystore, pwDerivedKey, signingAddress);

  tx.sign(privateKeyBuff);

  return tx.serialize().toString('hex');
}

function signMsg(keystore, pwDerivedKey, rawMsg, signingAddress) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const msgHash = Util.addHexPrefix(Util.keccak(rawMsg).toString('hex'));

  return this.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress);
}

function signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const msgBuff = new Buffer(Util.stripHexPrefix(msgHash), 'hex');
  const privateKeyBuff = getPrivateKeyBuff(keystore, pwDerivedKey, signingAddress);

  return Util.ecsign(msgBuff, privateKeyBuff);
}

function concatSig(signature) {
  let v = signature.v;
  let r = signature.r;
  let s = signature.s;

  r = Util.fromSigned(r);
  s = Util.fromSigned(s);
  v = Util.bufferToInt(v);

  r = Util.setLengthLeft(Util.toUnsigned(r), 32).toString('hex');
  s = Util.setLengthLeft(Util.toUnsigned(s), 32).toString('hex');
  v = Util.stripHexPrefix(Util.intToHex(v));

  return Util.addHexPrefix(r.concat(s, v).toString('hex'));
}

function recoverAddress(rawMsg, v, r, s) {
  const msgHash = Util.keccak(rawMsg);

  return Util.pubToAddress(Util.ecrecover(msgHash, v, r, s));
}

module.exports = {
  signTx,
  signMsg,
  signMsgHash,
  concatSig,
  recoverAddress,
};
