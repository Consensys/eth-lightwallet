const Nacl = require('tweetnacl');
const NaclUtil = require('tweetnacl-util');
const Assert = require('./assert');

function encodeHex(msgUInt8Arr) {
  const msgBase64 = NaclUtil.encodeBase64(msgUInt8Arr);

  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function decodeHex(msgHex) {
  const msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');

  return NaclUtil.decodeBase64(msgBase64);
}

function asymEncryptRaw(keystore, pwDerivedKey, msgUint8Array, myAddress, theirPubKey) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const privateKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  const privateKeyUInt8Array = decodeHex(privateKey);
  const pubKeyUInt8Array = decodeHex(theirPubKey);
  const nonce = Nacl.randomBytes(Nacl.box.nonceLength);
  const encryptedMessage = Nacl.box(msgUint8Array, nonce, pubKeyUInt8Array, privateKeyUInt8Array);

  return {
    alg: 'curve25519-xsalsa20-poly1305',
    nonce: NaclUtil.encodeBase64(nonce),
    ciphertext: NaclUtil.encodeBase64(encryptedMessage)
  };
}

function asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const privateKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  const privateKeyUInt8Array = decodeHex(privateKey);
  const pubKeyUInt8Array = decodeHex(theirPubKey);

  const nonce = NaclUtil.decodeBase64(encMsg.nonce);
  const cipherText = NaclUtil.decodeBase64(encMsg.ciphertext);
  const clearText = Nacl.box.open(cipherText, nonce, pubKeyUInt8Array, privateKeyUInt8Array);

  return clearText;
}

function asymEncryptString(keystore, pwDerivedKey, msg, myAddress, theirPubKey) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const messageUInt8Array = NaclUtil.decodeUTF8(msg);

  return asymEncryptRaw(keystore, pwDerivedKey, messageUInt8Array, myAddress, theirPubKey);
}

function asymDecryptString(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const clearText = asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress);

  if (clearText === null) {
    return false;
  }

  return NaclUtil.encodeUTF8(clearText);
}

function multiEncryptString(keystore, pwDerivedKey, msg, myAddress, theirPubKeyArray) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const messageUInt8Array = NaclUtil.decodeUTF8(msg);
  const symEncryptionKey = Nacl.randomBytes(Nacl.secretbox.keyLength);
  const symNonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);

  const symEncMessage = Nacl.secretbox(messageUInt8Array, symNonce, symEncryptionKey);

  if (theirPubKeyArray.length < 1) {
    throw new Error('Found no pubkeys to encrypt to.');
  }

  const encryptedSymKey = theirPubKeyArray.map(theirPubKey => {
    const { alg, ...props } = asymEncryptRaw(keystore, pwDerivedKey, symEncryptionKey, myAddress, theirPubKey);

    return {
      ...props,
    };
  });

  return {
    version: 1,
    asymAlg: 'curve25519-xsalsa20-poly1305',
    symAlg: 'xsalsa20-poly1305',
    symNonce: NaclUtil.encodeBase64(symNonce),
    symEncMessage: NaclUtil.encodeBase64(symEncMessage),
    encryptedSymKey,
  };
}

function multiDecryptString(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {
  Assert.derivedKey(keystore, pwDerivedKey);

  let symKey = null;

  for (let i = 0; i < encMsg.encryptedSymKey.length; i++) {
    const result = asymDecryptRaw(keystore, pwDerivedKey, encMsg.encryptedSymKey[i], theirPubKey, myAddress);

    if (result !== null) {
      symKey = result;
      break;
    }
  }

  if (symKey === null) {
    return false;
  }

  const symNonce = NaclUtil.decodeBase64(encMsg.symNonce);
  const symEncMessage = NaclUtil.decodeBase64(encMsg.symEncMessage);
  const msg = Nacl.secretbox.open(symEncMessage, symNonce, symKey);

  if (msg === null) {
    return false;
  }

  return NaclUtil.encodeUTF8(msg);
}

function addressToPublicEncKey(keystore, pwDerivedKey, address) {
  Assert.derivedKey(keystore, pwDerivedKey);

  const privateKey = keystore.exportPrivateKey(address, pwDerivedKey);
  const privateKeyUInt8Array = decodeHex(privateKey);
  const pubKeyUInt8Array = Nacl.box.keyPair.fromSecretKey(privateKeyUInt8Array).publicKey;

  return encodeHex(pubKeyUInt8Array);
}

module.exports = {
  encodeHex,
  decodeHex,
  asymEncryptString,
  asymDecryptString,
  multiEncryptString,
  multiDecryptString,
  addressToPublicEncKey,
};
