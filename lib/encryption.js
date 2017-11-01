var util = require("ethereumjs-util");
var nacl = require('tweetnacl');

function nacl_encodeHex(msgUInt8Arr) {
  var msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}

function addressToPublicEncKey (keystore, pwDerivedKey, address) {
  var privKey = keystore.exportPrivateKey(address, pwDerivedKey)
  var privKeyUInt8Array = nacl_decodeHex(privKey)
  var pubKeyUInt8Array = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey
  return nacl_encodeHex(pubKeyUInt8Array)
}


function _asymEncryptRaw (keystore, pwDerivedKey, msgUint8Array, myAddress, theirPubKey) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var privKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  var privKeyUInt8Array = nacl_decodeHex(privKey);
  var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);
  var nonce = nacl.randomBytes(nacl.box.nonceLength);
  var encryptedMessage = nacl.box(msgUint8Array, nonce, pubKeyUInt8Array, privKeyUInt8Array);

  var output = {
    alg: 'curve25519-xsalsa20-poly1305',
    nonce: nacl.util.encodeBase64(nonce),
    ciphertext: nacl.util.encodeBase64(encryptedMessage)
  };

  return output;
}

function _asymDecryptRaw (keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var privKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  var privKeyUInt8Array = nacl_decodeHex(privKey);
  var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

  var nonce = nacl.util.decodeBase64(encMsg.nonce);
  var ciphertext = nacl.util.decodeBase64(encMsg.ciphertext);
  var cleartext = nacl.box.open(ciphertext, nonce, pubKeyUInt8Array, privKeyUInt8Array);

  return cleartext;

}

var asymEncryptString = function (keystore, pwDerivedKey, msg, myAddress, theirPubKey) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var messageUInt8Array = nacl.util.decodeUTF8(msg);

  return _asymEncryptRaw(keystore, pwDerivedKey, messageUInt8Array, myAddress, theirPubKey);

}

var asymDecryptString = function (keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var cleartext = _asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress);

  if (cleartext === false) {
    return false;
  }
  else {
    return nacl.util.encodeUTF8(cleartext);
  }

}

var multiEncryptString = function (keystore, pwDerivedKey, msg, myAddress, theirPubKeyArray) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var messageUInt8Array = nacl.util.decodeUTF8(msg);
  var symEncryptionKey = nacl.randomBytes(nacl.secretbox.keyLength);
  var symNonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  var symEncMessage = nacl.secretbox(messageUInt8Array, symNonce, symEncryptionKey);

  if (theirPubKeyArray.length < 1) {
    throw new Error('Found no pubkeys to encrypt to.');
  }

  var encryptedSymKey = {};
  encryptedSymKey = []
  for (var i=0; i<theirPubKeyArray.length; i++) {

    var encSymKey = _asymEncryptRaw(keystore, pwDerivedKey, symEncryptionKey, myAddress, theirPubKeyArray[i]);

    delete encSymKey['alg'];
    encryptedSymKey.push(encSymKey);
  }

  var output = {};
  output.version = 1;
  output.asymAlg = 'curve25519-xsalsa20-poly1305';
  output.symAlg = 'xsalsa20-poly1305';
  output.symNonce = nacl.util.encodeBase64(symNonce);
  output.symEncMessage = nacl.util.encodeBase64(symEncMessage);
  output.encryptedSymKey = encryptedSymKey;

  return output;
}

var multiDecryptString = function (keystore, pwDerivedKey, encMsg, theirPubKey, myAddress) {

  if(!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  var symKey = false;
  for (var i=0; i < encMsg.encryptedSymKey.length; i++) {
    var result = _asymDecryptRaw(keystore, pwDerivedKey, encMsg.encryptedSymKey[i], theirPubKey, myAddress)
    if (result !== false) {
      symKey = result;
      break;
    }
  }

  if (symKey === false) {
    return false;
  }
  else {
    var symNonce = nacl.util.decodeBase64(encMsg.symNonce);
    var symEncMessage = nacl.util.decodeBase64(encMsg.symEncMessage);
    var msg = nacl.secretbox.open(symEncMessage, symNonce, symKey);

    if (msg === false) {
      return false;
    }
    else {
      return nacl.util.encodeUTF8(msg);
    }
  }

}

module.exports = {
  asymEncryptString: asymEncryptString,
  asymDecryptString: asymDecryptString,
  multiEncryptString: multiEncryptString,
  multiDecryptString: multiDecryptString,
  addressToPublicEncKey: addressToPublicEncKey
};
