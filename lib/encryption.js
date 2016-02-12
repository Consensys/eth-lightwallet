var nacl = require('tweetnacl');

function nacl_encodeHex(msgUInt8Arr) {
  var msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}

_encryptString = function (string, pwDerivedKey) {

  var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  var encObj = nacl.secretbox(nacl.util.decodeUTF8(string), nonce, pwDerivedKey);
  var encString = { 'encStr': nacl.util.encodeBase64(encObj),
                    'nonce': nacl.util.encodeBase64(nonce)};
  return encString;
};

_decryptString = function (encryptedStr, pwDerivedKey) {

  var secretbox = nacl.util.decodeBase64(encryptedStr.encStr);
  var nonce = nacl.util.decodeBase64(encryptedStr.nonce);

  var decryptedStr = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  return nacl.util.encodeUTF8(decryptedStr);
};

_encryptKey = function (privKey, pwDerivedKey) {

  var privKeyArray = nacl_decodeHex(privKey);
  var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  var encKey = nacl.secretbox(privKeyArray, nonce, pwDerivedKey);
  encKey = { 'key': nacl.util.encodeBase64(encKey), 'nonce': nacl.util.encodeBase64(nonce)};

  return encKey;
};

_decryptKey = function (encryptedKey, pwDerivedKey) {

  var secretbox = nacl.util.decodeBase64(encryptedKey.key);
  var nonce = nacl.util.decodeBase64(encryptedKey.nonce);

  // console.log('secretbox:' + secretbox.toString());
  // console.log('nonce:' + nonce.toString());
  // console.log('pwDerivedKey:' + pwDerivedKey.toString());
  var decryptedKey = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);
  // console.log(decryptedKey)
  // console.log(decryptedKey.toString());
  return nacl_encodeHex(decryptedKey);
};

function _asymEncryptRaw (keystore, msgUint8Array, myPubKey, theirPubKey, pwDerivedKey, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  if (keystore.ksData[hdPathString].info.purpose !== 'asymEncrypt') {
    throw new Error('encryption._asymEncryptRaw: Function not defined when purpose is not "asymEncrypt"');
  }

  if (keystore.ksData[hdPathString].encPrivKeys[myPubKey] === undefined) {
    throw new Error('encryption._asymEncryptRaw: public key not found in KeyStore');
  }

  var encPrivKey = keystore.ksData[hdPathString].encPrivKeys[myPubKey];
  var privKey = _decryptKey(encPrivKey, pwDerivedKey);
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

function _asymDecryptRaw (keystore, encMsg, theirPubKey, myPubKey, pwDerivedKey, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = keystore.defaultHdPathString;
  }

  if (keystore.ksData[hdPathString].info.purpose !== 'asymEncrypt') {
    throw new Error('encryption._asymDecryptRaw: Function not defined when purpose is not "asymEncrypt"');
  }

  if (keystore.ksData[hdPathString].encPrivKeys[myPubKey] === undefined) {
    throw new Error('encryption._asymDecryptRaw: public key not found in KeyStore');
  }

  var encPrivKey = keystore.ksData[hdPathString].encPrivKeys[myPubKey];
  var privKey = _decryptKey(encPrivKey, pwDerivedKey);
  var privKeyUInt8Array = nacl_decodeHex(privKey);
  var pubKeyUInt8Array = nacl_decodeHex(theirPubKey);

  var nonce = nacl.util.decodeBase64(encMsg.nonce);
  var ciphertext = nacl.util.decodeBase64(encMsg.ciphertext);
  var cleartext = nacl.box.open(ciphertext, nonce, pubKeyUInt8Array, privKeyUInt8Array);

  return cleartext;

}

asymEncryptString = function (keystore, msg, myPubKey, theirPubKey, pwDerivedKey, hdPathString) {

  var messageUInt8Array = nacl.util.decodeUTF8(msg);

  return _asymEncryptRaw(keystore, messageUInt8Array, myPubKey, theirPubKey, pwDerivedKey, hdPathString);

}

asymDecryptString = function (keystore, encMsg, theirPubKey, myPubKey, pwDerivedKey, hdPathString) {

  var cleartext = _asymDecryptRaw(keystore, encMsg, theirPubKey, myPubKey, pwDerivedKey, hdPathString);

  if (cleartext === false) {
    return false;
  }
  else {
    return nacl.util.encodeUTF8(cleartext);
  }

}

multiEncryptString = function (keystore, msg, myPubKey, theirPubKeyArray, pwDerivedKey, hdPathString) {

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

    var encSymKey = _asymEncryptRaw(keystore, symEncryptionKey, myPubKey, theirPubKeyArray[i], pwDerivedKey, hdPathString);

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

multiDecryptString = function (keystore, encMsg, theirPubKey, myPubKey, pwDerivedKey, hdPathString) {

  var symKey = false;
  for (var i=0; i < encMsg.encryptedSymKey.length; i++) {
    var result = _asymDecryptRaw(keystore, encMsg.encryptedSymKey[i], theirPubKey, myPubKey, pwDerivedKey, hdPathString)
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
  _encryptString: _encryptString,
  _decryptString: _decryptString,
  _encryptKey: _encryptKey,
  _decryptKey: _decryptKey,
  asymEncryptString: asymEncryptString,
  asymDecryptString: asymDecryptString,
  multiEncryptString: multiEncryptString,
  multiDecryptString: multiDecryptString,
};
