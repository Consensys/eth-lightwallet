var nacl = require('tweetnacl');
var Random = require('./random');
var scrypt = require('scrypt-async');

// Create a secure vault for storing keys in encrypted form
var Vault = function(passwordProvider) {
	this.passwordProvider = passwordProvider;
  this.store = {};
};

Vault.browserPasswordProvider = function (callback) {
  var password = prompt("Enter password to continue","Enter password");
  callback(null, password);
}

// Use for situations where we just want to set the password once.
Vault.constantPasswordProvider = function(password) {
  return function(callback) { callback(null, password)};
}

Vault.prototype.sealString = function(name, data, callback) {
  this.encryptString(data,function(error, encrypted) {
    if (err) return callback(error,null);
    this.store[name] = encrypted;
    callback(null, true);
  });
}

Vault.prototype.sealKey = function(name, data, callback) {
  this.encryptKey(data,function(error, encrypted) {
    if (err) return callback(error,null);
    this.store[name] = encrypted;
    callback(null, true);
  });
}

Vault.prototype.unseal = function(name, callback) {
  var encrypted = store[name];
  if (encrypted === undefined) return callback("Key not found",null);
  this.decrypt(encrypted,callback);
}

Vault.prototype.encryptString = function(data, callback) {
  this.deriveKeyFromPassword(function(error, pwDerivedKey) {
    if (error) {
      callback(error,null);
      return
    }

    Random.randomBytes(nacl.secretbox.length,function(e, nonce) {
      var encObj = nacl.secretbox(nacl.util.decodeUTF8(string), nonce, pwDerivedKey);
      var encString = { 'encStr': nacl.util.encodeBase64(encObj),
                        'nonce': nacl.util.encodeBase64(nonce)};
      callback(null, encString);
    });
  })
}

Vault.prototype.decrypt = function(encrypted, callback) {
  deriveKeyFromPassword(function(error, pwDerivedKey) {
    if (error) {
      callback(error,null);
      return
    }

    var secretbox = nacl.util.decodeBase64(encrypted.encStr || encrypted.key);
    var nonce = nacl.util.decodeBase64(encrypted.nonce);
    var decrypted = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);
    if (encrypted.encStr) {
      callback(null, nacl.util.encodeUTF8(decryptedStr));
    } else {
      callback(null, nacl_encodeHex(decryptedKey));
    }
  });
}

Vault.prototype.encryptKey = function(privKey, callback) {
  this.deriveKeyFromPassword(function(error, pwDerivedKey) {
    if (error) {
      callback(error,null);
      return
    }

    Random.randomBytes(nacl.secretbox.length,function(e, nonce) {
      var privKeyArray = nacl_decodeHex(privKey);
      var encKey = nacl.secretbox(privKeyArray, nonce, pwDerivedKey);
      encKey = { 'key': nacl.util.encodeBase64(encKey), 'nonce': nacl.util.encodeBase64(nonce)};
      callback(null, encKey);
    });
  })
}

Vault.prototype.decryptKey = function(encryptedStr, callback) {
  deriveKeyFromPassword(function(error, pwDerivedKey) {
    if (error) {
      callback(error,null);
      return
    }

    Random.randomBytes(nacl.secretbox.length,function(e, nonce) {
      var secretbox = nacl.util.decodeBase64(encryptedStr.encStr);
      var nonce = nacl.util.decodeBase64(encryptedStr.nonce);
      var decryptedStr = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);
      callback(null, nacl.util.encodeUTF8(decryptedStr));
    });
  })
}

Vault.prototype.clear = function() {
  this.store = {};
}

Vault.prototype.deriveKeyFromPassword = function(callback) {
  this.passwordProvider(function(error, password) {
    if (error) {
      callback(error,null);
      return
    }
    var salt = 'lightwalletSalt'; // should we have user-defined salt?
    var logN = 14;
    var r = 8;
    var dkLen = 32;
    var interruptStep = 200;

    var cb = function(derKey) {

      var ui8arr = (new Uint8Array(derKey));
      callback(null, ui8arr);
    }

    scrypt(password, salt, logN, r, dkLen, interruptStep, cb, null);
  });
};

module.exports = Vault;  
