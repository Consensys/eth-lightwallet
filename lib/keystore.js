const CryptoJS = require('crypto-js');
const Util = require('ethereumjs-util');
const EC = require('elliptic').ec;
const BitCore = require('bitcore-lib');
const Random = BitCore.crypto.Random;
const Hash = BitCore.crypto.Hash;
const Mnemonic = require('bitcore-mnemonic');
const Nacl = require('tweetnacl');
const NaclUtil = require('tweetnacl-util');
const ScryptAsync = require('scrypt-async');

const Assert = require('./assert');
const Encryption = require('./encryption');
const Signing = require('./signing');
const TxUtils = require('./txutils');

const ec = new EC('secp256k1');

function leftPadString(stringToPad, padChar, length) {
  let repeatedPadChar = '';

  for (let i = 0; i < length; i++) {
    repeatedPadChar += padChar;
  }

  return ((repeatedPadChar + stringToPad).slice(-length));
}

const KeyStore = function () {
};

KeyStore.prototype.init = function (mnemonic, pwDerivedKey, hdPathString, salt) {
  this.salt = salt;
  this.hdPathString = hdPathString;
  this.encSeed = undefined;
  this.encHdRootPriv = undefined;
  this.version = 3;
  this.hdIndex = 0;
  this.encPrivKeys = {};
  this.addresses = [];

  if ((typeof pwDerivedKey !== 'undefined') && (typeof mnemonic !== 'undefined')) {
    const words = mnemonic.split(' ');

    if (!KeyStore.isSeedValid(mnemonic) || words.length !== 12) {
      throw new Error('KeyStore: Invalid mnemonic');
    }

    // Pad the seed to length 120 before encrypting
    const paddedSeed = leftPadString(mnemonic, ' ', 120);
    this.encSeed = KeyStore._encryptString(paddedSeed, pwDerivedKey);

    // hdRoot is the relative root from which we derive the keys using generateNewAddress().
    // The derived keys are then `hdRoot/hdIndex`.

    const hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    const hdRootKey = new BitCore.HDPrivateKey(hdRoot);
    const hdPathKey = hdRootKey.derive(hdPathString).xprivkey;

    this.encHdRootPriv = KeyStore._encryptString(hdPathKey, pwDerivedKey);
  }
};

KeyStore.prototype.isDerivedKeyCorrect = function (pwDerivedKey) {
  const paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);

  return paddedSeed && paddedSeed.length > 0;
};

KeyStore.prototype.serialize = function () {
  return JSON.stringify({
    encSeed: this.encSeed,
    encHdRootPriv: this.encHdRootPriv,
    addresses: this.addresses,
    encPrivKeys: this.encPrivKeys,
    hdPathString: this.hdPathString,
    salt: this.salt,
    hdIndex: this.hdIndex,
    version: this.version,
  });
};

KeyStore.prototype.getAddresses = function () {
  return this.addresses.map((addr) => Util.addHexPrefix(addr));
};

KeyStore.prototype.getSeed = function (pwDerivedKey) {
  Assert.derivedKey(this, pwDerivedKey);

  const paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);

  if (!paddedSeed || paddedSeed.length === 0) {
    throw new Error('Provided password derived key is wrong');
  }

  return paddedSeed.trim();
};

KeyStore.prototype.exportPrivateKey = function (address, pwDerivedKey) {
  Assert.derivedKey(this, pwDerivedKey);

  const addr = Util.stripHexPrefix(address).toLowerCase();

  if (this.encPrivKeys[addr] === undefined) {
    throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
  }

  const encPrivateKey = this.encPrivKeys[addr];

  return KeyStore._decryptKey(encPrivateKey, pwDerivedKey);
};

KeyStore.prototype.generateNewAddress = function (pwDerivedKey, n) {
  Assert.derivedKey(this, pwDerivedKey);

  if (!this.encSeed) {
    throw new Error('KeyStore.generateNewAddress: No seed set');
  }

  n = n || 1;

  const keys = this._generatePrivKeys(pwDerivedKey, n);

  for (let i = 0; i < n; i++) {
    const keyObj = keys[i];
    const address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);

    this.encPrivKeys[address] = keyObj.encPrivKey;
    this.addresses.push(address);
  }
};

KeyStore.prototype.keyFromPassword = function (password, callback) {
  KeyStore.deriveKeyFromPasswordAndSalt(password, this.salt, callback);
};

KeyStore.prototype.passwordProvider = function (callback) {
  const password = prompt('Enter password to continue', 'Enter password');

  callback(null, password);
};

KeyStore.prototype.hasAddress = function (address, callback) {
  const addrToCheck = Util.stripHexPrefix(address);

  if (this.encPrivKeys[addrToCheck] === undefined) {
    const err = new Error('Address not found!');
    callback(err, false);
    return;
  }

  callback(null, true);
};

KeyStore.prototype.signTransaction = function (txParams, callback) {
  const { gas, ...params } = txParams;
  const txObj = {
    ...params,
    gasLimit: gas,
  };

  const tx = TxUtils.createTx(txObj);
  const rawTx = TxUtils.txToHexString(tx);
  const signingAddress = Util.stripHexPrefix(txParams.from);

  this.passwordProvider((err, password) => {
    if (err) {
      callback(err);
      return;
    }

    this.keyFromPassword(password, (err, pwDerivedKey) => {
      if (err) {
        callback(err);
        return;
      }

      const signedTx = Signing.signTx(this, pwDerivedKey, rawTx, signingAddress);

      callback(null, Util.addHexPrefix(signedTx));
    });
  });
};

KeyStore.prototype._generatePrivKeys = function (pwDerivedKey, n) {
  Assert.derivedKey(this, pwDerivedKey);

  const hdRoot = KeyStore._decryptString(this.encHdRootPriv, pwDerivedKey);

  if (!hdRoot || hdRoot.length === 0) {
    throw new Error('Provided password derived key is wrong');
  }

  const keys = [];

  for (let i = 0; i < n; i++) {
    const hdPrivateKey = new BitCore.HDPrivateKey(hdRoot).derive(this.hdIndex++);
    const privateKeyBuf = hdPrivateKey.privateKey.toBuffer();
    let privateKeyHex = privateKeyBuf.toString('hex');

    if (privateKeyBuf.length < 16) {
      // Way too small key, something must have gone wrong
      // Halt and catch fire
      throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
    } else if (privateKeyBuf.length > 32) {
      throw new Error('Private key larger than 32 bytes. Aborting!');
    } else if (privateKeyBuf.length < 32) {
      // Pad private key if too short
      // bitcore has a bug where it sometimes returns
      // truncated keys
      privateKeyHex = leftPadString(privateKeyBuf.toString('hex'), '0', 64);
    }

    const encPrivateKey = KeyStore._encryptKey(privateKeyHex, pwDerivedKey);

    keys[i] = {
      privKey: privateKeyHex,
      encPrivKey: encPrivateKey
    };
  }

  return keys;
};

KeyStore.createVault = function (opts, cb) {
  const { hdPathString, seedPhrase, password } = opts;
  let salt = opts.salt;

  // Default hdPathString
  if (!hdPathString) {
    const err = new Error('Keystore: Must include hdPathString in createVault inputs. Suggested alternatives are m/0\'/0\'/0\' for previous lightwallet default, or m/44\'/60\'/0\'/0 for BIP44 (used by Jaxx & MetaMask)');
    return cb(err);
  }

  if (!seedPhrase) {
    const err = new Error('Keystore: Must include seedPhrase in createVault inputs.');
    return cb(err);
  }

  if (!salt) {
    salt = KeyStore.generateSalt(32);
  }

  KeyStore.deriveKeyFromPasswordAndSalt(password, salt, (err, pwDerivedKey) => {
    if (err) {
      cb(err);
      return;
    }

    const ks = new KeyStore();

    ks.init(seedPhrase, pwDerivedKey, hdPathString, salt);

    cb(null, ks);
  });
};

KeyStore.generateSalt = function (byteCount) {
  return BitCore.crypto.Random.getRandomBuffer(byteCount || 32).toString('base64');
};

// Generates a random seed. If the optional string extraEntropy is set,
//  a random set of entropy is created, then concatenated with extraEntropy
//  and hashed to produce the entropy that gives the seed.
// Thus if extraEntropy comes from a high-entropy source (like dice)
//  it can give some protection from a bad RNG.
// If extraEntropy is not set, the random number generator is used directly.
KeyStore.generateRandomSeed = function (extraEntropy) {
  let seed = '';

  if (extraEntropy === undefined) {
    seed = new Mnemonic(Mnemonic.Words.ENGLISH);
  } else if (typeof extraEntropy === 'string') {
    const entBuf = new Buffer(extraEntropy);
    const randBuf = Random.getRandomBuffer(256 / 8);
    const hashedEnt = this._concatAndSha256(randBuf, entBuf).slice(0, 128 / 8);

    seed = new Mnemonic(hashedEnt, Mnemonic.Words.ENGLISH);
  } else {
    throw new Error('generateRandomSeed: extraEntropy is set but not a string.');
  }

  return seed.toString();
};

KeyStore.isSeedValid = function (seed) {
  return Mnemonic.isValid(seed, Mnemonic.Words.ENGLISH);
};

KeyStore.deserialize = function (keystore) {
  const dataKS = JSON.parse(keystore);
  const { version, salt, encSeed, encHdRootPriv, encPrivKeys, hdIndex, hdPathString, addresses } = dataKS;

  if (version === undefined || version < 3) {
    throw new Error('Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.');
  }

  const ks = new KeyStore();

  ks.salt = salt;
  ks.hdPathString = hdPathString;
  ks.encSeed = encSeed;
  ks.encHdRootPriv = encHdRootPriv;
  ks.version = version;
  ks.hdIndex = hdIndex;
  ks.encPrivKeys = encPrivKeys;
  ks.addresses = addresses;

  return ks;
};

KeyStore.deriveKeyFromPasswordAndSalt = function (password, salt, callback) {
  // Do not require salt, and default it to 'lightwalletSalt'
  // (for backwards compatibility)
  if (!callback && typeof salt === 'function') {
    callback = salt;
    salt = KeyStore.DEFAULT_SALT;
  } else if (!salt && typeof callback === 'function') {
    salt = KeyStore.DEFAULT_SALT;
  }

  const logN = 14;
  const r = 8;
  const dkLen = 32;
  const interruptStep = 200;

  const cb = function (derKey) {
    let err = null;
    let ui8arr = null;

    try {
      ui8arr = (new Uint8Array(derKey));
    } catch (e) {
      err = e;
    }

    callback(err, ui8arr);
  };

  ScryptAsync(password, salt, logN, r, dkLen, interruptStep, cb, null);
};

KeyStore._encryptString = function (string, pwDerivedKey) {
  const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
  const encStr = Nacl.secretbox(NaclUtil.decodeUTF8(string), nonce, pwDerivedKey);

  return {
    encStr: NaclUtil.encodeBase64(encStr),
    nonce: NaclUtil.encodeBase64(nonce),
  };
};

KeyStore._decryptString = function (encryptedStr, pwDerivedKey) {
  const decStr = NaclUtil.decodeBase64(encryptedStr.encStr);
  const nonce = NaclUtil.decodeBase64(encryptedStr.nonce);

  const decryptedStr = Nacl.secretbox.open(decStr, nonce, pwDerivedKey);

  if (decryptedStr === null) {
    return false;
  }

  return NaclUtil.encodeUTF8(decryptedStr);
};

KeyStore._encryptKey = function (privateKey, pwDerivedKey) {
  const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
  const privateKeyArray = Encryption.decodeHex(privateKey);
  const encKey = Nacl.secretbox(privateKeyArray, nonce, pwDerivedKey);

  return {
    key: NaclUtil.encodeBase64(encKey),
    nonce: NaclUtil.encodeBase64(nonce),
  };
};

KeyStore._decryptKey = function (encryptedKey, pwDerivedKey) {
  const decKey = NaclUtil.decodeBase64(encryptedKey.key);
  const nonce = NaclUtil.decodeBase64(encryptedKey.nonce);
  const decryptedKey = Nacl.secretbox.open(decKey, nonce, pwDerivedKey);

  if (decryptedKey === null) {
    throw new Error('Decryption failed!');
  }

  return Encryption.encodeHex(decryptedKey);
};

KeyStore._computeAddressFromPrivKey = function (privateKey) {
  const keyPair = ec.genKeyPair();
  keyPair._importPrivate(privateKey, 'hex');

  const pubKey = keyPair.getPublic(false, 'hex').slice(2);
  const pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey);
  const hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 });
  const address = hash.toString(CryptoJS.enc.Hex).slice(24);

  return address;
};

KeyStore._computePubkeyFromPrivKey = function (privKey, curve) {
  if (curve !== 'curve25519') {
    throw new Error('KeyStore._computePubkeyFromPrivKey: Only "curve25519" supported.');
  }

  const privateKeyBase64 = (new Buffer(privKey, 'hex')).toString('base64');
  const privateKeyUInt8Array = NaclUtil.decodeBase64(privateKeyBase64);
  const pubKey = Nacl.box.keyPair.fromSecretKey(privateKeyUInt8Array).publicKey;
  const pubKeyBase64 = NaclUtil.encodeBase64(pubKey);
  const pubKeyHex = (new Buffer(pubKeyBase64, 'base64')).toString('hex');

  return pubKeyHex;
};

// This function is tested using the test vectors here:
// http://www.di-mgt.com.au/sha_testvectors.html
KeyStore._concatAndSha256 = function (entropyBuf0, entropyBuf1) {
  const totalEnt = Buffer.concat([entropyBuf0, entropyBuf1]);

  if (totalEnt.length !== entropyBuf0.length + entropyBuf1.length) {
    throw new Error('generateRandomSeed: Logic error! Concatenation of entropy sources failed.');
  }

  return Hash.sha256(totalEnt);
};

KeyStore.DEFAULT_SALT = 'lightwalletSalt';

module.exports = KeyStore;
