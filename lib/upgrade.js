const CryptoJS = require('crypto-js');
const Keystore = require('./keystore');

const HD_PATH_STRING = 'm/0\'/0\'/0\'';

function legacyGenerateEncKey(password, salt) {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 512 / 32,
    iterations: 150,
  }).toString();
}

function legacyDecryptString(encryptedStr, password) {
  const { encStr, iv, salt } = encryptedStr;
  const decryptedStr = CryptoJS.AES.decrypt(encStr, password, { iv, salt });

  return decryptedStr.toString(CryptoJS.enc.Latin1);
}

function upgradeVersion1(oldKS, password, callback) {
  const { salt, keyHash, encSeed, hdIndex } = oldKS;
  const derivedKey = legacyGenerateEncKey(password, salt);

  const hash = CryptoJS.SHA3(derivedKey).toString();

  if (keyHash !== hash) {
    callback(new Error('Keystore Upgrade: Invalid Password!'));
    return;
  }

  const seedPhrase = legacyDecryptString(encSeed, derivedKey);

  Keystore.createVault({
    password,
    seedPhrase,
    salt: Keystore.DEFAULT_SALT,
    hdPathString: HD_PATH_STRING
  }, (err, newKeyStore) => {
    if (err) {
      callback(err);
      return;
    }

    newKeyStore.keyFromPassword(password, (err, pwDerivedKey) => {
      if (err) {
        callback(err);
        return;
      }

      newKeyStore.generateNewAddress(pwDerivedKey, hdIndex);

      callback(null, newKeyStore.serialize());
    });
  });
}

function upgradeVersion2(oldKS, password, callback) {
  const { salt = Keystore.DEFAULT_SALT, encSeed, ksData } = oldKS;

  Keystore.deriveKeyFromPasswordAndSalt(password, salt, (err, pwKey) => {
    if (err) {
      callback(err);
      return;
    }

    let seedPhrase = Keystore._decryptString(encSeed, pwKey);
    
    if (seedPhrase) {
      seedPhrase = seedPhrase.trim();
    }

    if (!seedPhrase || !Keystore.isSeedValid(seedPhrase)) {
      callback(new Error('Keystore Upgrade: Invalid provided password.'));
      return;
    }

    const hdPaths = Object.keys(ksData);

    let hdPathString = HD_PATH_STRING;

    if (hdPaths.length > 0) {
      hdPathString = hdPaths[0];
    }

    Keystore.createVault({
      password,
      seedPhrase,
      salt,
      hdPathString
    }, (err, newKeyStore) => {
      if (err) {
        callback(err);
        return;
      }

      newKeyStore.keyFromPassword(password, (err, pwDerivedKey) => {
        if (err) {
          callback(err);
          return;
        }

        const hdIndex = ksData[hdPathString].hdIndex;
        newKeyStore.generateNewAddress(pwDerivedKey, hdIndex);

        callback(null, newKeyStore.serialize());
      });
    });
  });
}

function upgradeOldSerialized(oldSerialized, password, callback) {
  const oldKS = JSON.parse(oldSerialized);
  const { version } = oldKS;

  if (version === undefined || version === 1) {
    upgradeVersion1(oldKS, password, callback);
  } else if (version === 2) {
    upgradeVersion2(oldKS, password, callback);
  } else if (version === 3) {
    callback(null, oldSerialized);
  } else {
    throw new Error('Keystore is not of correct version.');
  }
}

module.exports = {
  upgradeOldSerialized,
};
