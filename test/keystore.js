const { expect } = require('chai');
const Promise = require('bluebird');
const KeyStore = require('../lib/keystore');
const Upgrade = require('../lib/upgrade');
const fixtures = require('./fixtures/keystore');

// Test with 100 private keys
const addrPrivKeyVector = require('./fixtures/addrprivkey100.json');
// Test with 10000 private keys - takes about 40 seconds to run
// const addrPrivKeyVector = require('./fixtures/addrprivkey10000.json')

const createVaultProm = Promise.promisify(KeyStore.createVault);

describe('Keystore', function () {
  describe('createVault constructor', function () {
    it('accepts a variety of options', function (done) {
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        expect(ks.encSeed).to.not.equal(undefined);
        const decryptedPaddedSeed = KeyStore._decryptString(ks.encSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey));
        // Check padding
        expect(decryptedPaddedSeed.length).to.equal(120);
        expect(decryptedPaddedSeed.trim()).to.equal(fixtures.valid[0].mnSeed);
        done();
      });
    });

    it('generates a random salt for key generation', function (done) {
      this.timeout(10000);
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        const salt0 = ks.salt;
        expect(ks.salt).to.not.equal(undefined);
        ks.keyFromPassword(fixture.password, function (err, derivedKey) {
          const decryptedPaddedSeed = KeyStore._decryptString(ks.encSeed, derivedKey);
          // Check padding
          expect(decryptedPaddedSeed.length).to.equal(120);
          expect(decryptedPaddedSeed.trim()).to.equal(fixtures.valid[0].mnSeed);
          KeyStore.createVault({
            password: fixture.password,
            seedPhrase: fixture.mnSeed,
            hdPathString: fixture.hdPathString
          }, function (err, ks1) {
            const salt1 = ks1.salt;
            expect(salt0).to.not.equal(salt1);
            done();
          });
        });
      });
    });
  });


  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe('_encryptString _decryptString', function () {
    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed.substring(0, 25) + '..."', function (done) {
        const encryptedString = KeyStore._encryptString(f.mnSeed, Uint8Array.from(f.pwDerivedKey));
        const decryptedString = KeyStore._decryptString(encryptedString, Uint8Array.from(f.pwDerivedKey));

        expect(decryptedString).to.equal(f.mnSeed);
        done();
      });
    });
  });

  describe('_encryptKey _decryptKey', function () {
    fixtures.valid.forEach(function (f) {
      it('encrypts the key then returns same key decrypted ' + '"' + f.privKeyHex.substring(0, 15) + '..."', function (done) {
        const encryptedKey = KeyStore._encryptKey(f.privKeyHex, Uint8Array.from(f.pwDerivedKey));
        const decryptedKey = KeyStore._decryptKey(encryptedKey, Uint8Array.from(f.pwDerivedKey));

        expect(decryptedKey).to.equal(f.privKeyHex);
        done();
      });
    });
  });

  describe('deriveKeyFromPassword', function () {
    it('derives a key correctly from the password', function (done) {
      const derKeyProm = Promise.promisify(KeyStore.deriveKeyFromPasswordAndSalt);
      const promArray = [];

      fixtures.valid.forEach(function (f) {
        promArray.push(derKeyProm(f.password, f.salt));
      });

      Promise.all(promArray).then(function (derived) {
        for (let i = 0; i < derived.length; i++) {
          expect(derived[i]).to.deep.equal(Uint8Array.from(fixtures.valid[i].pwDerivedKey));
        }
        done();
      });
    });

    it('Checks if a derived key is correct or not', function (done) {
      const derKey = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      const derKey1 = Uint8Array.from(fixtures.valid[1].pwDerivedKey);
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        const isDerKeyCorrect = ks.isDerivedKeyCorrect(derKey);
        expect(isDerKeyCorrect).to.equal(true);
        const isDerKey1Correct = ks.isDerivedKeyCorrect(derKey1);
        expect(isDerKey1Correct).to.equal(false);
        done();
      });
    });

  });

  describe('_computeAddressFromPrivKey', function () {
    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.privKeyHex.substring(0, 15) + '..."', function (done) {
        const address = '0x' + KeyStore._computeAddressFromPrivKey(f.privKeyHex);
        expect(address).to.equal(f.address);
        done();
      });
    });

    addrPrivKeyVector.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.key.substring(0, 15) + '..."', function (done) {
        const address = KeyStore._computeAddressFromPrivKey(f.key);
        expect(address).to.equal(f.addr);
        done();
      });
    });
  });

  describe('serialize deserialize', function () {
    it('serializes empty keystore and returns same non-empty keystore when deserialized ', function (done) {
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, origKS) {
        const serKS = origKS.serialize();
        const deserKS = KeyStore.deserialize(serKS);

        // Retains all attributes properly
        expect(deserKS).to.deep.equal(origKS);
        done();
      });
    });

    it('serializes non-empty keystore and returns same non-empty keystore when deserialized ', function (done) {
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, origKS) {
        //Add Keys
        origKS.generateNewAddress(Uint8Array.from(fixtures.valid[0].pwDerivedKey), 20);

        const serKS = origKS.serialize();
        const deserKS = KeyStore.deserialize(serKS);

        // Retains all attributes properly
        expect(deserKS).to.deep.equal(origKS);
        done();
      });
    });
  });


  describe('generateNewAddress', function () {
    const N = fixtures.valid.length;

    it('returns a new address, next in hd wallet', function (done) {
      this.timeout(10000);

      const promArray = [];
      fixtures.valid.forEach(function (fixture) {
        promArray.push(createVaultProm({
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        }));
      });

      Promise.all(promArray).then(function (keystores) {
        for (let i = 0; i < N; i++) {
          const ks = keystores[i];
          const numAddresses = fixtures.valid[i].hdIndex + 1;
          ks.generateNewAddress(Uint8Array.from(fixtures.valid[i].pwDerivedKey), numAddresses);
          const addresses = ks.getAddresses();
          const addr = addresses[addresses.length - 1];
          const priv = ks.exportPrivateKey(addr, Uint8Array.from(fixtures.valid[i].pwDerivedKey));
          expect(addr).to.equal(fixtures.valid[i].address);
          expect(priv).to.equal(fixtures.valid[i].privKeyHex);
        }
        done();
      }).catch(done);
    });
  });


  describe('getAddresses', function () {
    it('returns the object\'s address attribute', function (done) {
      const fixture = fixtures.valid[0];
      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        const add0x = function (addr) {
          return ('0x' + addr);
        };

        const pwKey = Uint8Array.from(fixture.pwDerivedKey);
        expect(ks.addresses.length).to.equal(0);
        expect(ks.getAddresses()).to.deep.equal(ks.addresses);
        ks.generateNewAddress(pwKey);
        expect(ks.addresses.length).to.equal(1);
        expect(ks.getAddresses()).to.deep.equal(ks.addresses.map(add0x));
        ks.generateNewAddress(pwKey, 5);
        expect(ks.addresses.length).to.equal(6);
        expect(ks.getAddresses()).to.deep.equal(ks.addresses.map(add0x));
        done();
      });
    });
  });

  describe('Seed functions', function () {
    it('returns the unencrypted seed', function (done) {
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        const pwKey = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
        expect(ks.getSeed(pwKey)).to.equal(fixture.mnSeed);
        done();
      });
    });

    it('checks if seed is valid', function (done) {
      let isValid = KeyStore.isSeedValid(fixtures.valid[0].mnSeed);
      expect(isValid).to.equal(true);

      isValid = KeyStore.isSeedValid(fixtures.invalid[0].mnSeed);
      expect(isValid).to.equal(false);
      done();
    });

    it('concatenates and hashes entropy sources', function (done) {
      const N = fixtures.sha256Test.length;

      for (let i = 0; i < N; i++) {
        const ent0 = new Buffer(fixtures.sha256Test[i].ent0);
        const ent1 = new Buffer(fixtures.sha256Test[i].ent1);
        const outputString = KeyStore._concatAndSha256(ent0, ent1).toString('hex');
        expect(outputString).to.equal(fixtures.sha256Test[i].targetHash);
      }

      done();
    });
  });

  describe('exportPrivateKey', function () {
    it('exports the private key corresponding to an address', function (done) {
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        const pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
        ks.generateNewAddress(pw, 2);
        const addr = ks.getAddresses();

        const exportedPriv0 = ks.exportPrivateKey(addr[0], pw);
        const exportedPriv1 = ks.exportPrivateKey(addr[1], pw);

        const addrFromExported0 = '0x' + KeyStore._computeAddressFromPrivKey(exportedPriv0);
        const addrFromExported1 = '0x' + KeyStore._computeAddressFromPrivKey(exportedPriv1);

        expect(addrFromExported0).to.equal(addr[0]);
        expect(addrFromExported1).to.equal(addr[1]);
        done();
      });
    });
  });

  describe('hooked web3-provider', function () {
    it('implements hasAddress() correctly', function (done) {
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        const pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
        ks.generateNewAddress(pw, 5);
        const addr = ks.getAddresses();

        for (let i = 0; i < addr.length; i++) {
          ks.hasAddress(addr[i], function (err, hasAddr) {
            expect(hasAddr).to.equal(true);
          });
          ks.hasAddress(addr[i], function (err, hasAddr) {
            expect(hasAddr).to.equal(true);
          });
        }

        ks.hasAddress('abcdef0123456', function (err, hasAddr) {
          expect(hasAddr).to.equal(false);
        });

        ks.hasAddress('0xabcdef0123456', function (err, hasAddr) {
          expect(hasAddr).to.equal(false);
        });

        done();
      });
    });

    it('implements signTransaction correctly', function (done) {
      const fixture = fixtures.valid[1];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        ks.keyFromPassword(fixture.password, function (err, pwDerivedKey) {

          ks.generateNewAddress(pwDerivedKey, 1);
          const addr = ks.getAddresses()[0];

          // Trivial passwordProvider
          ks.passwordProvider = function (callback) {
            callback(null, fixture.password);
          };

          const txParams = fixture.web3TxParams;
          ks.signTransaction(txParams, function (err, signedTx) {
            expect(signedTx.slice(2)).to.equal(fixture.rawSignedTx);
            done();
          });
        });
      });
    });
  });

  describe('upgrade old serialized keystore', function () {
    it('upgrades a keystore older than version 2', function (done) {
      this.timeout(10000);
      const oldKS = require('./fixtures/lightwallet.json');
      const oldSerialized = JSON.stringify(oldKS);

      Upgrade.upgradeOldSerialized(oldSerialized, 'test', function (err, upgradedKeystore) {
        const newKS = KeyStore.deserialize(upgradedKeystore);
        expect(newKS.addresses).to.deep.equal(oldKS.addresses);
        done();
      });
    });

    it('upgrades a version 2 keystore', function (done) {
      this.timeout(10000);
      const oldKS = require('./fixtures/lightwalletv2.json');
      const oldSerialized = JSON.stringify(oldKS);

      Upgrade.upgradeOldSerialized(oldSerialized, 'PHveKjhQ&8dwWEdhu]q6', function (err, upgradedKeystore) {
        const newKS = KeyStore.deserialize(upgradedKeystore);
        expect(newKS.addresses).to.deep.equal(oldKS.ksData[newKS.hdPathString].addresses);
        done();
      });
    });
  });
});
