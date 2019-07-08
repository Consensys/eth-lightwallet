const { expect } = require('chai');
const KeyStore = require('../lib/keystore');
const Encryption = require('../lib/encryption');
const fixtures = require('./fixtures/keystore');

describe('Encryption', function () {
  describe('Asymmetric Encryption', function () {
    it('encrypts and decrypts a string', function (done) {
      const fixture = fixtures.valid[0];
      const pw = Uint8Array.from(fixture.pwDerivedKey);

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: 'm/0\'/0\'/2\''
      }, function (err, ks) {
        ks.generateNewAddress(pw, 2);
        const addresses = ks.getAddresses();
        const pubKey0 = Encryption.addressToPublicEncKey(ks, pw, addresses[0]);
        const pubKey1 = Encryption.addressToPublicEncKey(ks, pw, addresses[1]);

        const msg = 'Hello World!';
        const encrypted = Encryption.asymEncryptString(ks, pw, msg, addresses[0], pubKey1);
        const clearText = Encryption.asymDecryptString(ks, pw, encrypted, pubKey0, addresses[1]);
        expect(clearText).to.equal(msg);
        done();
      });
    });
  });

  describe('Multi-recipient Encryption', function () {
    this.timeout(10000);

    it('encrypts and decrypts a string to multiple parties', function (done) {
      const fixture = fixtures.valid[0];
      const pw = Uint8Array.from(fixture.pwDerivedKey);

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: 'm/0\'/0\'/2\''
      }, function (err, ks) {

        ks.generateNewAddress(pw, 6);

        const addresses = ks.getAddresses();
        const pubKeys = [];
        addresses.map(function (addr) {
          pubKeys.push(Encryption.addressToPublicEncKey(ks, pw, addr));
        });

        const msg = 'Hello World to multiple people!';
        const encrypted = Encryption.multiEncryptString(ks, pw, msg, addresses[0], pubKeys.slice(0, 4));

        let clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[0]);
        expect(clearText).to.equal(msg);
        clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[1]);
        expect(clearText).to.equal(msg);
        clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[2]);
        expect(clearText).to.equal(msg);
        clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[3]);
        expect(clearText).to.equal(msg);
        clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[4]);
        expect(clearText).to.equal(false);
        done();
      });
    });
  });
});
