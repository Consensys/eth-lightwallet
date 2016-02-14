var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var upgrade = require('../lib/upgrade')
var encryption = require('../lib/encryption')
var fixtures = require('./fixtures/keystore')

describe("Encryption", function () {

  describe('Asymmetric Encryption', function() {

    it('encrypts and decrypts a string', function (done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/2'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'curve25519', purpose: 'asymEncrypt'});
      ks.generateNewEncryptionKeys(pw, 2, hdPath);
      var pubKeys = ks.getPubKeys(hdPath);
      var msg = "Hello World!";
      var encrypted = encryption.asymEncryptString(ks, msg, pubKeys[0], pubKeys[1], pw, hdPath);
      var cleartext = encryption.asymDecryptString(ks, encrypted, pubKeys[1], pubKeys[0], pw, hdPath);
      expect(cleartext).to.equal(msg);
      done();
    });

  });

  describe('Multi-recipient Encryption', function() {

    this.timeout(10000);

    it('encrypts and decrypts a string to multiple parties', function (done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/2'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'curve25519', purpose: 'asymEncrypt'});
      ks.generateNewEncryptionKeys(pw, 6, hdPath);
      var pubKeys = ks.getPubKeys(hdPath);
      var msg = "Hello World to multiple people!";
      var encrypted = encryption.multiEncryptString(ks, msg, pubKeys[0], pubKeys.slice(0,4), pw, hdPath);
      var cleartext = encryption.multiDecryptString(ks, encrypted, pubKeys[0], pubKeys[0], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = encryption.multiDecryptString(ks, encrypted, pubKeys[0], pubKeys[1], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = encryption.multiDecryptString(ks, encrypted, pubKeys[0], pubKeys[2], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = encryption.multiDecryptString(ks, encrypted, pubKeys[0], pubKeys[3], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = encryption.multiDecryptString(ks, encrypted, pubKeys[0], pubKeys[4], pw, hdPath);
      expect(cleartext).to.equal(false);
      done();
    });

  });
});
