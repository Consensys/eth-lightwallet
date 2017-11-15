var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var upgrade = require('../lib/upgrade')
var encryption = require('../lib/encryption')
var fixtures = require('./fixtures/keystore')

describe("Encryption", function () {

  describe('Asymmetric Encryption', function() {

    it('encrypts and decrypts a string', function (done) {

      var fixture = fixtures.valid[0]
      var pw = Uint8Array.from(fixture.pwDerivedKey)

      keyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: "m/0'/0'/2'"
      }, function (err, ks) {

        ks.generateNewAddress(pw, 2)
        var addresses = ks.getAddresses()
        var pubKey0 = encryption.addressToPublicEncKey(ks, pw, addresses[0])
        var pubKey1 = encryption.addressToPublicEncKey(ks, pw, addresses[1])

        var msg = "Hello World!"
        var encrypted = encryption.asymEncryptString(ks, pw, msg, addresses[0], pubKey1)
        var cleartext = encryption.asymDecryptString(ks, pw, encrypted, pubKey0, addresses[1])
        expect(cleartext).to.equal(msg)
        done()
      })
    });

  });

  describe('Multi-recipient Encryption', function() {

    this.timeout(10000);

    it('encrypts and decrypts a string to multiple parties', function (done) {

      var fixture = fixtures.valid[0]
      var pw = Uint8Array.from(fixture.pwDerivedKey)

      keyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: "m/0'/0'/2'"
      }, function (err, ks) {

        ks.generateNewAddress(pw, 6)
        var addresses = ks.getAddresses()
        var pubKeys = []
        addresses.map(function(addr) {
          pubKeys.push(encryption.addressToPublicEncKey(ks, pw, addr))
        })

        var msg = "Hello World to multiple people!";
        var encrypted = encryption.multiEncryptString(ks, pw, msg, addresses[0], pubKeys.slice(0,4));
        var cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[0]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[1]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[2]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[3]);
        expect(cleartext).to.equal(msg);
        cleartext = encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[4]);
        expect(cleartext).to.equal(false);
        done();
      });

    });
  });
})
