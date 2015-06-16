var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var fixtures = require('./fixtures/keystore')

describe("Keystore", function() {

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe("_encryptSeed _decryptSeed", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed + '"', function () {

        var encryptedSeed = keyStore._encryptSeed(f.mnSeed, f.password)
        var decryptedSeed = keyStore._decryptSeed(encryptedSeed, f.password)

        expect(decryptedSeed).to.equal(f.mnSeed)
      })
    })

  });

  describe("_encryptKey _decryptKey", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the key then returns same key decrypted ' + '"' + f.pubKeyHex + '"', function () {

        var encryptedKey = keyStore._encryptKey(f.pubKeyHex, f.password)
        var decryptedKey = keyStore._decryptKey(encryptedKey, f.password)

        expect(decryptedKey).to.equal(f.pubKeyHex)
      })
    })

  });

  describe("_computeAddressFromPrivKey", function() {

    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.HDPrivKey + '"', function () {

        var address = keyStore._computeAddressFromPrivKey(f.HDPrivKey)

        expect(address).to.equal(f.address)
      })
    })

  });


  describe("setSeed", function() {
    it('throws when a seed has already been set', function() {
      expect(function(){
        keyStore.setSeed(fixtures.valid[0].mnSeed, fixtures.valid[0].password);
        keyStore.setSeed(fixtures.valid[1].mnSeed, fixtures.valid[1].password);

      }).to.throw(/Seed has already been set/)
    })

  });

  describe("generateNewAddress", function() {

  });


  describe("getAddresses", function() {

    // Example
    it("should be empty if no keys have been created", function() {
      expect(keyStore.getAddresses()).to.have.length(0);
    });

  });

  describe("addPrivateKey", function() {

  });

  describe("signTx", function() {

  });

});
