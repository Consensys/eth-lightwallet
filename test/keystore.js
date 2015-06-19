var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var fixtures = require('./fixtures/keystore')

describe("Keystore", function() {

  describe("Constructor", function() {

    it("returns empty keystore when no args are passed", function() {
      var ks = new keyStore()
      expect(ks.getAddresses()).to.equal(ks.addresses);

      // No values are set
      expect(ks.encSeed).to.equal(undefined)
      expect(ks.encPrivKeys).to.deep.equal({})
      expect(ks.addresses).to.deep.equal([])
    });

    it("sets the hd index to 0", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.hdIndex).to.equal(0)
    })

    it("returns keystore with an encrypted seed set when give mnemonic and password", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.encSeed).to.not.equal(undefined);
      expect(keyStore._decryptSeed(ks.encSeed, fixtures.valid[0].password)).to.equal(fixtures.valid[0].mnSeed);
    });

    it("throws error if invalid mnemonic is given", function() {
      // invalid described in bitcore-mnemonic
      expect(function(){
        new keyStore("als", fixtures.valid[0].password)
      }).to.throw(Error)
    });

    it("throws error if password not given", function() {
      // add
    });
  });

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe("_encryptSeed _decryptSeed", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed.substring(0,25) + '..."', function () {

        var encryptedSeed = keyStore._encryptSeed(f.mnSeed, f.password)
        var decryptedSeed = keyStore._decryptSeed(encryptedSeed, f.password)

        expect(decryptedSeed).to.equal(f.mnSeed)
      })
    })

  });

  describe("_encryptKey _decryptKey", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the key then returns same key decrypted ' + '"' + f.pubKeyHex.substring(0,15) + '..."', function () {

        var encryptedKey = keyStore._encryptKey(f.pubKeyHex, f.password)
        var decryptedKey = keyStore._decryptKey(encryptedKey, f.password)

        expect(decryptedKey).to.equal(f.pubKeyHex)
      })
    })

  });

  describe("_computeAddressFromPrivKey", function() {
    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.HDPrivKey.substring(0,15) + '..."', function () {
        var address = keyStore._computeAddressFromPrivKey(f.HDPrivKey)
        expect(address).to.equal(f.address)
      })
    })
  });

  describe("serialize deserialize", function() {
    it("serializes empty keystore and returns same empty keystore when deserialized ", function() {
      var origKS = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.hdIndex).to.equal(origKS.hdIndex)
      expect(deserKS.encPrivKeys).to.deep.equal(origKS.encPrivKeys)
      expect(deserKS.addresses).to.deep.equal(origKS.addresses)
    });

    it("serializes non-empty keystore and returns same non-empty keystore when deserialized ", function() {
      var origKS = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)

      //Add Keys
      for (i = 0; i < 20; i++) {
        origKS.generateNewAddress(fixtures.valid[0].password)
      }

      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.hdIndex).to.equal(origKS.hdIndex)
      expect(deserKS.encPrivKeys).to.deep.equal(origKS.encPrivKeys)
      expect(deserKS.addresses).to.deep.equal(origKS.addresses)

    });
  });


  describe("generateNewAddress", function() {
    it("returns a new address, next in hd wallet with hdindex 0", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      var newAddress = ks.generateNewAddress(fixtures.valid[0].password)
      expect(newAddress).to.equal(fixtures.valid[0].address)
    });
  });


  describe("getAddresses", function() {

    it("returns the object's address attribute", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.getAddresses()).to.equal(ks.addresses);
    });

  });

  describe("getSeed", function() {
    it('returns the unencrypted seed', function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.getSeed(fixtures.valid[0].password)).to.equal(fixtures.valid[0].mnSeed)
    });
  });

  describe("_generatePrivKey", function() {

    var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)

    // Add children key sets to test this more completely
    // fixtures.valid.forEach(function (f) {
    //   it('returns next private key in hd wallet with hdIndex ' + f.HDIndex, function() {
    //      var pk = ks._generatePrivKey(fixtures.valid[0].password)
    //      expect(pk).to.equal(fixtures.valid[0].HDPrivKey)
    //   });
    // })

    it('returns next private key in hd wallet with hdIndex 0', function() {
        var pk = ks._generatePrivKey(fixtures.valid[0].password)
        expect(pk).to.equal(fixtures.valid[0].HDPrivKey)

    });

  });

  describe("_addKeyPair", function() {
    var fixture = fixtures.valid[0]
    it('adds both private key and public key pair to keystore obj', function() {
      var ks = new keyStore(fixture.mnSeed, fixture.password)
      ks._addKeyPair(fixture.HDPrivKey, fixture.address, fixture.password)

      expect(ks.addresses).to.include(fixture.address)

      var decFromKS = keyStore._decryptKey(ks.encPrivKeys[fixture.address], fixture.password)
      expect(decFromKS).to.equal(fixture.HDPrivKey)
    });

    //loop and add each, at each check if the priv/pub key is in keystore now
  });

  describe("signTx", function() {

  });

});
