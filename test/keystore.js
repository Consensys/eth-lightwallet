var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var fixtures = require('./fixtures/keystore')
var bitcore = require('bitcore')

describe("Keystore", function() {

  describe("Constructor", function() {

    it("returns empty keystore when no args are passed", function() {
      var ks = new keyStore()
      expect(ks.getAddresses()).to.equal(ks.addresses);

      // No values are set
      expect(ks.encSeed).to.equal(undefined)
      expect(ks.encMasterPriv).to.equal(undefined)
      expect(ks.masterPub).to.equal(undefined)
      expect(ks.addresses).to.deep.equal([])
    });

    it("sets the hd index to 0", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.hdIndex).to.equal(0)
    })

    it("returns keystore with an encrypted seed set when give mnemonic and password", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.encSeed).to.not.equal(undefined);
      expect(keyStore._decryptString(ks.encSeed, fixtures.valid[0].password)).to.equal(fixtures.valid[0].mnSeed);
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
  describe("_encryptString _decryptString", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed.substring(0,25) + '..."', function () {

        var encryptedString = keyStore._encryptString(f.mnSeed, f.password)
        var decryptedString = keyStore._decryptString(encryptedString, f.password)

        expect(decryptedString).to.equal(f.mnSeed)
      })
    })

  });

  describe("_computeAddressFromPrivKey _computeAddressFromPubKey", function() {
    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.HDPrivKey.substring(0,15) + '..."', function () {
        var address1 = keyStore._computeAddressFromPrivKey(f.HDPrivKey)
        var buffer = new Buffer(f.HDPrivKey)
        var bitcorePub = new bitcore.HDPrivateKey(f.xHDPrivKey).publicKey
        var pubkey = keyStore._uncompressPubKey(bitcorePub)
        var address2 = keyStore._computeAddressFromPubKey(pubkey)
        expect(address1).to.equal(f.address)
        expect(address2).to.equal(f.address)
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
      var newAddress = ks.generateNewAddress()
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

  describe("signTx", function() {

  });

});
