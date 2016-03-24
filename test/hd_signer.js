var expect = require('chai').expect
var Phrase = require('../lib/generators/phrase');
var fixtures = require('./fixtures/keystore')
var HDSigner = require('../lib/hd_signer');
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");

describe("HDSigner", function () {
  var phrase = 'dress bounce bind upset boat slot hub upgrade marriage beauty human short';

  var signer = new HDSigner(Phrase.toHDPrivateKey(phrase));
  var address = "0x6f875f2ab111891b1702ec95366064f6c229e382";

  describe("hasAddress", function() {
    it("returns true for it's address", function(done) {
      signer.hasAddress(address, function(e, result) {
        expect(result).to.equal(true);
        done();
      })
    })

    it("returns false for any other address", function(done) {
      signer.hasAddress("0xdaeee689e6fb3e0971ecffba4082a24cfb23ed48",function(e, result) {
        expect(result).to.equal(false);
        done();
      })
    })
  })

  describe("getAddresses", function() {
    it("returns its address", function(done) {
      signer.getAddresses(function(e, addresses) {
        expect(addresses.length).to.equal(1);
        expect(addresses[0]).to.equal(address);
        done();
      })
    })
  })

  describe("signRawTx", function() {
    it("signs transaction", function(done) {
      signer.signRawTx("f680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901c8080",
        function(e, signedRawTx) {
          expect(signedRawTx).to.equal("f87680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901ca0ab9b5705e2202ebf1a05ff4a7a378aa9715f559ec9ca3b0bb4c35f7b1826e829a05d7cea8ff4cd1e5f3b26a5904e313e43b35fc4b71dc25d6cf7d7a348268c0095");
          var tx = new Transaction(signedRawTx);
          expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(signer.signer.keypair.publicKey));
          done();
      });
    })
  })
});
