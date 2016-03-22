var expect = require('chai').expect
var KeyPair = require('../lib/generators/key_pair');
var SimpleSigner = require('../lib/simple_signer');
var keypair = require('./fixtures/keypair')
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");

describe("SimpleSigner", function () {
  var signer = new SimpleSigner(keypair);

  describe("hasAddress", function() {
    it("returns true for it's address", function(done) {
      signer.hasAddress(keypair.address,function(e, result) {
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
        expect(addresses[0]).to.equal(keypair.address);
        done();
      })
    })
  })

  describe("signRawTx", function() {
    it("signs transaction", function(done) {
      signer.signRawTx("f680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901c8080",
        function(e, signedRawTx) {
          expect(signedRawTx).to.equal("f87680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901ca0809e3b5ef25f4a3b039139e2fb70f70b636eba89c77a3b01e0c71c1a36d84126a038524dfcd3e412cb6bc37f4594bbad104b6764bb14c64e42c699730106d1885a");
          var tx = new Transaction(signedRawTx);
          expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(keypair.publicKey));
          done();
      });
    })
  })
});
