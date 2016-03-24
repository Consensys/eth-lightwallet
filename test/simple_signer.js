var expect = require('chai').expect
var KeyPair = require('../lib/generators/key_pair');
var SimpleSigner = require('../lib/simple_signer');
var keypair = require('./fixtures/keypair')
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");

describe("SimpleSigner", function () {
  var signer = new SimpleSigner(keypair);

  describe("getAddress", function() {
    it("returns its address", function(done) {
      expect(signer.getAddress()).to.equal(keypair.address);
      done();
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
