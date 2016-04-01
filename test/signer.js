var expect = require('chai').expect
var SimpleSigner = require('../lib/simple_signer');
var Signer = require('../lib/signer');
var keypair = require('./fixtures/keypair')
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");

describe("Signer", function () {
  describe("with SimpleSigner implementation", function () {
    var signer = new Signer(new SimpleSigner(keypair));

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

    describe("getAddress", function() {
      it("returns its address", function(done) {
        expect(signer.getAddress()).to.equal(keypair.address);
        done();
      })
    })

    describe("getAccounts", function() {
      it("returns its accounts", function(done) {
        signer.getAccounts(function (e,accounts) {
          expect(accounts.length).to.equal(1);
          expect(accounts[0]).to.equal(keypair.address);
          done();
        })
      })
    })

    describe("signTransaction", function() {
      it("signs transaction", function(done) {
        var txParams = {"from" : keypair.address,
                          "to" : "0x9e2068cce22de4e1e80f15cb71ef435a20a3b37c",
                          "nonce" : "0x00",
                          "value" : "0xde0b6b3a7640000",
                          "gas" : "0x2fefd8",
                          "gasPrice" : "0xba43b7400",
                         "data" : "0xabcdef01234567890"};

        signer.signTransaction(txParams, function(e, signedRawTx) {
          expect(signedRawTx).to.equal("0xf87680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901ca0809e3b5ef25f4a3b039139e2fb70f70b636eba89c77a3b01e0c71c1a36d84126a038524dfcd3e412cb6bc37f4594bbad104b6764bb14c64e42c699730106d1885a");
          var tx = new Transaction(signedRawTx);
          expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(keypair.publicKey));
          done();
        });
      })
    })
  })
});
