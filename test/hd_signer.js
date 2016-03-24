var expect = require('chai').expect
var Phrase = require('../lib/generators/phrase');
var fixtures = require('./fixtures/keystore')
var HDSigner = require('../lib/hd_signer');
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");

describe("HDSigner", function () {
  var phrase = 'dress bounce bind upset boat slot hub upgrade marriage beauty human short';
  var hdPrivateKey = Phrase.toHDPrivateKey(phrase);
  var signer = new HDSigner(hdPrivateKey);
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

  describe("changed path", function() {
    var signer = new HDSigner(hdPrivateKey, "m/0/0/0/1");
    var address = "0xb89ca0a03c21e9a931f82643df3ee4469a0c896a";

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
            expect(signedRawTx).to.equal("f87680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901ba06bd80a6a5a235dd948cd127858ced293481757706854513fbaafe060744c8158a06628a6d9676765721e49210ecb96fef1b8679cad415f0d76d83803136934a12c");
            var tx = new Transaction(signedRawTx);
            expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(signer.signer.keypair.publicKey));
            done();
        });
      })
    })
  });

  describe("bip44", function() {
    var signer = HDSigner.bip44(hdPrivateKey, 1);
    var address = "0x653f4156b7e1979af34c0cb1d746a42ed4dc4319";

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
            expect(signedRawTx).to.equal("f87680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901ca022a395fd856ca6b0ba809bf0a6c597505a2f67b3bc6eb4912618c45b16fe7b5ca03d5ad061fba6b9fd200a3783303005b3f334984453272b41cf67099a8f06f166");
            var tx = new Transaction(signedRawTx);
            expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(signer.signer.keypair.publicKey));
            done();
        });
      })
    })
  });

});
