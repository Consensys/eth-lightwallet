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
  var address = "0x7008907ffc8811a5c690b554a81296d38ee35bdd";

  describe("getAddress", function() {
    it("returns its address", function(done) {
      expect(signer.getAddress()).to.equal(address);
      done();
    })
  })

  describe("default path", function() {
    it("defaults to bip44", function(done) {
      expect(signer.path).to.equal("m/44'/60'/0'/0/0");
      done();
    })
  })
  describe("signRawTx", function() {
    it("signs transaction", function(done) {
      signer.signRawTx("f680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901c8080",
        function(e, signedRawTx) {
          expect(signedRawTx).to.equal("f87680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901ba0c3c7c82b17fd1f355d27722049e501fc5f8108c0a94298b6df298f0961537b5da03479ccf724ee60196bc19e37e4d4d23257d1b1d90bebbd267bd647d135e0764c");
          var tx = new Transaction(signedRawTx);
          expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(signer.signer.keypair.publicKey));
          done();
      });
    })
  })

  describe("changed path", function() {
    var signer = new HDSigner(hdPrivateKey, "m/0/0/0/1");
    var address = "0xb89ca0a03c21e9a931f82643df3ee4469a0c896a";

    describe("getAddress", function() {
      it("returns its address", function(done) {
        expect(signer.getAddress()).to.equal(address);
        done();
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
    var signer = new HDSigner(hdPrivateKey, 1);
    var address = "0x653f4156b7e1979af34c0cb1d746a42ed4dc4319";

    describe("getAddress", function() {
      it("returns its address", function(done) {
        expect(signer.getAddress()).to.equal(address);
        done();
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
  describe("legacy path", function() {
    var signer = new HDSigner(hdPrivateKey, "m/0'/0'/0'");
    var address = "0x6f875f2ab111891b1702ec95366064f6c229e382";

    describe("getAddress", function() {
      it("returns its address", function(done) {
        expect(signer.getAddress()).to.equal(address);
        done();
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

});
