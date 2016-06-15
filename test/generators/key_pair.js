var expect = require('chai').expect;
var Random = require('../../lib/generators/random');
var KeyPair = require('../../lib/generators/key_pair');
var util = require("ethereumjs-util");

// Test with 100 private keys
var addrprivkeyvector = require('../fixtures/addrprivkey100.json')
// Test with 10000 private keys - takes about 40 seconds to run
// var addrprivkeyvector = require('../fixtures/addrprivkey10000.json')

describe("KeyPair", function() {
  describe(".generate", function () {
    it("generates valid keypair", function(done) {
      Random.randomBytes = Random.naclRandom;
      KeyPair.generate(function(e,keypair) {
        expect(keypair.privateKey).to.not.equal(null);
        expect(util.secp256k1.privateKeyVerify(new Buffer(util.stripHexPrefix(keypair.privateKey), 'hex')));
        expect(keypair.publicKey).to.not.equal(null);
        expect(keypair.address).to.not.equal(null);
        done();
      });
    })
  });

  describe("fromPrivateKey", function() {
    addrprivkeyvector.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.key.substring(0,15) + '..."', function (done) {
        var kp = KeyPair.fromPrivateKey(f.key);
        expect(kp.address).to.equal("0x"+f.addr);
        expect(kp.publicKey).to.not.equal(null);
        expect(kp.privateKey).to.equal("0x"+f.key);
        done();
      })
    })
  });

});