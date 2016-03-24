var expect = require('chai').expect;
var Random = require('../../lib/generators/random');
var KeyPair = require('../../lib/generators/key_pair');
var util = require("ethereumjs-util");

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
});