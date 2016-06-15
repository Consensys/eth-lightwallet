var expect = require('chai').expect;
var Random = require('../../lib/generators/random');
var Phrase = require('../../lib/generators/phrase');
var fixtures = require('../fixtures/keystore');

describe("Phrase", function() {
  describe(".generate", function () {
    it("generates correct seed", function(done) {
      Random.randomBytes = Random.naclRandom;
      Phrase.generate(function(e,phrase) {
        expect(phrase).to.not.equal(null);
        expect(phrase.split(' ').length).to.equal(12);
        done();
      });
    });
  });

  describe(".fromRandom", function () {
    it("generates correct phrase", function(done) {
      expect(Phrase.fromRandom(new Buffer(fixtures.valid[0].seed,'hex'))).to.equal(fixtures.valid[0].mnSeed);
      done();
    })
  });


  describe(".toHDPrivateKey", function () {
    var phrase = "unveil aware reopen used matter army clinic find report metal year jelly";
    it("generates correct HDPrivateKey", function(done) {
      expect(Phrase.toHDPrivateKey(phrase).privateKey.toString('hex')).to.equal(Phrase.toHDPrivateKey(phrase).privateKey.toString('hex'));
      expect(Phrase.toHDPrivateKey(phrase).privateKey.toString('hex')).to.equal("56d60edad8c62421db433e4a91ac5f02c4cf3fe8c1fcc4a22edebe49a47e2f0b");
      // Random.randomBytes = Random.naclRandom;
      // expect(Phrase.generate(function(e,keypair) {
      //   expect(keypair.privateKey).to.not.equal(null);
      //   expect(util.secp256k1.privateKeyVerify(new Buffer(util.stripHexPrefix(keypair.privateKey), 'hex')));
      //   expect(keypair.publicKey).to.not.equal(null);
      //   expect(keypair.address).to.not.equal(null);
      done();
    })
  });
});