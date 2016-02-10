var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var upgrade = require('../lib/upgrade')
var signing = require('../lib/signing')
var fixtures = require('./fixtures/keystore')
var Transaction = require('ethereumjs-tx')

describe("Signing", function () {
  describe("signTx", function() {
    it('signs a transaction deterministically', function(done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey)
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
      ks.generateNewAddress(pw)
      var addr = ks.getAddresses()[0]
      expect('0x' + addr).to.equal(fixtures.valid[0].ethjsTxParams.from)
      
      var tx = new Transaction(fixtures.valid[0].ethjsTxParams)
      var rawTx = tx.serialize().toString('hex')
      expect(rawTx).to.equal(fixtures.valid[0].rawUnsignedTx)
      
      var signedTx0 = signing.signTx(ks, pw, rawTx, addr);
      expect(signedTx0).to.equal(fixtures.valid[0].rawSignedTx)

      done();
    });
  });
});
