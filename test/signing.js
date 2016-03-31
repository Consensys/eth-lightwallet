var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var upgrade = require('../lib/upgrade')
var signing = require('../lib/signing')
var fixtures = require('./fixtures/keystore')
var Transaction = require('ethereumjs-tx')
var nacl = require('tweetnacl')

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

    it('Correctly handles a 31 byte key from bitcore', function(done) {
      var secretSeed = "erupt consider beyond twist bike enroll you salute weasel emerge divert hundred";
      var pwDerivedKey = nacl.randomBytes(32);

      var keystore = new keyStore(secretSeed, pwDerivedKey);
      var hdPath = "m/44'/60'/0'"; //as defined in SLIP44

      keystore.addHdDerivationPath(hdPath, pwDerivedKey, {curve: 'secp256k1', purpose: 'sign'});
      keystore.generateNewAddress(pwDerivedKey, 1, hdPath); //Generate a new address

      var address = keystore.getAddresses(hdPath)[0];
      keystore.setDefaultHdDerivationPath(hdPath);

      var hexSeedETH = keystore.exportPrivateKey(address, pwDerivedKey);
      var addr0 = keyStore._computeAddressFromPrivKey(hexSeedETH);
      expect(address).to.equal(addr0);

      var tx = new Transaction({from: '0x' + address,
                                to: '0x' + address,
                                value: 100000000})
      var rawTx = tx.serialize().toString('hex');

      var signedTx = signing.signTx(keystore, pwDerivedKey, rawTx, address, hdPath)
      var expectedTx = 'f861808080945e2abe3de708923e8425348005ee7fdd77e203cb8405f5e100801ca00a9a2486f65cab6c7819c82ee741f72d1acaab005642eef32f303696909fa64ea04e5d5e0e8d5f38704ac04faa1f91a9ee15a3ffcf158de342324d242b6acba819';

      expect(signedTx).to.equal(expectedTx);
      done();
    });

  });

  describe("signMsg", function() {
    it('signs a message deterministically', function(done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey)
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
      ks.generateNewAddress(pw)
      var addr = ks.getAddresses()[0]
      expect('0x' + addr).to.equal(fixtures.valid[0].ethjsTxParams.from)

      var msg = "this is a message"

      var signedMsg = signing.signMsg(ks, pw, msg, addr)

      var recoveredAddress = signing.recoverAddress(msg, signedMsg.v, signedMsg.r, signedMsg.s)

      expect(addr).to.equal(recoveredAddress.toString('hex'))

      var concatSig = signing.concatSig(signedMsg.v, signedMsg.r, signedMsg.s)
      var expectedConcatSig = '0x7b518ee144b8facf3f21b1f97a6d1f8aea448934d89cf5570e92bcca4d375ab6080f17400eafad3c5808e064ee56cd45321382040fb299fa028ea3cddf3488151c'

      expect(concatSig).to.equal(expectedConcatSig);

      done();
    });

  });
});
