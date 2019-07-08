const { expect } = require('chai');
const Transaction = require('ethereumjs-tx');
const Util = require('ethereumjs-util');
const KeyStore = require('../lib/keystore');
const Signing = require('../lib/signing');
const fixtures = require('./fixtures/keystore');

describe('Signing', function () {
  describe('signTx', function () {
    it('signs a transaction deterministically', function (done) {
      const pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      const fixture = fixtures.valid[0];

      KeyStore.createVault({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString
      }, function (err, ks) {
        ks.generateNewAddress(pw);

        const addr = ks.getAddresses()[0];
        expect(addr).to.equal(fixtures.valid[0].ethjsTxParams.from);

        const tx = new Transaction(fixtures.valid[0].ethjsTxParams);
        const rawTx = tx.serialize().toString('hex');
        expect(rawTx).to.equal(fixtures.valid[0].rawUnsignedTx);

        const signedTx0 = Signing.signTx(ks, pw, rawTx, addr);
        expect(signedTx0).to.equal(fixtures.valid[0].rawSignedTx);
        done();
      });
    });

    it('Correctly handles a 31 byte key from bitcore', function (done) {
      const secretSeed = 'erupt consider beyond twist bike enroll you salute weasel emerge divert hundred';
      const hdPath = 'm/44\'/60\'/0\''; //as defined in SLIP44
      const password = 'test';

      KeyStore.createVault({
        password: password,
        seedPhrase: secretSeed,
        salt: 'someSalt',
        hdPathString: hdPath
      }, function (err, keystore) {
        keystore.keyFromPassword(password, function (err, pwDerivedKey) {
          keystore.generateNewAddress(pwDerivedKey, 1); //Generate a new address

          const address = keystore.getAddresses()[0];
          const hexSeedETH = keystore.exportPrivateKey(address, pwDerivedKey);
          const addr0 = KeyStore._computeAddressFromPrivKey(hexSeedETH);
          expect(address).to.equal('0x' + addr0);

          const tx = new Transaction({
            from: address,
            to: address,
            value: 100000000
          });
          const rawTx = tx.serialize().toString('hex');
          const signedTx = Signing.signTx(keystore, pwDerivedKey, rawTx, address, hdPath);
          const expectedTx = 'f861808080945e2abe3de708923e8425348005ee7fdd77e203cb8405f5e100801ca00a9a2486f65cab6c7819c82ee741f72d1acaab005642eef32f303696909fa64ea04e5d5e0e8d5f38704ac04faa1f91a9ee15a3ffcf158de342324d242b6acba819';

          expect(signedTx).to.equal(expectedTx);
          done();
        });
      });
    });

    describe('signMsg', function () {
      it('signs a message deterministically', function (done) {
        const pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
        const fixture = fixtures.valid[0];

        KeyStore.createVault({
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        }, function (err, ks) {
          ks.generateNewAddress(pw);

          const addr = ks.getAddresses()[0];
          expect(addr).to.equal(fixtures.valid[0].ethjsTxParams.from);

          const msg = 'this is a message';
          const signedMsg = Signing.signMsg(ks, pw, msg, addr);
          const msgHash = Util.addHexPrefix(Util.keccak(msg).toString('hex'));
          const signedMsgHash = Signing.signMsgHash(ks, pw, msgHash, addr);

          // signedMsg and signedMsgHash have the same signature
          expect(signedMsg.v).to.equal(signedMsgHash.v);
          expect(signedMsg.r.toString()).to.equal(signedMsgHash.r.toString());
          expect(signedMsg.s.toString()).to.equal(signedMsgHash.s.toString());

          const recoveredAddress = Signing.recoverAddress(msg, signedMsg.v, signedMsg.r, signedMsg.s);

          expect(addr).to.equal('0x' + recoveredAddress.toString('hex'));
          const concatSig = Signing.concatSig(signedMsg);
          const expectedConcatSig = '0x7b518ee144b8facf3f21b1f97a6d1f8aea448934d89cf5570e92bcca4d375ab6080f17400eafad3c5808e064ee56cd45321382040fb299fa028ea3cddf3488151c';

          expect(concatSig).to.equal(expectedConcatSig);
          done();
        });
      });
    });
  });
});
