var expect = require('chai').expect
var SimpleSigner = require('../lib/simple_signer');
var ProxySigner = require('../lib/proxy_signer');
var keypair = require('./fixtures/keypair')
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");

describe("ProxySigner", function () {
  var proxy_address = "0xdaeee689e6fb3e0971ecffba4082a24cfb23ed48"
  var signer = new ProxySigner(proxy_address,new SimpleSigner(keypair));

  describe("getAddress", function() {
    it("returns its address", function(done) {
      expect(signer.getAddress()).to.equal(proxy_address);
      done();
    })
  })

  describe("signRawTx", function() {
    it("signs transaction", function(done) {
      signer.signRawTx("f680850ba43b7400832fefd8949e2068cce22de4e1e80f15cb71ef435a20a3b37c880de0b6b3a7640000890abcdef012345678901c8080",
        function(e, signedRawTx) {
          expect(signedRawTx).to.equal("f9010a01850ba43b7400832fefd894daeee689e6fb3e0971ecffba4082a24cfb23ed4880b8a4d7f31eb90000000000000000000000009e2068cce22de4e1e80f15cb71ef435a20a3b37c0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000090abcdef0123456789000000000000000000000000000000000000000000000001ba0e077be25961bb59352c34d39e95e247b2ee1072c7707fe48022a2f7d557bc760a0103491de60dc3b48d410433a19c1c97440abc37f2ed0ef114c73008a6914724d");
          var tx = new Transaction(signedRawTx);
          expect(tx.getSenderPublicKey().toString('hex')).to.equal(util.stripHexPrefix(keypair.publicKey));
          done();
      });
    })
  })
});
