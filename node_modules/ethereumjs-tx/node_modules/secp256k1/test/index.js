//tests against the `ecdsa` module
var ecdsa = require('ecdsa');
var BigInteger = require('bigi');
var assert = require('assert');
var sr = require('secure-random');
var CoinKey = require('coinkey');
var ecdsaNative = require('../');

var privateKey = sr.randomBuffer(32);
var msg = sr.randomBuffer(32);
var ck;

var pubKey;
var compactSig;

describe('it should handle basic ecdsa ops', function() {

  it('should create a public key', function() {
    ck = new CoinKey(privateKey, true);
    pubKey = ecdsaNative.createPublicKey(privateKey, true);
    assert(pubKey.toString('hex') === ck.publicKey.toString('hex'), 'incorrect public key');
  });

  it('should sign a message', function() {
    var sig = ecdsaNative.sign(privateKey, msg);
    var s = ecdsa.parseSig(sig);
    assert(ecdsa.verify(msg, s, ck.publicKey), 'the message should verify');
  });

  it('should sign a message async', function(done) {
    ecdsaNative.sign(privateKey, msg, function(result, sig) {
      var s = ecdsa.parseSig(sig);
      assert(ecdsa.verify(msg, s, ck.publicKey), 'the message should verify');
      done();
    });
  });

  it('should verify a signature', function() {
    //testing verification
    var sig2 = ecdsa.sign(msg, ck.privateKey);
    sig2 = new Buffer(ecdsa.serializeSig(sig2));
    assert(ecdsaNative.verify(pubKey, msg, sig2) === 1, 'should verify signature');
  });

  it('should NOT verify an invalid signature', function() {
    //testing verification
    var sig2 = ecdsa.sign(msg, ck.privateKey);
    sig2 = new Buffer(ecdsa.serializeSig(sig2));
    sig2[0] = 0xff;
    assert(ecdsaNative.verify(pubKey, msg, sig2) === -2, 'should NOT verify invalid signature');
  });

  it('should verify a signature async', function(done) {
    //testing verification
    var sig2 = ecdsa.sign(msg, ck.privateKey);
    sig2 = new Buffer(ecdsa.serializeSig(sig2));
    ecdsaNative.verify(pubKey, msg, sig2, function(result) {
      assert(result === 1, 'the result should equal one');
      done();
    });
  });

  it('should create a compact signature', function() {
    var sig = ecdsaNative.signCompact(privateKey, msg);
    //save to use to test verifyCompact
    compactSig = sig;

    var s = {
        r: BigInteger.fromBuffer(sig.r),
        s: BigInteger.fromBuffer(sig.s),
        v: sig.recoveryId
      },
      e = BigInteger.fromBuffer(msg),
      key = ecdsa.recoverPubKey(e, s, s.v);

    assert(key.getEncoded().toString('hex') === pubKey.toString('hex'), 'the recovered Key should be the same as the public key');
  });

  it('should create a compact signature async', function(done) {
    ecdsaNative.signCompact(privateKey, msg, function(result, sig, recoveryId) {
      var s = {
          r: BigInteger.fromBuffer(sig.slice(0, 32)),
          s: BigInteger.fromBuffer(sig.slice(32, 64)),
          v: recoveryId
        },
        e = BigInteger.fromBuffer(msg),
        key = ecdsa.recoverPubKey(e, s, s.v);

      assert(key.getEncoded().toString('hex') === pubKey.toString('hex'), 'the recovered Key should be the same as the public key');
      done();
    });
  });

  it('should recover a compact signature and return the public key', function() {
    var sig = ecdsaNative.recoverCompact(msg, compactSig.signature, compactSig.recoveryId, true);
    assert(sig.toString('hex') === pubKey.toString('hex'));
  });

  it('should recover a compact signature and return the public key, async', function(done) {
    ecdsaNative.recoverCompact(msg, compactSig.signature, compactSig.recoveryId, true, function(result, sig) {
      assert(sig.toString('hex') === pubKey.toString('hex'));
      done();
    });
  });

  it('should recover a compact signature and return the public key, async', function(done) {
    ecdsaNative.recoverCompact(msg, compactSig.signature, compactSig.recoveryId, true, function(result, sig) {
      assert(sig.toString('hex') === pubKey.toString('hex'));
      done();
    });
  });

  it('should not crash when recoverId is out of bounds - sync', function() {
    var sig = ecdsaNative.recoverCompact(msg, compactSig.signature, -27, true);
    assert.strictEqual(sig, null);
  });

  it('should not crash when recoverId is out of bounds - async', function(done) {
    ecdsaNative.recoverCompact(msg, compactSig.signature, -27, true, function(err, sig) {
      assert(err);
      assert.strictEqual(sig, undefined);
      done();
    });
  });
});
