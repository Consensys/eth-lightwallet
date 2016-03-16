var Random = require('./random');
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var secp256k1 = util.secp256k1;

// Simple unencrypted signer, not to be used in the browser

var SimpleSigner = function(keypair) {
  this.keypair = keypair;
}

function hex0x(buffer) {
  return util.addHexPrefix(buffer.toString('hex'));
}
SimpleSigner.generateKeypair = function(callback) {
  Random.randomBytes(32, function(error, rand) {
    if (error) { return callback(error, null) };
    if (secp256k1.privateKeyVerify(rand)) {
      var privateKey = new Buffer(rand);
      var publicKey = util.privateToPublic(privateKey);
      callback(null, {
        privateKey: hex0x(privateKey),
        publicKey: hex0x(publicKey),
        address: hex0x(util.pubToAddress(publicKey))
      });
    } else {
      SimpleSigner.generateKeyPair(callback);
    }
  });
}

SimpleSigner.prototype.hasAddress = function(address, callback) {
  callback(null, this.keypair.address === address );
}

SimpleSigner.prototype.getAddresses = function(callback) {
  callback(null, [this.keypair.address]);
}

SimpleSigner.prototype.signRawTx = function(rawTx, callback) {
  var rawTx = util.stripHexPrefix(rawTx);
  var txCopy = new Transaction(new Buffer(rawTx, 'hex'));
  txCopy.sign(new Buffer(util.stripHexPrefix(this.keypair.privateKey), 'hex'));
  callback(null, txCopy.serialize().toString('hex'));
}


module.exports = SimpleSigner;