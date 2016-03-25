var Random = require('./random');
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var secp256k1 = util.secp256k1;

function hex0x(buffer) {
  return util.addHexPrefix(buffer.toString('hex'));
}
function fromPrivateKey(privateKey) {
  if (!Buffer.isBuffer(privateKey)) {
    privateKey = new Buffer(privateKey,'hex');
  }
  var publicKey = util.privateToPublic(privateKey);
  return {
        privateKey: hex0x(privateKey),
        publicKey: hex0x(publicKey),
        address: hex0x(util.pubToAddress(publicKey))
      };
}
function generate (callback) {
  Random.randomBytes(32, function(error, rand) {
    if (error) { return callback(error, null) };
    if (secp256k1.privateKeyVerify(rand)) {
      var privateKey = new Buffer(rand);
      callback(null, fromPrivateKey(privateKey));
    } else {
      generate(callback);
    }
  });
}
var KeyPair = {
  generate: generate,
  fromPrivateKey: fromPrivateKey
};
module.exports = KeyPair;