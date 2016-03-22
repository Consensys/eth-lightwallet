var Random = require('./random');
var Transaction = require('ethereumjs-tx');
var util = require("ethereumjs-util");
var secp256k1 = util.secp256k1;

function hex0x(buffer) {
  return util.addHexPrefix(buffer.toString('hex'));
}
function generate (callback) {
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
      generate(callback);
    }
  });
}
var KeyPair = {
  generate: generate
};
module.exports = KeyPair;