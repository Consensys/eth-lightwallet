var Random = require('./random');
var Mnemonic = require('bitcore-mnemonic');
var util = require("ethereumjs-util");

function hex0x(buffer) {
  return util.addHexPrefix(buffer.toString('hex'));
}

function generate(callback) {
  Random.randomBytes(16, function(error, rand) {
    if (error) { return callback(error, null) };
    callback(null, fromRandom(rand));
  });
}

function fromRandom(rand) {
  return Mnemonic.fromSeed(rand,Mnemonic.Words.ENGLISH).toString()
}

function toHDPrivateKey(phrase) {
  return new Mnemonic(phrase,Mnemonic.Words.ENGLISH).toHDPrivateKey();
}

var Phrase = {
  generate: generate,
  fromRandom: fromRandom,
  toHDPrivateKey: toHDPrivateKey
};
module.exports = Phrase;