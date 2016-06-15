var nacl = require('tweetnacl');

var Random = {};

Random.setProvider = function(provider) {
  Random.randomBytes = provider;
}

Random.randomBytes = Random.naclRandom = function(length, callback) {
	callback(null, new Buffer(nacl.randomBytes(length)));
}

module.exports = Random;
