var nacl = require('tweetnacl');

var Random = {}

Random.setProvider = function(provider) {
  Random.randomBytes = provider;
}

Random.naclRandom = function(length, callback) {
	callback(null, nacl.randomBytes(length))
}

Random.randomBytes = Random.naclRandom;


module.exports = Random;
