var bitcore = require('bitcore')
var Mnemonic = require('bitcore-mnemonic')
var keyStore = require('./keystore.js')

// This module uses bip32 to generate new adresses to the keystore
var HDKeyGen = module.exports = (function () {

    var hd = {};
    var index = 0;

    // Takes a bip39 word list and creates master key
    hd.setSeed = function(words) {
        var mn = new Mnemonic(words);
        hd.masterKey = mn.toHDPrivateKey();
    }

    // Generate a new address and add it to the keystore
    hd.generateNewAddress = function(password) {
        if (!hd.masterKey) {
            throw new Error("HDKeyGen: No seed set");
        }
        var key = hd.masterKey.derive(index++);
        keyStore.addPrivateKey(key.privateKey.toString(), password);
    }

    return hd;
}());
