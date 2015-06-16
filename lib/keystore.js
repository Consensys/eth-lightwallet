var CryptoJS = require("crypto-js")
var Transaction = require('ethereumjs-tx')
var EC = require('elliptic').ec
var ec = new EC('secp256k1')
var Mnemonic = require('bitcore-mnemonic')

var LightWalletKeyStore = module.exports = (function () {

    var keyStore = {};

    var hdIndex = 0;
    var encSeed;
    var hdPubkey;

    var encPrivKeys = {};
    var addresses = [];

    // "Internal" functions

    keyStore._encryptSeed = function (seed, password) {
        return CryptoJS.AES.encrypt(seed, password);
    }

    keyStore._decryptSeed = function (encryptedKey, password) {
        var decryptedSeed = CryptoJS.AES.decrypt(encryptedKey, password);
        return decryptedSeed.toString(CryptoJS.enc.Latin1);
    }

    keyStore._encryptKey = function (privKey, password) {
        var privKeyWordArray = CryptoJS.enc.Hex.parse(privKey)
        var encryptedKey = CryptoJS.AES.encrypt(privKeyWordArray, password);
        return encryptedKey;
    }

    keyStore._decryptKey = function (encryptedKey, password) {
        var decryptedKey = CryptoJS.AES.decrypt(encryptedKey, password);
        return decryptedKey.toString(CryptoJS.enc.Hex);
    }

    keyStore._computeAddressFromPrivKey = function (privKey) {
        var keyPair = ec.genKeyPair()
        keyPair._importPrivate(privKey, 'hex')
        var compact = false
        var pubKey = keyPair.getPublic(compact, 'hex')

        return keyStore._computeAddressFromPubKey(pubKey);
    }

    keyStore._computeAddressFromPubKey = function (pubKey) {
        var pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey.slice(2))
        var hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 })
        var address = hash.toString(CryptoJS.enc.Hex).slice(24)

        return address
    }

    keyStore._uncompressPubKey = function (pubKey) {
        var x = pubKey.point.x.toString('hex');
        var y = pubKey.point.y.toString('hex');

        return '04' + x + y;
    }

    // External API functions
    keyStore.setSeed = function(words, password) {
        if (encSeed) {
          throw new Error("keyStore.setSeed: Seed already set");
        }
        encSeed = keyStore._encryptSeed(words, password);
        var mn = new Mnemonic(words);
        hdPubkey = mn.toHDPrivateKey().hdPublicKey;

        keyStore.generateNewAddress();
    }

    keyStore.generateNewAddress = function() {
        if (!encSeed || !hdPubkey) {
            throw new Error("keyStore.generateNewAddress: No seed set");
        }
        var key = hdPubkey.derive(hdIndex++).publicKey;

        keyStore.addPublicKey(key);
    }

    keyStore.getAddresses = function () {
        return addresses;
    }

    keyStore.addPublicKey = function (pubKey) {
        var uncompressedKey = keyStore._uncompressPubKey(pubKey);
        var address = keyStore._computeAddressFromPubKey(uncompressedKey);

        addresses.push(address)
    }

    keyStore.signTx = function (rawTx, password, signingAddress) {

        if (addresses.length === 0) {
            throw new Error("keyStore.signTx: No private keys in keyStore.")
        }

        var addressIndex = addresses.indexOf(signingAddress);
        if (addressIndex === -1) {
            throw new Error("keyStore.signTxWithAddress: Address not found in keyStore")
        }

        var txCopy = new Transaction(new Buffer(rawTx, 'hex'))

        var words = keyStore._decryptSeed(encSeed, password);
        var mn = new Mnemonic(words);
        var privKey = mn.toHDPrivateKey().derive(addressIndex).privateKey.toString();

        var addrFromPrivKey = keyStore._computeAddressFromPrivKey(privKey)
        if (addrFromPrivKey !== signingAddress) {
            throw new Error("keyStore.signTx: Decrypting private key failed!")
        }
        txCopy.sign(new Buffer(privKey, 'hex'));
        privKey = ''

        return txCopy.serialize().toString('hex')
    }

    return keyStore;

}());
