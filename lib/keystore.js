var CryptoJS = require("crypto-js")
var Transaction = require('ethereumjs-tx')
var EC = require('elliptic').ec
var ec = new EC('secp256k1')
var Mnemonic = require('bitcore-mnemonic')

var LightWalletKeyStore = module.exports = (function () {

    var keyStore = {};

    var hdIndex = 0;
    var encSeed = undefined;

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
        var pubKey = keyPair.getPublic(compact, 'hex').slice(2)
        var pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey)
        var hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 })
        var address = hash.toString(CryptoJS.enc.Hex).slice(24)

        return address
    }

    // External API functions
    keyStore.setSeed = function(words, password) {
        encSeed = keyStore._encryptSeed(words, password);
        keyStore.generateNewAddress(password);
    }

    keyStore.generateNewAddress = function(password) {
        if (!encSeed) {
            throw new Error("keyStore.generateNewAddress: No seed set");
        }
        var words = keyStore._decryptSeed(encSeed, password);
        var mn = new Mnemonic(words);
        var key = mn.toHDPrivateKey().derive(hdIndex++);

        keyStore.addPrivateKey(key.privateKey.toString(), password);
    }

    keyStore.getAddresses = function () {
        return addresses;
    }

    keyStore.addPrivateKey = function (privKey, password) {

        var address = keyStore._computeAddressFromPrivKey(privKey)
        var encPrivKey = keyStore._encryptKey(privKey, password)

        encPrivKeys[address] = encPrivKey
        addresses.push(address)
    }

    keyStore.signTx = function (rawTx, password, signingAddress) {

        if (addresses.length === 0) {
            throw new Error("keyStore.signTx: No private keys in keyStore.")
        }

        var address = ''
        if (signingAddress === undefined) {
            address = addresses[0]
        }
        else {
            if (encPrivKeys[signingAddress] === undefined) {
                throw new Error("keyStore.signTx: Address not found in keyStore")
            }
            address = signingAddress
        }

        var txCopy = new Transaction(new Buffer(rawTx, 'hex'))
        var encPrivKey = encPrivKeys[address]
        var privKey = keyStore._decryptKey(encPrivKey, password)
        var addrFromPrivKey = keyStore._computeAddressFromPrivKey(privKey)
        if (addrFromPrivKey !== address) {
            throw new Error("keyStore.signTx: Decrypting private key failed!")
        }
        txCopy.sign(new Buffer(privKey, 'hex'));
        privKey = ''

        return txCopy.serialize().toString('hex')
    }

    return keyStore;

}());
