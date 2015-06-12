var CryptoJS = require("crypto-js")
var Transaction = require('ethereumjs-tx')
var EC = require('elliptic').ec
var ec = new EC('secp256k1')

var LightWalletKeyStore = module.exports = (function () {

    var keyStore = {};

    var encPrivKeys = {};
    var addresses = [];

    // "Internal" functions

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
            throw new Error("keyStore.signTxWithAddress: No private keys in keyStore.")
        }

        var address = ''
        if (signingAddress === undefined) {
            address = addresses[0]
        }
        else {
            if (encPrivKeys[signingAddress] === undefined) {
                throw new Error("keyStore.signTxWithAddress: Address not found in keyStore")
            }
            address = signingAddress
        }

        var txCopy = new Transaction(new Buffer(rawTx, 'hex'))
        var encPrivKey = encPrivKeys[address]
        var privKey = keyStore._decryptKey(encPrivKey, password)
        var addrFromPrivKey = keyStore._computeAddressFromPrivKey(privKey)
        if (addrFromPrivKey !== address) {
            throw new Error("keyStore.signTxWithAddress: Decrypting private key failed!")
        }
        txCopy.sign(new Buffer(privKey, 'hex'));
        privKey = ''

        return txCopy.serialize().toString('hex')
    }

    return keyStore;

}());
