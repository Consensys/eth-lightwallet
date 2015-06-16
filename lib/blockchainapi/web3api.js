var web3 = require('web3')

var web3api = module.exports = (function () {

    var web3api = {};

    try {
        web3.setProvider(new web3.providers.HttpProvider('http://localhost:8545'));
    } catch(e) {
        console.error("Could not connect: %s", e);
    }

    web3api.getBalance = function(address) {
        var bignum = web3.eth.getBalance('0x' + address);
        return bignum.toNumber();
    }

    web3api.injectTransaction = function(txObject) {
        // this function will inject a signed transaction into the network
    }

    web3api.getNonce = function(address) {
        return web3.eth.getTransactionCount('0x' + address);
    }

    web3api.estimateGas = function(txObject) {
        return web3.eth.estimateGas(txObject);
    }

    return web3api;

}());
