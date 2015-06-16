
var blockappsapi = module.exports = (function () {

    var baapi = {};

    baapi.getBalance = function(address) {
        // http://api.blockapps.net/query/account?address=
        return;
    }

    baapi.injectTransaction = function(txObject) {
        // this function will inject a signed transaction into the network
    }

    baapi.getNonce = function(address) {
        // http://api.blockapps.net/query/account?address=
        return;
    }

    baapi.estimateGas = function(txObject) {
        return;
    }

    return baapi;

}());
