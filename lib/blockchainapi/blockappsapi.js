
var blockappsapi = function() {}

blockappsapi.prototype.getBalance = function(address) {
    // http://api.blockapps.net/query/account?address=
    return;
}

blockappsapi.prototype.injectTransaction = function(signedTx) {
    // this function will inject a signed transaction into the network
}

blockappsapi.prototype.getNonce = function(address) {
    // http://api.blockapps.net/query/account?address=
    return;
}

blockappsapi.prototype.estimateGas = function(txObject) {
    return;
}

module.exports = blockappsapi;
