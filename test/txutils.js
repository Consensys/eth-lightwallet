var expect = require('chai').expect
var txutils = require('../lib/txutils')
var fixtures = require('./fixtures/txutils')

describe("Utils", function() {

  describe("_getTypesFromAbi", function() {
    fixtures.valid.forEach(function (f) {
      it('returns valid types of function ' + '"' + f.func + '"', function () {

        var types = txutils._getTypesFromAbi(f.abi, f.func)

        expect(types).to.deep.equal(f.types)
      })
    })
  });

  describe("functionTx", function() {
    fixtures.valid.forEach(function (f) {
      it('correct transaction generated', function () {

        var tx = txutils.functionTx(f.abi, f.func, f.args, f.txObject)

        expect(tx).to.equal(f.funcTx)
      })
    })
  });

  describe("createdContractAddress", function() {
    fixtures.valid.forEach(function (f) {
      it('correct contract address is generated', function () {

        var address = txutils.createdContractAddress(f.fromAddress, f.txObject.nonce)

        expect(address).to.equal(f.contractAddress)
      })
    })
  });

  describe("createContractTx valueTx", function() {
    fixtures.valid.forEach(function (f) {
      it('createContractTx returns the same as valueTx and contractAddress', function () {

        var contractTxData = txutils.createContractTx(f.fromAddress, f.txObject)
        var txData = txutils.valueTx(f.txObject)
        var address = txutils.createdContractAddress(f.fromAddress, f.txObject.nonce)

        expect(address).to.equal(contractTxData.addr)
        expect(txData).to.equal(contractTxData.tx)
      })
    })
  });

});
