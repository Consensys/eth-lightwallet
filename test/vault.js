var expect = require('chai').expect;
var Vault = require('../lib/vault');

describe("Vault", function (){
  // var vault = new Vault(Vault.constantPasswordProvider("secret"));

  describe(".constantPasswordProvider", function () {
    it("always returns the same password", function(done) {
      var provider = Vault.constantPasswordProvider("secret");
      provider(function(e, password) {
        expect(password).to.eq("secret")
        done();  
      });      
    });
  });
});
