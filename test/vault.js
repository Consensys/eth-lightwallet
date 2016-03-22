var expect = require('chai').expect;
var Random = require('../lib/generators/random');
var Vault = require('../lib/vault');

describe("Vault", function (){
  describe(".constantPasswordProvider", function () {
    it("always returns the same password", function(done) {
      var provider = Vault.constantPasswordProvider("secret");
      provider(function(e, password) {
        expect(password).to.eq("secret")
        done();
      });
    });
  });

  describe(".encryptString", function(){
    var vault = new Vault(Vault.constantPasswordProvider("secret"));
    vault.randomBytes = Random.naclRandom;
    it("encrypts the string", function(done) {
      vault.encryptString("ssh don't tell",function(e, encrypted) {
        expect(encrypted).to.not.eq(null);
        vault.decrypt(encrypted, function(e,plain) {
          expect(plain).to.eq("ssh don't tell");
          done();
        })
      })
    })
  })

  describe(".encryptKey", function(){
    var vault = new Vault(Vault.constantPasswordProvider("secret"));
    vault.randomBytes = Random.naclRandom;
    it("encrypts the key", function(done) {
      vault.encryptKey("0123456789abcdef",function(e, encrypted) {
        expect(encrypted).to.not.eq(null);
        vault.decrypt(encrypted, function(e,plain) {
          expect(plain).to.eq("0123456789abcdef");
          done();
        })
      })
    })
  })

  describe(".sealString", function(){
    var vault = new Vault(Vault.constantPasswordProvider("secret"));
    vault.randomBytes = Random.naclRandom;
    it("encrypts the string", function(done) {
      vault.sealString("seed","ssh don't tell",function(e, success) {
        expect(vault.store.seed).to.not.eq(null);
        vault.unseal("seed", function(e,plain) {
          expect(plain).to.eq("ssh don't tell");
          done();
        })
      })
    })
  })

  describe(".sealKey", function(){
    var vault = new Vault(Vault.constantPasswordProvider("secret"));
    vault.randomBytes = Random.naclRandom;
    it("encrypts the string", function(done) {
      vault.sealKey("seed","0123456789abcdef",function(e, success) {
        expect(vault.store.seed).to.not.eq(null);
        vault.unseal("seed", function(e,plain) {
          expect(plain).to.eq("0123456789abcdef");
          done();
        })
      })
    })
  })

});
