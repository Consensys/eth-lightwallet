var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var fixtures = require('./fixtures/keystore')

// Test with 100 private keys
var addrprivkeyvector = require('./fixtures/addrprivkey100.json')
// Test with 10000 private keys - takes about 40 seconds to run
// var addrprivkeyvector = require('./fixtures/addrprivkey10000.json')

var Transaction = require('ethereumjs-tx');

describe("Keystore", function() {

  describe("Constructor", function() {

    it("returns empty keystore when no args are passed", function() {
      var ks = new keyStore()
      expect(ks.getAddresses()).to.equal(ks.ksData[ks.defaultHdPathString].addresses);

      // No values are set
      expect(ks.encSeed).to.equal(undefined)
      expect(ks.ksData[ks.defaultHdPathString].encHdRootPrivkey).to.equal(undefined)
      expect(ks.ksData[ks.defaultHdPathString].encPrivKeys).to.deep.equal({})
      expect(ks.ksData[ks.defaultHdPathString].addresses).to.deep.equal([])
    });

    it("sets the hd index to 0", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.ksData[ks.defaultHdPathString].hdIndex).to.equal(0)
    })

    it("returns keystore with an encrypted seed set when give mnemonic and password", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.encSeed).to.not.equal(undefined);
      expect(keyStore._decryptString(ks.encSeed, ks.generateEncKey(fixtures.valid[0].password))).to.equal(fixtures.valid[0].mnSeed);
    });

    it("throws error if invalid mnemonic is given", function() {
      // invalid described in bitcore-mnemonic
      expect(function(){
        new keyStore("als", fixtures.valid[0].password)
      }).to.throw(Error)
    });

    it("throws error if password not given", function() {
      // add
    });
  });

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe("_encryptString _decryptString", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed.substring(0,25) + '..."', function () {

        var encryptedString = keyStore._encryptString(f.mnSeed, f.password)
        var decryptedString = keyStore._decryptString(encryptedString, f.password)

        expect(decryptedString).to.equal(f.mnSeed)
      })
    })

  });

  describe("_encryptKey _decryptKey", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the key then returns same key decrypted ' + '"' + f.privKeyHex.substring(0,15) + '..."', function () {

        var encryptedKey = keyStore._encryptKey(f.privKeyHex, f.password)
        var decryptedKey = keyStore._decryptKey(encryptedKey, f.password)

        expect(decryptedKey).to.equal(f.privKeyHex)
      })
    })

  });

  describe("_computeAddressFromPrivKey", function() {
    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.privKeyHex.substring(0,15) + '..."', function () {
        var address = keyStore._computeAddressFromPrivKey(f.privKeyHex)
        expect(address).to.equal(f.address)
      })
    })

    addrprivkeyvector.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.key.substring(0,15) + '..."', function () {
        var address = keyStore._computeAddressFromPrivKey(f.key)
        expect(address).to.equal(f.addr)
      })
    })

  });

  describe("serialize deserialize", function() {
    it("serializes empty keystore and returns same empty keystore when deserialized ", function() {
      var origKS = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.ksData).to.deep.equal(origKS.ksData)
    });

    it("serializes non-empty keystore and returns same non-empty keystore when deserialized ", function() {
      var origKS = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)

      //Add Keys
      origKS.generateNewAddress(fixtures.valid[0].password, 20)

      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.salt.words).to.deep.equal(origKS.salt.words)
      expect(deserKS.salt.sigBytes).to.deep.equal(origKS.salt.sigBytes)
      expect(deserKS.keyHash).to.deep.equal(origKS.keyHash)
      expect(deserKS.ksData).to.deep.equal(origKS.ksData)
    });
  });


  describe("generateNewAddress", function() {

    var N = fixtures.valid.length;

      it("returns a new address, next in hd wallet", function() {
        this.timeout(10000);
        for (var i=0; i<N; i++) {
          var ks = new keyStore(fixtures.valid[i].mnSeed, fixtures.valid[i].password)
          var numAddresses = fixtures.valid[i].hdIndex+1;
          ks.generateNewAddress(fixtures.valid[i].password, numAddresses);
          var addresses = ks.getAddresses();
          var addr = addresses[addresses.length-1];
          var priv = ks.exportPrivateKey(addr, fixtures.valid[i].password);
          expect(addr).to.equal(fixtures.valid[i].address);
          expect(priv).to.equal(fixtures.valid[i].privKeyHex);
        }
      });
  });


  describe("getAddresses", function() {

    it("returns the object's address attribute", function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.getAddresses()).to.equal(ks.ksData[ks.defaultHdPathString].addresses);
    });

  });

  describe("Seed functions", function() {
    it('returns the unencrypted seed', function() {
      var ks = new keyStore(fixtures.valid[0].mnSeed, fixtures.valid[0].password)
      expect(ks.getSeed(fixtures.valid[0].password)).to.equal(fixtures.valid[0].mnSeed)
    });

    it('checks if seed is valid', function() {
      var isValid = keyStore.isSeedValid(fixtures.valid[0].mnSeed)
      expect(isValid).to.equal(true);
      
      isValid = keyStore.isSeedValid(fixtures.invalid[0].mnSeed)
      expect(isValid).to.equal(false);      
    });

    it('concatenates and hashes entropy sources', function() {

      var N = fixtures.sha256Test.length;
      for (var i=0; i<N; i++) {
        var ent0 = new Buffer(fixtures.sha256Test[i].ent0);
        var ent1 = new Buffer(fixtures.sha256Test[i].ent1);
        var outputString = keyStore._concatAndSha256(ent0, ent1).toString('hex');
        expect(outputString).to.equal(fixtures.sha256Test[i].targetHash);
      }
    })

  });



  describe("exportPrivateKey", function() {
      it('exports the private key corresponding to an address', function() {
          var pw = fixtures.valid[0].password
          var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
          ks.generateNewAddress(pw, 2)
          var addr = ks.getAddresses();
	  
          var exportedPriv0 = ks.exportPrivateKey(addr[0], pw)
          var exportedPriv1 = ks.exportPrivateKey(addr[1], pw)

          var addrFromExported0 = keyStore._computeAddressFromPrivKey(exportedPriv0)
          var addrFromExported1 = keyStore._computeAddressFromPrivKey(exportedPriv1)

          expect(addrFromExported0).to.equal(addr[0])
          expect(addrFromExported1).to.equal(addr[1])
      });
  });
    
  describe("signTx", function() {
    it('signs a transaction deterministically', function() {
      var pw = fixtures.valid[0].password
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
      ks.generateNewAddress(pw)
      var addr = ks.getAddresses()[0]
      expect('0x' + addr).to.equal(fixtures.valid[0].ethjsTxParams.from)
      
      var tx = new Transaction(fixtures.valid[0].ethjsTxParams)
      var rawTx = tx.serialize().toString('hex')
      expect(rawTx).to.equal(fixtures.valid[0].rawUnsignedTx)
      
      var signedTx = ks.signTx(rawTx, pw, addr);
      expect(signedTx).to.equal(fixtures.valid[0].rawSignedTx)
    });
  });

  describe("hooked web3-provider", function() {

    it('implements hasAddress() correctly', function() {
      var pw = fixtures.valid[0].password
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
      ks.generateNewAddress(pw, 5)
      var addr = ks.getAddresses();

      for (var i=0; i<addr.length; i++) {
        ks.hasAddress(addr[i], function (err, hasAddr) {
          expect(hasAddr).to.equal(true)
        })
        ks.hasAddress('0x' + addr[i], function (err, hasAddr) {
          expect(hasAddr).to.equal(true)
        })
      }

      ks.hasAddress('abcdef0123456', function (err, hasAddr) {
        expect(hasAddr).to.equal(false)
      })

      ks.hasAddress('0xabcdef0123456', function (err, hasAddr) {
        expect(hasAddr).to.equal(false)
      })
    });

    it('implements signTransaction correctly', function() {
      var pw = fixtures.valid[0].password
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
      ks.generateNewAddress(pw)
      var addr = ks.getAddresses()[0]

      // Trivial passwordProvider
      ks.passwordProvider = function(callback) {callback(null, pw)}

      var txParams = fixtures.valid[0].web3TxParams
      ks.signTransaction(txParams, function (err, signedTx) {
        expect(signedTx.slice(2)).to.equal(fixtures.valid[0].rawSignedTx)
      });

    });

  });
    
  describe('upgrade old serialized keystore', function () {
    it('upgrades an old keystore', function () {
      var oldKS = require('./fixtures/lightwallet.json')
      var newKS = keyStore.deserialize(keyStore.upgradeOldSerialized(oldKS, 'test'))
      var addresses = newKS.getAddresses();
      expect(addresses).to.deep.equal(oldKS.addresses);
    })
  })

  describe('multiple HD paths', function () {
    it('creates new HD paths', function() {
      var pw = fixtures.valid[0].password;
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/1'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'secp256k1', purpose: 'sign'});
      ks.generateNewAddress(pw, 5, hdPath);
      var addresses = ks.getAddresses(hdPath);
      expect(addresses).to.deep.equal(fixtures.valid[0][hdPath].addresses);
      hdPath = "m/0'/0'/5'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'secp256k1', purpose: 'sign'});
      ks.generateNewAddress(pw, 7, hdPath);
      addresses = ks.getAddresses(hdPath);
      expect(addresses).to.deep.equal(fixtures.valid[0][hdPath].addresses);
    });

    it('creates HD paths with encryption keys', function () {
      var pw = fixtures.valid[0].password;
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/2'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'curve25519', purpose: 'asymEncrypt'});
      expect(function () {ks.generateNewAddress(pw, 5, hdPath);}).to.throw(Error);
      ks.generateNewEncryptionKeys(pw, 6, hdPath);
      var pubKeys = ks.getPubKeys(hdPath);
      expect(pubKeys).to.deep.equal(fixtures.valid[0][hdPath].pubKeys);
    }); 

    it('sets the default HD path', function () {
      var pw = fixtures.valid[0].password;
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/1'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'secp256k1', purpose: 'sign'});
      ks.generateNewAddress(pw, 5, hdPath);
      var addresses0 = ks.getAddresses(hdPath);
      ks.setDefaultHdDerivationPath(hdPath);
      var addresses1 = ks.getAddresses();
      expect(addresses0).to.deep.equal(addresses1);
    })

  });

  describe('Asymmetric Encryption', function() {

    it('encrypts and decrypts a string', function () {
      var pw = fixtures.valid[0].password;
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/2'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'curve25519', purpose: 'asymEncrypt'});
      ks.generateNewEncryptionKeys(pw, 2, hdPath);
      var pubKeys = ks.getPubKeys(hdPath);
      var msg = "Hello World!";
      var encrypted = ks.asymEncryptString(msg, pubKeys[0], pubKeys[1], pw, hdPath);
      var cleartext = ks.asymDecryptString(encrypted, pubKeys[1], pubKeys[0], pw, hdPath);
      expect(cleartext).to.equal(msg);
    });    

  });

  describe('Multi-recipient Encryption', function() {

    this.timeout(10000);

    it('encrypts and decrypts a string to multiple parties', function () {
      var pw = fixtures.valid[0].password;
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/2'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'curve25519', purpose: 'asymEncrypt'});
      ks.generateNewEncryptionKeys(pw, 6, hdPath);
      var pubKeys = ks.getPubKeys(hdPath);
      var msg = "Hello World to multiple people!";
      var encrypted = ks.multiEncryptString(msg, pubKeys[0], pubKeys.slice(0,4), pw, hdPath);
      var cleartext = ks.multiDecryptString(encrypted, pubKeys[0], pubKeys[0], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = ks.multiDecryptString(encrypted, pubKeys[0], pubKeys[1], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = ks.multiDecryptString(encrypted, pubKeys[0], pubKeys[2], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = ks.multiDecryptString(encrypted, pubKeys[0], pubKeys[3], pw, hdPath);
      expect(cleartext).to.equal(msg);
      cleartext = ks.multiDecryptString(encrypted, pubKeys[0], pubKeys[4], pw, hdPath);
      expect(cleartext).to.equal(false);
      
    });

  });



});
