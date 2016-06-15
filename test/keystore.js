var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var upgrade = require('../lib/upgrade')
var fixtures = require('./fixtures/keystore')
var Promise = require('bluebird')
var bitcore = require('bitcore-lib');
var Random = bitcore.crypto.Random;


// Test with 100 private keys
var addrprivkeyvector = require('./fixtures/addrprivkey100.json')
// Test with 10000 private keys - takes about 40 seconds to run
// var addrprivkeyvector = require('./fixtures/addrprivkey10000.json')

var Transaction = require('ethereumjs-tx');

describe("Keystore", function() {

  describe("Constructor", function() {

    it("returns empty keystore when no args are passed", function(done) {
      var ks = new keyStore()
      expect(ks.getAddresses()).to.equal(ks.ksData[ks.defaultHdPathString].addresses);

      // No values are set
      expect(ks.encSeed).to.equal(undefined)
      expect(ks.ksData[ks.defaultHdPathString].encHdRootPrivkey).to.equal(undefined)
      expect(ks.ksData[ks.defaultHdPathString].encPrivKeys).to.deep.equal({})
      expect(ks.ksData[ks.defaultHdPathString].addresses).to.deep.equal([])
      done();
    });

    it("sets the hd index to 0", function(done) {
      var ks = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      expect(ks.ksData[ks.defaultHdPathString].hdIndex).to.equal(0)
      done();
    })

    it("returns keystore with an encrypted seed set when give mnemonic and pwDerivedKey", function(done) {
      var ks = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      expect(ks.encSeed).to.not.equal(undefined);
      var decryptedPaddedSeed = keyStore._decryptString(ks.encSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey));
      // Check padding
      expect(decryptedPaddedSeed.length).to.equal(120);
      expect(decryptedPaddedSeed.trim()).to.equal(fixtures.valid[0].mnSeed);
      done();
    });

    it("throws error if invalid mnemonic is given", function(done) {
      // invalid described in bitcore-mnemonic
      expect(function(){
        new keyStore("als", Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      }).to.throw(Error)
      done();
    });

    it("throws error if pwDerivedKey not given", function(done) {
      // add
      done();
    });
  });

  describe("generateRandomSeed", function() {
    it("generates a new new seed everytime", function(done) {
      var seed = keyStore.generateRandomSeed();
      expect(keyStore.isSeedValid(seed)).to.equal(true);
      expect(seed.split(" ").length).to.equal(12);
      expect(seed).to.not.equal(keyStore.generateRandomSeed());
      done();
    });

    it("respects entropy and generates a new new seed everytime", function(done) {
      // Can't really test that entropy creates a better key, but we can test it doesn't break
      var entropy = 'bad-entropy';
      var seed = keyStore.generateRandomSeed(entropy);
      expect(keyStore.isSeedValid(seed)).to.equal(true);
      expect(seed.split(" ").length).to.equal(12);
      expect(seed).to.not.equal(keyStore.generateRandomSeed(entropy));
      done();
    });

    it("respects a passed in externally generated random number", function(done) {
      var randBuf = Random.getRandomBuffer(16);
      var seed = keyStore.generateRandomSeed(undefined, randBuf);
      expect(keyStore.isSeedValid(seed)).to.equal(true);
      expect(seed.split(" ").length).to.equal(12);
      expect(seed).to.equal(keyStore.generateRandomSeed(undefined, randBuf));
      done();
    });

    it("throws an exception if randombuffer is too small", function(done) {
      var randBuf = Random.getRandomBuffer(15);
      expect(function(){
        keyStore.generateRandomSeed(undefined, randBuf);
      }).to.throw(Error)
      done();
    });


    it("respects entropy and generates a new new seed with differing entropies", function(done) {
      var randBuf = Random.getRandomBuffer(16);
      var seed = keyStore.generateRandomSeed('bad-entropy',randBuf);
      expect(keyStore.isSeedValid(seed)).to.equal(true);
      expect(seed.split(" ").length).to.equal(12);
      expect(seed).to.not.equal(keyStore.generateRandomSeed('worse-entropy',randBuf));
      done();
    });

    it("generates the same seed with same entropy and random number", function(done) {
      var randBuf = Random.getRandomBuffer(16);
      var seed = keyStore.generateRandomSeed('bad-entropy',randBuf);
      expect(keyStore.isSeedValid(seed)).to.equal(true);
      expect(seed.split(" ").length).to.equal(12);
      expect(seed).to.equal(keyStore.generateRandomSeed('bad-entropy',randBuf));
      done();
    });


  });

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe("_encryptString _decryptString", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed.substring(0,25) + '..."', function (done) {

        var encryptedString = keyStore._encryptString(f.mnSeed, Uint8Array.from(f.pwDerivedKey))
        var decryptedString = keyStore._decryptString(encryptedString, Uint8Array.from(f.pwDerivedKey))

        expect(decryptedString).to.equal(f.mnSeed)
        done();
      })
    })
  });

  describe("_encryptKey _decryptKey", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the key then returns same key decrypted ' + '"' + f.privKeyHex.substring(0,15) + '..."', function (done) {

        var encryptedKey = keyStore._encryptKey(f.privKeyHex, Uint8Array.from(f.pwDerivedKey))
        var decryptedKey = keyStore._decryptKey(encryptedKey, Uint8Array.from(f.pwDerivedKey))

        expect(decryptedKey).to.equal(f.privKeyHex)
        done();
      })
    })
  });

  describe("deriveKeyFromPassword", function () {
    it("derives a key correctly from the password", function(done) {
      var derKeyProm = Promise.promisify(keyStore.deriveKeyFromPassword);
      var promArray = [];
      fixtures.valid.forEach(function (f) {
        promArray.push(derKeyProm(f.password));
      })
      Promise.all(promArray).then(function(derived) {
        for(var i=0; i<derived.length; i++) {
          expect(derived[i]).to.deep.equal(Uint8Array.from(fixtures.valid[i].pwDerivedKey))
        }
        done();
      })
    })

    it('Checks if a derived key is correct or not', function (done) {
      var derKey = Uint8Array.from(fixtures.valid[0].pwDerivedKey)
      var derKey1 = Uint8Array.from(fixtures.valid[1].pwDerivedKey)
      var ks = new keyStore(fixtures.valid[0].mnSeed, derKey);
      var isDerKeyCorrect = ks.isDerivedKeyCorrect(derKey);
      expect(isDerKeyCorrect).to.equal(true);
      var isDerKey1Correct = ks.isDerivedKeyCorrect(derKey1);
      expect(isDerKey1Correct).to.equal(false);
      done();
    })

  })

  describe("_computeAddressFromPrivKey", function() {
    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.privKeyHex.substring(0,15) + '..."', function (done) {
        var address = keyStore._computeAddressFromPrivKey(f.privKeyHex)
        expect(address).to.equal(f.address)
        done();
      })
    })

    addrprivkeyvector.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.key.substring(0,15) + '..."', function (done) {
        var address = keyStore._computeAddressFromPrivKey(f.key)
        expect(address).to.equal(f.addr)
        done();
      })
    })
  });

  describe("serialize deserialize", function() {
    it("serializes empty keystore and returns same empty keystore when deserialized ", function(done) {
      var origKS = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.encHdRootPriv).to.deep.equal(origKS.encHdRootPriv)
      expect(deserKS.ksData).to.deep.equal(origKS.ksData)
      expect(deserKS.version).to.equal(origKS.version)
      done();
    });

    it("serializes non-empty keystore and returns same non-empty keystore when deserialized ", function(done) {
      var origKS = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))

      //Add Keys
      origKS.generateNewAddress(Uint8Array.from(fixtures.valid[0].pwDerivedKey), 20)

      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.ksData).to.deep.equal(origKS.ksData)
      done();
    });

    it("sets the default HD path to the first path in the keystore when deserializing", function(done){
      var specificHDpath = "m/44'/60'/0'/0"
      var origKS = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey), specificHDpath)

      //Add Keys
      origKS.generateNewAddress(Uint8Array.from(fixtures.valid[0].pwDerivedKey), 20, specificHDpath)

      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.defaultHdPathString).to.deep.equal(specificHDpath)
      done();
    })
  });


  describe("generateNewAddress", function() {

    var N = fixtures.valid.length;

      it("returns a new address, next in hd wallet", function(done) {
        this.timeout(10000);
        for (var i=0; i<N; i++) {
          var ks = new keyStore(fixtures.valid[i].mnSeed, Uint8Array.from(fixtures.valid[i].pwDerivedKey))
          var numAddresses = fixtures.valid[i].hdIndex+1;
          ks.generateNewAddress(Uint8Array.from(fixtures.valid[i].pwDerivedKey), numAddresses);
          var addresses = ks.getAddresses();
          var addr = addresses[addresses.length-1];
          var priv = ks.exportPrivateKey(addr, Uint8Array.from(fixtures.valid[i].pwDerivedKey));
          expect(addr).to.equal(fixtures.valid[i].address);
          expect(priv).to.equal(fixtures.valid[i].privKeyHex);
        }
        done();
      });
  });


  describe("getAddresses", function() {

    it("returns the object's address attribute", function(done) {
      var ks = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      expect(ks.getAddresses()).to.equal(ks.ksData[ks.defaultHdPathString].addresses);
    done();
    });

  });

  describe("Seed functions", function() {
    it('returns the unencrypted seed', function(done) {
      var ks = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      expect(ks.getSeed(Uint8Array.from(fixtures.valid[0].pwDerivedKey))).to.equal(fixtures.valid[0].mnSeed)
      done();
    });

    it('checks if seed is valid', function(done) {
      var isValid = keyStore.isSeedValid(fixtures.valid[0].mnSeed)
      expect(isValid).to.equal(true);

      isValid = keyStore.isSeedValid(fixtures.invalid[0].mnSeed)
      expect(isValid).to.equal(false);
      done();
    });

    it('concatenates and hashes entropy sources', function(done) {

      var N = fixtures.sha256Test.length;
      for (var i=0; i<N; i++) {
        var ent0 = new Buffer(fixtures.sha256Test[i].ent0);
        var ent1 = new Buffer(fixtures.sha256Test[i].ent1);
        var outputString = keyStore._concatAndSha256(ent0, ent1).toString('hex');
        expect(outputString).to.equal(fixtures.sha256Test[i].targetHash);
      }
      done();
    })

  });



  describe("exportPrivateKey", function() {
      it('exports the private key corresponding to an address', function(done) {
          var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey)
          var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
          ks.generateNewAddress(pw, 2)
          var addr = ks.getAddresses();

          var exportedPriv0 = ks.exportPrivateKey(addr[0], pw)
          var exportedPriv1 = ks.exportPrivateKey(addr[1], pw)

          var addrFromExported0 = keyStore._computeAddressFromPrivKey(exportedPriv0)
          var addrFromExported1 = keyStore._computeAddressFromPrivKey(exportedPriv1)

          expect(addrFromExported0).to.equal(addr[0])
          expect(addrFromExported1).to.equal(addr[1])
        done();
      });
  });

  describe("hooked web3-provider", function() {

    it('implements hasAddress() correctly', function(done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey)
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
      done();
    });

    it('implements signTransaction correctly', function(done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey)
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw)
      ks.generateNewAddress(pw)
      var addr = ks.getAddresses()[0]

      // Trivial passwordProvider
      ks.passwordProvider = function(callback) {callback(null, fixtures.valid[0].password)}

      var txParams = fixtures.valid[0].web3TxParams
      ks.signTransaction(txParams, function (err, signedTx) {
        expect(signedTx.slice(2)).to.equal(fixtures.valid[0].rawSignedTx)
        done();
      });

    });

  });

  describe('upgrade old serialized keystore', function () {
    it('upgrades an old keystore', function (done) {
      this.timeout(10000);
      var oldKS = require('./fixtures/lightwallet.json')
      var oldSerialized = JSON.stringify(oldKS);
      upgrade.upgradeOldSerialized(oldSerialized, 'test', function(err, upgradedKeystore) {
        var newKS = keyStore.deserialize(upgradedKeystore);
        var addresses = newKS.getAddresses();
        expect(addresses).to.deep.equal(oldKS.addresses);
        done();
      })
    })
  })

  describe('multiple HD paths', function () {
    it('creates new HD paths', function(done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
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
      done();
    });

    it('creates HD paths with encryption keys', function (done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/2'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'curve25519', purpose: 'asymEncrypt'});
      expect(function () {ks.generateNewAddress(pw, 5, hdPath);}).to.throw(Error);
      ks.generateNewEncryptionKeys(pw, 6, hdPath);
      var pubKeys = ks.getPubKeys(hdPath);
      expect(pubKeys).to.deep.equal(fixtures.valid[0][hdPath].pubKeys);
      done();
    });

    it('sets the default HD path', function (done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
      var hdPath = "m/0'/0'/1'";
      ks.addHdDerivationPath(hdPath, pw, {curve: 'secp256k1', purpose: 'sign'});
      ks.generateNewAddress(pw, 5, hdPath);
      var addresses0 = ks.getAddresses(hdPath);
      ks.setDefaultHdDerivationPath(hdPath);
      var addresses1 = ks.getAddresses();
      expect(addresses0).to.deep.equal(addresses1);
      done();
    })

  });

  describe("Signer Interface", function () {
    var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
    var ks = new keyStore(fixtures.valid[0].mnSeed, pw);
    ks.generateNewAddress(pw, 1);
    ks.passwordProvider = function(callback) {callback(null, fixtures.valid[0].password)}
    var address = fixtures.valid[0].address;
    var signer = ks.signer();


    describe("hasAddress", function() {
      it("returns true for it's address", function(done) {
        signer.hasAddress(address,function(e, result) {
          expect(e).to.equal(null);
          expect(result).to.equal(true);
          done();
        })
      })

      it("returns false for any other address", function(done) {
        signer.hasAddress("0xdaeee689e6fb3e0971ecffba4082a24cfb23ed48",function(e, result) {
          expect(result).to.equal(false);
          done();
        })
      })
    })

    describe("getAddresses", function() {
      it("returns its address", function(done) {
        expect(signer.getAddress()).to.equal(address);
        done();
      })
    })

    describe("signRawTx", function() {
      it("signs transaction", function(done) {
        signer.signRawTx(fixtures.valid[0].rawUnsignedTx,
          function(e, signedRawTx) {
            expect(e).to.equal(null);
            expect(signedRawTx).to.equal("0x"+fixtures.valid[0].rawSignedTx);
            done();
        });
      })
    })
  });
});
