var expect = require("chai").expect;
var keyStore = require("../lib/keystore");
var fixtures = require("./fixtures/keystore");
var Promise = require("bluebird");

// Test with 100 private keys
var addrprivkeyvector = require("./fixtures/addrprivkey100.json");
// Test with 10000 private keys - takes about 40 seconds to run
// var addrprivkeyvector = require('./fixtures/addrprivkey10000.json')

var createVaultProm = Promise.promisify(keyStore.createVault);

describe("Keystore", function() {
  describe("createVault constructor", function() {
    it("accepts a variety of options", function(done) {
      var fixture = fixtures.valid[0];

      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          expect(ks.encSeed).to.not.equal(undefined);
          var decryptedPaddedSeed = keyStore._decryptString(
            ks.encSeed,
            Uint8Array.from(fixtures.valid[0].pwDerivedKey)
          );
          // Check padding
          expect(decryptedPaddedSeed.length).to.equal(240);
          expect(decryptedPaddedSeed.trim()).to.equal(fixtures.valid[0].mnSeed);
          done();
        }
      );
    });

    it("generates a random salt for key generation", function(done) {
      this.timeout(10000);
      var fixture = fixtures.valid[0];

      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          var salt0 = ks.salt;
          expect(ks.salt).to.not.equal(undefined);
          ks.keyFromPassword(fixture.password, function(err, derivedKey) {
            var decryptedPaddedSeed = keyStore._decryptString(
              ks.encSeed,
              derivedKey
            );
            // Check padding
            expect(decryptedPaddedSeed.length).to.equal(240);
            expect(decryptedPaddedSeed.trim()).to.equal(
              fixtures.valid[0].mnSeed
            );
            keyStore.createVault(
              {
                password: fixture.password,
                seedPhrase: fixture.mnSeed,
                hdPathString: fixture.hdPathString
              },
              function(err, ks1) {
                var salt1 = ks1.salt;
                expect(salt0).to.not.equal(salt1);
                done();
              }
            );
          });
        }
      );
    });
  });

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe("_encryptString _decryptString", function() {
    fixtures.valid.forEach(function(f) {
      it(
        "encrypts the seed then returns same seed decrypted " +
          '"' +
          f.mnSeed.substring(0, 25) +
          '..."',
        function(done) {
          var encryptedString = keyStore._encryptString(
            f.mnSeed,
            Uint8Array.from(f.pwDerivedKey)
          );
          var decryptedString = keyStore._decryptString(
            encryptedString,
            Uint8Array.from(f.pwDerivedKey)
          );
          expect(decryptedString).to.equal(f.mnSeed);
          done();
        }
      );
    });
  });

  describe("_encryptKey _decryptKey", function() {
    fixtures.valid.forEach(function(f) {
      it(
        "encrypts the key then returns same key decrypted " +
          '"' +
          f.privKeyHex.substring(0, 15) +
          '..."',
        function(done) {
          var encryptedKey = keyStore._encryptKey(
            f.privKeyHex,
            Uint8Array.from(f.pwDerivedKey)
          );
          var decryptedKey = keyStore._decryptKey(
            encryptedKey,
            Uint8Array.from(f.pwDerivedKey)
          );

          expect(decryptedKey).to.equal(f.privKeyHex);
          done();
        }
      );
    });
  });

  describe("deriveKeyFromPassword", function() {
    it("derives a key correctly from the password", function(done) {
      var derKeyProm = Promise.promisify(keyStore.deriveKeyFromPasswordAndSalt);
      var promArray = [];
      fixtures.valid.forEach(function(f) {
        promArray.push(derKeyProm(f.password, f.salt));
      });
      Promise.all(promArray).then(function(derived) {
        for (var i = 0; i < derived.length; i++) {
          expect(derived[i]).to.deep.equal(
            Uint8Array.from(fixtures.valid[i].pwDerivedKey)
          );
        }
        done();
      });
    });

    it("Checks if a derived key is correct or not", function(done) {
      var derKey = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      var derKey1 = Uint8Array.from(fixtures.valid[1].pwDerivedKey);

      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          var isDerKeyCorrect = ks.isDerivedKeyCorrect(derKey);
          expect(isDerKeyCorrect).to.equal(true);
          var isDerKey1Correct = ks.isDerivedKeyCorrect(derKey1);
          expect(isDerKey1Correct).to.equal(false);
          done();
        }
      );
    });
  });

  describe("_computeAddressFromPrivKey", function() {
    fixtures.valid.forEach(function(f) {
      it(
        "generates valid address from private key " +
          '"' +
          f.privKeyHex.substring(0, 15) +
          '..."',
        function(done) {
          var address =
            "0x" + keyStore._computeAddressFromPrivKey(f.privKeyHex);
          expect(address).to.equal(f.address);
          done();
        }
      );
    });

    addrprivkeyvector.forEach(function(f) {
      it(
        "generates valid address from private key " +
          '"' +
          f.key.substring(0, 15) +
          '..."',
        function(done) {
          var address = keyStore._computeAddressFromPrivKey(f.key);
          expect(address).to.equal(f.addr);
          done();
        }
      );
    });
  });

  describe("serialize deserialize", function() {
    it("serializes empty keystore and returns same non-empty keystore when deserialized ", function(done) {
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, origKS) {
          var serKS = origKS.serialize();
          var deserKS = keyStore.deserialize(serKS, fixture.salt);

          // Retains all attributes properly
          expect(deserKS).to.deep.equal(origKS);
          done();
        }
      );
    });

    it("serializes non-empty keystore and returns same non-empty keystore when deserialized ", function(done) {
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, origKS) {
          //Add Keys
          origKS.generateNewAddress(
            Uint8Array.from(fixtures.valid[0].pwDerivedKey),
            20
          );

          var serKS = origKS.serialize();
          var deserKS = keyStore.deserialize(serKS, fixture.salt);

          // Retains all attributes properly
          expect(deserKS).to.deep.equal(origKS);
          done();
        }
      );
    });
  });

  describe("generateNewAddress", function() {
    var N = fixtures.valid.length;

    it("returns a new address, next in hd wallet", function(done) {
      this.timeout(10000);

      var promArray = [];
      fixtures.valid.forEach(function(fixture) {
        promArray.push(
          createVaultProm({
            password: fixture.password,
            seedPhrase: fixture.mnSeed,
            salt: fixture.salt,
            hdPathString: fixture.hdPathString
          })
        );
      });

      Promise.all(promArray)
        .then(function(keystores) {
          for (var i = 0; i < N; i++) {
            var ks = keystores[i];
            var numAddresses = fixtures.valid[i].hdIndex + 1;
            ks.generateNewAddress(
              Uint8Array.from(fixtures.valid[i].pwDerivedKey),
              numAddresses
            );
            var addresses = ks.getAddresses();
            var addr = addresses[addresses.length - 1];
            var priv = ks.exportPrivateKey(
              addr,
              Uint8Array.from(fixtures.valid[i].pwDerivedKey)
            );
            expect(addr).to.equal(fixtures.valid[i].address);
            expect(priv).to.equal(fixtures.valid[i].privKeyHex);
          }
          done();
        })
        .catch(done);
    });
  });

  describe("getAddresses", function() {
    it("returns the object's address attribute", function(done) {
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          var add0x = function(addr) {
            return "0x" + addr;
          };

          var pwKey = Uint8Array.from(fixture.pwDerivedKey);
          expect(ks.addresses.length).to.equal(0);
          expect(ks.getAddresses()).to.deep.equal(ks.addresses);
          ks.generateNewAddress(pwKey);
          expect(ks.addresses.length).to.equal(1);
          expect(ks.getAddresses()).to.deep.equal(ks.addresses.map(add0x));
          ks.generateNewAddress(pwKey, 5);
          expect(ks.addresses.length).to.equal(6);
          expect(ks.getAddresses()).to.deep.equal(ks.addresses.map(add0x));
          done();
        }
      );
    });
  });

  describe("Seed functions", function() {
    it("returns the unencrypted seed", function(done) {
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          var pwKey = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
          expect(ks.getSeed(pwKey)).to.equal(fixture.mnSeed);
          done();
        }
      );
    });

    it("checks if seed is valid", function(done) {
      var isValid = keyStore.isSeedValid(fixtures.valid[0].mnSeed);
      expect(isValid).to.equal(true);

      isValid = keyStore.isSeedValid(fixtures.invalid[0].mnSeed);
      expect(isValid).to.equal(false);
      done();
    });

    it("concatenates and hashes entropy sources", function(done) {
      var N = fixtures.sha256Test.length;
      for (var i = 0; i < N; i++) {
        var ent0 = new Buffer(fixtures.sha256Test[i].ent0);
        var ent1 = new Buffer(fixtures.sha256Test[i].ent1);
        var outputString = keyStore
          ._concatAndSha256(ent0, ent1)
          .toString("hex");
        expect(outputString).to.equal(fixtures.sha256Test[i].targetHash);
      }
      done();
    });
  });

  describe("exportPrivateKey", function() {
    it("exports the private key corresponding to an address", function(done) {
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
          ks.generateNewAddress(pw, 2);
          var addr = ks.getAddresses();

          var exportedPriv0 = ks.exportPrivateKey(addr[0], pw);
          var exportedPriv1 = ks.exportPrivateKey(addr[1], pw);

          var addrFromExported0 =
            "0x" + keyStore._computeAddressFromPrivKey(exportedPriv0);
          var addrFromExported1 =
            "0x" + keyStore._computeAddressFromPrivKey(exportedPriv1);

          expect(addrFromExported0).to.equal(addr[0]);
          expect(addrFromExported1).to.equal(addr[1]);
          done();
        }
      );
    });
  });

  describe("hooked web3-provider", function() {
    it("implements hasAddress() correctly", function(done) {
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
          ks.generateNewAddress(pw, 5);
          var addr = ks.getAddresses();

          for (var i = 0; i < addr.length; i++) {
            ks.hasAddress(addr[i], function(err, hasAddr) {
              expect(hasAddr).to.equal(true);
            });
            ks.hasAddress(addr[i], function(err, hasAddr) {
              expect(hasAddr).to.equal(true);
            });
          }

          ks.hasAddress("abcdef0123456", function(err, hasAddr) {
            expect(hasAddr).to.equal(false);
          });

          ks.hasAddress("0xabcdef0123456", function(err, hasAddr) {
            expect(hasAddr).to.equal(false);
          });

          done();
        }
      );
    });

    it("implements signTransaction correctly", function(done) {
      var fixture = fixtures.valid[1];

      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          ks.keyFromPassword(fixture.password, function(err, pwDerivedKey) {
            ks.generateNewAddress(pwDerivedKey, 1);
            var addr = ks.getAddresses()[0];

            // Trivial passwordProvider
            ks.passwordProvider = function(callback) {
              callback(null, fixture.password);
            };

            var txParams = fixture.web3TxParams;
            ks.signTransaction(txParams, function(err, signedTx) {
              expect(signedTx.slice(2)).to.equal(fixture.rawSignedTx);
              done();
            });
          });
        }
      );
    });
  });
});
