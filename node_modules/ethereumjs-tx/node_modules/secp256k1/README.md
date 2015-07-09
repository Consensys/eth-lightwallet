SYNOPSIS [![Build Status](https://travis-ci.org/wanderer/secp256k1-node.svg?branch=master)](https://travis-ci.org/wanderer/secp256k1-node)
===

This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions.   
This library is experimental, so use at your own risk.

INSTALL
===

##### from npm

`npm install secp256k1`

##### from git

`git clone git@github.com:wanderer/secp256k1-node.git`  
`cd secp256k1-node`  
`git submodule init`  
`git submodule update`  
`npm install` 

NOTE: if you have the development version gmp installed secp256k1 will use it. Otherwise it should fallback to openssl. 

USAGE
===
```javascript

var ecdsa = require('secp256k1'),
  sr = require('secure-random'); 

var privateKey = sr.randomBuffer(32);

//a random message to sign
var msg = sr.randomBuffer(32);

//get the public key in a compressed format
var pubKey = ecdsa.createPublicKey(privateKey, true);

//sign the message
var sig = ecdsa.sign(privateKey, msg);

//verify the signature
if(ecdsa.verify(pubKey, msg, sig)){
  console.log("valid signature");
}

```

TEST
===
run `npm test`
 
API
===

secp256k1.verifySecretKey(secretKey) 
-----------------------------
Verify an ECDSA secret key.

**Parameters**

* secretKey - `Buffer`, the secret Key to verify

**Returns**: `Boolean`, `true` if secret key is valid, `false` secret key is invalid

secp256k1.verifyPublicKey(publicKey) 
-----------------------------
Verify an ECDSA public key.

**Parameters**

* publicKey - `Buffer`, the public Key to verify

**Returns**: `Boolean`, `true` if public key is valid, `false` secret key is invalid

secp256k1.sign(secretkey, msg, cb) 
-----------------------------
Create an ECDSA signature.

**Parameters**

* secretkey - `Buffer`, a 32-byte secret key (assumed to be valid)  
* msg - `Buffer`,  a 32-byte message hash being signed 
* cb - `function`, the callback given. The callback is given the signature  

**Returns**: `Buffer`, if no callback is given a 72-byte signature is returned

secp256k1.signCompact(secretKey, msg, cb) 
-----------------------------
Create a compact ECDSA signature (64 byte + recovery id). Runs asynchronously if given a callback

**Parameters**
* secretKey - `Buffer`, a 32-byte secret key (assumed to be valid)  
* msg - `Buffer`, 32-byte message hash being signed  

**cb**: function, the callback which is give `err`, `sig` the  
* sig - `Buffer`   a 64-byte buffer repersenting the signature  
* recid - `Buffer` an int which is the recovery id.  

**Returns**: result only returned if no callback is given
* result.signature
* result.r
* result.s
* result.recoveryId

secp256k1.verify(pubKey, mgs, sig) 
-----------------------------
Verify an ECDSA signature.  Runs asynchronously if given a callback

**Parameters**
* pubKey - `Buffer`, the public key
* mgs - `Buffer`, the 32-byte message hash being verified
* sig - `Buffer`, the signature being verified

**Returns**: Integer,  
   - 1: correct signature
   - 0: incorrect signature
   - -1: invalid public key
   - -2: invalid signature

secp256k1.recoverCompact(msg, sig, recid, compressed,  cb) 
-----------------------------
Recover an ECDSA public key from a compact signature in the process also verifing it.  Runs asynchronously if given a callback

**Parameters**
* msg - `Buffer`, the message assumed to be signed
* sig - `Buffer`, the signature as 64 byte buffer
* recid - `Integer`, the recovery id (as returned by ecdsa_sign_compact)
* compressed - `Boolean`, whether to recover a compressed or uncompressed pubkey
* cb - `function`, Recover an ECDSA public key from a compact signature. In the process also verifing it.

**Returns**: Buffer, the pubkey, a 33 or 65 byte buffer

secp256k1.createPubKey(secKey, compressed) 
-----------------------------
Compute the public key for a secret key.

**Parameters**
* secKey - `Buffer`, a 32-byte private key.
* compressed - `Boolean`, whether the computed public key should be compressed

**Returns**: Buffer, a 33-byte (if compressed) or 65-byte (if uncompressed) area to store the public key.

secp256k1.exportPrivateKey(secertKey, compressed) 
-----------------------------

**Parameters**
* secertKey - `Buffer`
* compressed - `Boolean`

** Returns**: Buffer, privateKey

secp256k1.importPrivateKey(privateKey) 
-----------------------------

**Parameters**
* privateKey - `Buffer`

**Returns**: `Buffer`, secertKey

secp256k1.decompressPublickey(secretKey) 
-----------------------------

**Parameters**
* secretKey - `Buffer`

**Returns**: `Buffer`, This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions

secp256k1.privKeyTweakAdd(secretKey) 
-----------------------------
**Parameters**
* privateKey - `Buffer`
* tweak - `Buffer`

**Returns**: `Buffer`

secp256k1.privKeyTweakMul(privateKey, tweak) 
-----------------------------
**Parameters**
* privateKey - `Buffer`
* tweak - `Buffer`

**Returns**: Buffer

secp256k1.pubKeyTweakAdd(publicKey, tweak) 
-----------------------------
**Parameters**
* publicKey - `Buffer`
* tweak - `Buffer`

**Returns**: `Buffer`

secp256k1.pubKeyTweakMul(publicKey, tweak) 
-----------------------------
**Parameters**
* publicKey - `Buffer`
* tweak - `Buffer`

**Returns**: `Buffer`

LISCENCE
-----------------------------
MIT
