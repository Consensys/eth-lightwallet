# LightWallet

A minimal ethereum javascript wallet.

## Security advisory

Please make sure to update to version 2.3.3. Previous versions contained a bug that could generate addresses that were unrelated to the HD seed if the wrong value of `pwDerivedKey` was passed in to `generateNewAddress()`. This could lead to loss of funds.

## About

LightWallet is a HD wallet that can store your private keys encrypted in the browser to allow you to run Ethereum dapps even if you're not running a local Ethereum node. It uses [BIP32][] and [BIP39][] to generate an HD tree of addresses from a randomly generated 12-word seed.

LightWallet is primarily intended to be a signing provider for the [Hooked Web3 provider](https://github.com/ConsenSys/hooked-web3-provider) through the `keystore` module. This allows you to have full control over your private keys while still connecting to a remote node to relay signed transactions. Moreover, the `txutils` functions can be used to construct transactions when offline, for use in e.g. air-gapped coldwallet implementations.

The default BIP32 HD derivation path is `m/0'/0'/0'/i`.

## Security

Please note that LightWallet has not been through a comprehensive security review at this point. It is still experimental software, intended for small amounts of Ether to be used for interacting with smart contracts on the Ethereum blockchain. Do not rely on it to store larger amounts of Ether yet.


## Get Started

```
npm install eth-lightwallet
```

The `eth-lightwallet` package contains `dist/lightwallet.min.js` that can be included in an HTML page:

```html
<html>
  <body>
    <script src="lightwallet.min.js"></script>
  </body>
</html>
```

The file `lightwallet.min.js` exposes the global object `lightwallet` to the browser which has the two main modules `lightwallet.keystore` and `lightwallet.txutils`.

Sample usage with hooked web3 provider:

```js
// generate a new BIP32 12-word seed
var secretSeed = lightwallet.keystore.generateRandomSeed();

// the seed is stored encrypted by a user-defined password
var password = prompt('Enter password for encryption', 'password');
lightwallet.keystore.deriveKeyFromPassword(password, function (err, pwDerivedKey) {

var ks = new lightwallet.keystore(secretSeed, pwDerivedKey);

// generate five new address/private key pairs
// the corresponding private keys are also encrypted
ks.generateNewAddress(pwDerivedKey, 5);
var addr = ks.getAddresses();

// Create a custom passwordProvider to prompt the user to enter their
// password whenever the hooked web3 provider issues a sendTransaction
// call.
ks.passwordProvider = function (callback) {
  var pw = prompt("Please enter password", "Password");
  callback(null, pw);
};

// Now set ks as transaction_signer in the hooked web3 provider
// and you can start using web3 using the keys/addresses in ks!
});
```

## `keystore` Function definitions

These are the interface functions for the keystore object. The keystore object holds a 12-word seed according to [BIP39][] spec. From this seed you can generate addresses and private keys, and use the private keys to sign transactions.

Note: Addresses and RLP encoded data are in the form of hex-strings. Hex-strings do not start with `0x`.

### `keystore.deriveKeyFromPassword(password, callback)`

Inputs the users password and generates a symmetric key of type `Uint8Array` that is used to encrypt/decrypt the keystore.

### `keystore(seed, pwDerivedKey [,hdPathString])`

Constructor of the keystore object. The seed `seed` is encrypted with `pwDerivedKey` and stored encrypted in the keystore.

#### Inputs

* words: string defining a 12-word seed according to [BIP39][]
* pwDerivedKey: symmetric key to encrypt the seed (Uint8Array)
* hdPathString: optional alternate HD derivation path to use

### `keystore.isDerivedKeyCorrect(pwDerivedKey)`

Returns `true` if the derived key can decrypt the seed, and returns `false` otherwise.

### `keystore.generateRandomSeed([extraEntropy])`

Generates a string consisting of a random 12-word seed and returns it. If the optional argument string `extraEntropy` is present the random data from the Javascript RNG will be concatenated with `extraEntropy` and then hashed to produce the final seed. The string `extraEntropy` can be something like entropy from mouse movements or keyboard presses, or a string representing dice throws.

### `keystore.isSeedValid(seed)`

Checks if `seed` is a valid 12-word seed according to the [BIP39][] specification.

### `keystore.addHdDerivationPath(hdPathString, pwDerivedKey, info)`

Adds the HD derivation path `hdPathString` to the keystore. The `info` structure denotes the curve and purpose for the keys in that path. Supported structures are

* `{curve: 'secp256k1', purpose: 'sign'}`
* `{curve: 'curve25519', purpose: 'asymEncrypt'}`

### `keystore.setDefaultHdDerivationPath(hdPathString)`

Set the default HD Derivation path. This path will be used if the `hdPathString` is omitted from other functions. This is also the path that's used if the keystore is used with the Hooked Web3 Provider.

### `keystore.generateNewAddress(pwDerivedKey [, num, hdPathString])`

Generates a new address/private key pair from the seed and stores them in the keystore. The private key is stored encrypted with the users password derived key. If the integer `num` is supplied a batch of `num` address/key pairs is generated. If `hdPathString` is supplied the new key pairs are generated at that HD Path, otherwise they are generated at `defaultHdPathString`.

### `keystore.deserialize(serialized_keystore)`

Takes a serialized keystore string `serialized_keystore` and returns a new keystore object.

### `keystore.serialize()`

Serializes the current keystore object into a JSON-encoded string and returns that string.

### `keystore.getAddresses()`

Returns a list of hex-string addresses currently stored in the keystore.

### `keystore.getSeed(pwDerivedKey)`

Given the pwDerivedKey, decrypts and returns the users 12-word seed.

### `keystore.exportPrivateKey(address, pwDerivedKey)`

Given the derived key, decrypts and returns the private key corresponding to `address`. This should be done sparingly as the recommended practice is for the `keystore` to sign transactions using `signing.signTx`, so there is normally no need to export private keys.

## `upgrade` Function definitions

### `keystore.upgradeOldSerialized(oldSerialized, password, callback)`

Takes a serialized keystore in an old format and a password. The callback takes the upgraded serialized keystore as its second argument.


### `keystore.generateNewEncryptionKeys(pwDerivedKey [, num, hdPathString])`

Generate `num` new encryption keys at the path `hdPathString`. Only
defined when the purpose of the HD path is `asymEncrypt`.

### `keystore.getPubKeys([hdPathString])`

Return the pubkeys at `hdPathString`, or at the default HD path. Only
defined when the purpose of the HD path is `asymEncrypt`.

## `signing` Function definitions

### `signing.signTx(keystore, pwDerivedKey, rawTx, signingAddress, hdPathString)`

Signs a transaction with the private key corresponding to `signingAddress`.

#### Inputs

* `keystore`: An instance of the keystore with which to sign the TX with.
* `pwDerivedKey`: the users password derived key (Uint8Array)
* `rawTx`: Hex-string defining an RLP-encoded raw transaction.
* `signingAddress`: hex-string defining the address to send the transaction from.
* `hdPathString`: (Optional) A path at which to create the encryption keys. 

#### Return value

Hex-string corresponding to the RLP-encoded raw transaction.

### `signing.signMsg(keystore, pwDerivedKey, rawMsg, signingAddress, hdPathString)`

Signs a message with the private key corresponding to `signingAddress`.

#### Inputs

* `keystore`: An instance of the keystore with which to sign the TX with.
* `pwDerivedKey`: the users password derived key (Uint8Array)
* `rawMsg`: Message to be signed
* `signingAddress`: hex-string defining the address corresponding to the signing private key.
* `hdPathString`: (Optional) A path at which to create the encryption keys. 

#### Return value

Hex-string corresponding to the RLP-encoded raw transaction.

### `recoverAddress(rawMsg, v, r, s)`

Recovers the signing address from the message `rawMsg` and the signature `v, r, s`.


## `encryption` Function definitions

### `encryption.multiEncryptString(keystore, pwDerivedKey, msg, myPubKey, theirPubKeyArray [, hdPathString])`

**NOTE:** The format of encrypted messages has not been finalized and may change at any time, so only use this for ephemeral messages that do not need to be stored encrypted for a long time.

Encrypts the string `msg` with a randomly generated symmetric key, then encrypts that symmetric key assymetrically to each of the pubkeys in `theirPubKeyArray`. The encrypted message can then be read only by sender and the holders of the private keys corresponding to the public keys in `theirPubKeyArray`. The returned object has the following form, where nonces and ciphertexts are encoded in base64:

```js
{ version: 1,
  asymAlg: 'curve25519-xsalsa20-poly1305',
  symAlg: 'xsalsa20-poly1305',
  symNonce: 'SLmxcH3/CPMCCJ7orkI7iSjetRlMmzQH',
  symEncMessage: 'iN4+/b5InlsVo5Bc7GTmaBh8SgWV8OBMHKHMVf7aq5O9eqwnIzVXeX4yzUWbw2w=',
  encryptedSymKey:
   [ { nonce: 'qcNCtKqiooYLlRuIrNlNVtF8zftoT5Cb',
       ciphertext: 'L8c12EJsFYM1K7udgHDRrdHhQ7ng+VMkzOdVFTjWu0jmUzpehFeqyoEyg8cROBmm' },
     { nonce: 'puD2x3wmQKu3OIyxgJq2kG2Hz01+dxXs',
       ciphertext: 'gLYtYpJbeFKXL/WAK0hyyGEelaL5Ddq9BU3249+hdZZ7xgTAZVL8tw+fIVcvpgaZ' },
     { nonce: '1g8VbftPnjc+1NG3zCGwZS8KO73yjucu',
       ciphertext: 'pftERJOPDV2dfP+C2vOwPWT43Q89V74Nfu1arNQeTMphSHqVuUXItbyCMizISTxG' },
     { nonce: 'KAH+cCxbFGSDjHDOBzDhMboQdFWepvBw',
       ciphertext: 'XWmmBmxLEyLTUmUBiWy2wDqedubsa0KTcufhKM7YfJn/eHWhDDptMxYDvaKisFmn' } ] }
```

Note that no padding is applied to `msg`, so it's possible to deduce the length of the string `msg` from the ciphertext. If you don't want this information to be known, please apply padding to `msg` before calling this function.

### `encryption.multiDecryptString(keystore, pwDerivedKey, encMsg, theirPubKey, myPubKey [, hdPathString])`

Decrypt a message `encMsg` created with the function
`multiEncryptString()`. If successful, returns the original message
string. If not successful, returns `false`.

## `txutils` Function definitions

These are the interface functions for the `txutils` module. These functions will create RLP encoded raw unsigned transactions which can be signed using the `keystore.signTx()` command.

### `txutils.createContractTx(fromAddress, txObject)`

Using the data in `txObject`, creates an RLP-encoded transaction that will create the contract with compiled bytecode defined by `txObject.data`. Also computes the address of the created contract.

#### Inputs

* `fromAddress`: Address to send the transaction from
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Endowment (optional)
* `txObject.nonce`: Nonce of `fromAddress`
* `txObject.data`: Compiled code of the contract

#### Output

Object `obj` with fields

* `obj.tx`: RLP encoded transaction (hex string)
* `obj.addr`: Address of the created contract

### `txutils.functionTx(abi, functionName, args, txObject)`

Creates a transaction calling a function with name `functionName`, with arguments `args` conforming to `abi`. The function is defined in a contract with address `txObject.to`.

#### Inputs

* `abi`: Json-formatted ABI as returned from the `solc` compiler
* `functionName`: string with the function name
* `args`: Array with the arguments to the function
* `txObject.to`: Address of the contract
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send
* `txObject.nonce`: Nonce of sending address

#### Output

RLP-encoded hex string defining the transaction.


### `txutils.valueTx(txObject)`

Creates a transaction sending value to `txObject.to`.

#### Inputs

* `txObject.to`: Address to send to
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send
* `txObject.nonce`: Nonce of sending address

#### Output

RLP-encoded hex string defining the transaction.

## Examples

See the file `example_usage.js` for usage of `keystore` and `txutils` in node.

See the file `example_web.html` for an example of how to use the LightWallet keystore together with the Hooked Web3 Provider in the browser.

## Tests

Run all tests:

```
npm run test
npm run coverage
```

[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## License

MIT License.
