# LightWallet

A minimal ethereum javascript wallet.

## About

LightWallet is a HD wallet that can store your private keys encrypted in the browser to allow you to run Ethereum dapps even if you're not running a local Ethereum node. It uses [BIP32][] and [BIP39][] to generate an HD tree of addresses from a randomly generated 12-word seed.

LightWallet is primarily intended to be a signing provider for the [Hooked Web3 provider](https://github.com/ConsenSys/hooked-web3-provider) through the `keystore` module. This allows you to have full control over your private keys while sitll connecting to a remote node to relay signed transactions. Moreover, the `txutils` functions can be used to construct transactions when offline, for use in e.g. air-gapped coldwallet implementations.

The default BIP32 HD derivation path is `m/0'/0'/0'/i`.

## Security

Please note that LightWallet has not been through a comprehensive security review at this point. It is still experimental software, intended for small amounts of Ether to be used for interacting with smart contracts on the Ethereum blockchain. Do not rely on it to store larger amounts of Ether yet.


## Get Started

```
npm install eth-lightwallet
```

The `eth-lightwallet` package contains `dist/lightwallet.min.js` that can be included in an HTML page:

```
<html>
  <body>
    <script src="lightwallet.min.js"></script>
  </body>
</html>
```

The file `lightwallet.min.js` exposes the global object `lightwallet` to the browser which has the two main modules `lightwallet.keystore` and `lightwallet.txutils`.

Sample usage with hooked web3 provider:

```
// generate a new BIP32 12-word seed
var secretSeed = lightwallet.keystore.generateRandomSeed();

// the seed is stored encrypted by a user-defined password
var password = prompt('Enter password for encryption', 'password');
var ks = new lightwallet.keystore(secretSeed, password);

// generate five new address/private key pairs
// the corresponding private keys are also encrypted
ks.generateNewAddress(password, 5);
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
```

## `keystore` Function definitions

These are the interface functions for the keystore object. The keystore object holds a 12-word seed according to [BIP39][] spec. From this seed you can generate addresses and private keys, and use the private keys to sign transactions.

Note: Addresses and RLP encoded data are in the form of hex-strings. Hex-strings do not start with `0x`.

### `keystore(seed, password)`

Constructor of the keystore object. The seed `seed` is encrypted with `password` and stored encrypted in the keystore.

#### Inputs

* words: string defining a 12-word seed according to [BIP39][]
* password: password to encrypt the seed


### `keystore.generateRandomSeed([extraEntropy])`

Generates a string consisting of a random 12-word seed and returns it. If the optional argument string `extraEntropy` is present the random data from the Javascript RNG will be concatenated with `extraEntropy` and then hashed to produce the final seed. The string `extraEntropy` can be something like entropy from mouse movements or keyboard presses, or a string representing dice throws.

### `keystore.isSeedValid(seed)`

Checks if `seed` is a valid 12-word seed according to the [BIP39][] specification.

### `keystore.generateNewAddress(password [, num])`

Generates a new address/private key pair from the seed and stores them in the keystore. The private key is stored encrypted with the users password. If the integer `num` is supplied a batch of `num` address/key pairs is generated.

### `keystore.deserialize(serialized_keystore)`

Takes a serialized keystore string `serialized_keystore` and returns a new keystore object.

### `keystore.serialize()`

Serializes the current keystore object into a JSON-encoded string and returns that string.

### `keystore.getAddresses()`

Returns a list of hex-string addresses currently stored in the keystore.

### `keystore.getSeed(password)`

Given the password, decrypts and returns the users 12-word seed.

### `keystore.exportPrivateKey(address, password)`

Given the password, decrypts and returns the private key corresponding to `address`. This should be done sparingly as the recommended practice is for the `keystore` to sign transactions using `keystore.signTx`, so there is normally no need to export private keys.

### `keystore.signTx(rawTx, password, signingAddress)`

Signs a transaction with the private key corresponding to `signingAddress`

#### Inputs

* `rawTx`: Hex-string defining an RLP-encoded raw transaction.
* `password`: the users password (string)
* `fromAddress`: hex-string defining the address to send the transaction from.

#### Return value

Hex-string corresponding to the RLP-encoded raw transaction.

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
