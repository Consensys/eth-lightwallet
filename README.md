# EthLightJs

A minimal ethereum javascript wallet.

## Get Started

```
git clone https://github.com/ConsenSys/LightWallet.git
cd LightWallet
npm install
npm run build-js
```

This will create the file `ethlightjs.min.js` that can be included in an HTML page:

```
<html>
  <body>
    <script src="ethlightjs.min.js"></script>
  </body>
</html>
```

To build a node package:

```
npm install path/to/LightWallet
```

To create a keystore, and sign and send a transaction:




## `keystore` Function definitions

These are the interface functions for the keystore object. The keystore object holds a 12-word seed according to [BIP39][] spec. From this seed you can generate addresses and private keys, and use the private keys to sign transactions.

Note: Addresses and RLP encoded data are in the form of hex-strings. Hex-strings do not start with `0x`.

### `keystore(seed, password)`

Constructor of the keystore object. The seed `seed` is encrypted with `password` and stored encrypted in the keystore.

#### Inputs

* words: string defining a 12-word seed according to [BIP39][]
* password: password to encrypt the seed

[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

### `keystore.generateRandomSeed()`

Generates a string consisting of a random 12-word seed and returns it.

### `keystore.generateNewAddress(password)`

Generates a new address/private key pair from the seed and stores them in the keystore. The private key is stored encrypted with the users password.

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

## `helpers` Function definitions

These are helper functions for packaging up some of the functionality in the `keystore` and `txutils`. They create, sign and send a transaction using `txutils` and `keystore`.

They use an object `blockchainApi` that define the following functions:

* `blockchainApi.getNonce(address)`: Returns the nonce of an address
* `blockchainApi.getBalance(address)`: Returns the balance of an address
* `blockchainApi.injectTransaction(rawTx)`: Injects a signed transaction into the network

We include two APIs: `web3api` and `blockappsapi` with predefined functions calling either an ethereum client or the blockapps backend.

### `helpers.sendFunctionTx(abi, contractAddr, functionName, args, fromAddr, txObject, blockchainApi, keystore, password)`

Creates, signs, and sends a transaction calling a function `functionName` conforming to `abi` of a contract at address `contractAddr` with arguments `args`. Returns the hash of the transaction. The `abi` is a JSON object specifying the ABI of the contract.

The object `txObject` contains the following optional arguments:

* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send in the function call
* `txObject.nonce`: Nonce of `fromAddress`

If the arguments are not provided default values will be used.

### `helpers.sendCreateContractTx(bytecode, fromAddr, txObject, blockchainApi, keystore, password)`

Signs and sends a transaction creating the contract with compiled code `bytecode`. The object `txObject` contains optional arguments as described in the `helpers.sendFunctionTx()` section. Returns the address of the newly created contract.

### `helpers.sendValueTx(fromAddr, toAddr, value, txObject, blockchainApi, keystore, password)`

Signs and send a transaction sending `value` wei from `fromAddr` to `toAddr`. The object `txObject` contains the optional items in the `helpers.sendFunctionTx()` section, except `txObject.value`.

## Examples

See the file `example_usage.js` for usage of `keystore` and `txutils`.

See the file `example_helpers.js` for using the `helpers` functions.

See the file `example_web.html` for an example of how to use the LightWallet functionality in the browser.

## Tests

Run all tests:

```
npm run test
npm run coverage
```

## License
