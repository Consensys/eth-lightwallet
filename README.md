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

## Function definitions

Note: Addresses and RLP encoded data are in the form of hex-strings. Hex-strings do not start with `0x`.

### `keystore.setSeed(words, password)`

The seed `words` is encrypted with `password` and stored encrypted in the keystore.

#### Inputs

* words: string defining a 12-word seed according to [BIP39][]
* password: password to encrypt the seed

[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

### `keystore.generateNewAddress(password)`

Generates a new address/private key pair from the seed and stores them in the keystore. The private key is stored encrypted with the users password.

### `keystore.getAddresses()`

Returns a list of hex-string addresses currently stored in the keystore.

### `keystore.signTx(rawTx, password, signingAddress)`

Signs a transaction with the private key corresponding to `signingAddress`

#### Inputs

* `rawTx`: Hex-string defining an RLP-encoded raw transaction.
* `password`: the users password (string)
* `fromAddress`: hex-string defining the address to send the transaction from.

#### Return value

Hex-string corresponding to the RLP-encoded raw transaction.

### `txutils.createContractTx(fromAddress, txObject)`

Using the data in `txObject`, creates an RLP-encoded transaction that will create the contract with compiled bytecode defined by `txObject.data`. Also computes the address of the created contract.

#### Inputs

* `fromAddress`: Address to send the transaction from
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas limit
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
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send
* `txObject.nonce`: Nonce of sending address

#### Output

RLP-encoded hex string defining the transaction.


### `txutils.valueTx(txObject)`

Creates a transaction sending value to `txObject.to`.

#### Inputs

* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send
* `txObject.nonce`: Nonce of sending address

#### Output

RLP-encoded hex string defining the transaction.


## Examples

See the file `example_usage.js`.

## Tests

Run all tests:

```
npm run test
```

## License
