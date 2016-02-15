# Release Notes #

## Version 2.1.0 - 2016-02-14 ##

* Refactoring by [cubedro](https://github.com/cubedro) - move functions out to separate modules (signing, encryption) in order to make the core keystore object less cluttered.

## Version 2.0.0 - 2016-02-09 ##

* Big refactoring of password handling. Key derivation is now moved out into an asyncronous function allowing for more secure password-based key derivation or user-supplied keys. A helper function is provided with Scrypt key derivation.

* Change from using AES for keystore encryption to using xsalsa20 (in the form of `nacl.secretbox`). This provides a simpler interface for the symmetric encryption.

* Updated tests with the new password handling and correct usage of `done()`.

## Version 1.0.1 - 2016-01-19 ##

* Formatting changes in documentation.

## Version 1.0.0 - 2015-12-09 ##

* Ability to have multiple HD derivation paths - allowing multiple Personas from one wallet seed

* The ability to designate that keys from a derivation path should be used for asymmetric encryption using Curve25519

* Ability to encrypt messages using keys in the lightwallet: messages can be encrypted to multiple recipients, allowing selective disclosure of Persona attributes as well as things like encrypted group chats between Personas

* A massive test of the private key —> address functionality using a file with 10000 pseudorandomly generated private keys.

* Fixed issues with nested `bitcore-lib` packages that would cause the build to fail with NPM3
