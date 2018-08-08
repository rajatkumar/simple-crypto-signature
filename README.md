[![Build Status](https://travis-ci.org/rajatkumar/simple-crypto-signature.svg?branch=master)](https://travis-ci.org/rajatkumar/simple-crypto-signature)

[![Coverage Status](https://coveralls.io/repos/github/rajatkumar/simple-crypto-signature/badge.svg?branch=master)](https://coveralls.io/github/rajatkumar/simple-crypto-signature?branch=master)

[![Dependency Status](https://david-dm.org/rajatkumar/simple-crypto-signature.svg)](https://david-dm.org/rajatkumar/simple-crypto-signature)
[![devDependencies Status](https://david-dm.org/rajatkumar/simple-crypto-signature/dev-status.svg)](https://david-dm.org/rajatkumar/simple-crypto-signature?type=dev)

# simple-crypto-signature

> A simple abstraction to sign and verify string payloads using NodeJS

## Getting Started

Install the module with: `npm install simple-crypto-signature`

## Usage

Require the library and pass the options to the constructor:

```js
// require the library
const SimpleCryptoSignature = require('simple-crypto-signature');
// pass simple options
const defaultOptions = {
  privateKeyPath: path.join(__dirname, 'private.pem'),
  publicKeyPath: path.join(__dirname, 'public.pem'),
  passPhrase: '<your_pass_phrase>'
};
const signatureGenerator = new SimpleCryptoSignature(defaultOptions);
```

Sign the payload:

```js
// payload to sign
const message = 'test-this-string';

// `signedValue` is the payload signed using your private key
const signedValue = signatureGenerator.sign(message);
```

Verify the signed value:

```js
// You can verify the `signedValue`
const verifiedValue = signatureGenerator.verify(message, signedValue);
// verifiedValue will be either `true` or `false`
```

### API

`SimpleCryptoSignature` class takes the following options as part of its constructor:

```js
{
  privateKeyPath, // Path to private key , used for signing {String}
    publicKeyPath, // Path to public key , used for verifying {String}
    privateKey, // You can also pass the private key string value instead of private key path {String}
    publicKey, // You can also pass the public key string value instead of public key path {String}
    passPhrase, // The pass phrase used for the private key, if not passed it assumes the private key does not use a pass phrase {String}
    signatureFormat, // The output of signature format - `hex` | `base64`(default) {String}
    signatureAlgorithm; // Algo to use to sign the payload  - `sha256` (default) | `md5` | `DSA` ... see `crypto.getHashes()` for all the algorithms supported by NodeJS crypto library
}
```

## Generating 2048 bit RSA Keys (with passphrase)

### Private Key

The following command will generate a `private.pem` file that contains your private
key.

> The command will prompt you for a `pass phrase` and this `pass phrase` is
> required for generating the public key as well.

```bash
openssl genrsa -des3 -out private.pem 2048
```

### Public Key

To generate the public key for your private key use the following command and
provide the `pass phrase` you used while generating the private key

```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

## Generating 2048 bit RSA Keys (without passphrase)

### Private Key

The following command will generate a `private.pem` file that contains your private
key.

```bash
openssl genrsa -out private.pem 2048
```

### Public Key

To generate the public key for your private key use the following command

```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

## License

Copyright (c) 2018 Rajat Kumar

Licensed under the MIT license.
