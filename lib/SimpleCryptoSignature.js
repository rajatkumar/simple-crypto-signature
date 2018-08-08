const fs = require('fs');
const crypto = require('crypto');
const SIGN_ALGO = 'sha256';
const SIGN_FORMAT = 'base64';
const UTF8 = 'utf-8';
class SimpleCryptoSignature {
  constructor({
    privateKeyPath, // Path to private key , used for signing {String}
    publicKeyPath, // Path to public key , used for verifying {String}
    privateKey, // You can also pass the private key string value instead of private key path {String}
    publicKey, // You can also pass the public key string value instead of public key path {String}
    passPhrase, // The pass phrase used for the private key, if not passed it assumes the private key does not use a pass phrase {String}
    signatureFormat, // The output of signature format - `hex` | `base64`(default) {String}
    signatureAlgorithm // Algo to use to sign the payload  - `sha256` (default) | `md5` | `DSA` ... see `crypto.getHashes()` for all the algorithms supported by NodeJS crypto library
  }) {
    this.privateKeyPath = privateKeyPath || null;
    this.publicKeyPath = publicKeyPath || null;
    this.passPhrase = passPhrase;
    this.signatureFormat = signatureFormat || SIGN_FORMAT;
    this.signatureAlgorithm = signatureAlgorithm || SIGN_ALGO;
    if (privateKey) {
      this.privateKey = privateKey;
    } else if (privateKeyPath) {
      this.privateKey = fs.readFileSync(this.privateKeyPath, UTF8);
    }
    if (publicKey) {
      this.publicKey = publicKey;
    } else if (publicKeyPath) {
      this.publicKey = fs.readFileSync(this.publicKeyPath, UTF8);
    }
  }

  sign(messageString) {
    const signer = crypto.createSign(this.signatureAlgorithm);
    signer.update(messageString);
    const signature = signer.sign({
      key: this.privateKey,
      passphrase: this.passPhrase
    });
    return signature.toString(this.signatureFormat);
  }

  verify(messageString, signatureStringHex) {
    const verifier = crypto.createVerify(this.signatureAlgorithm);
    verifier.update(messageString);
    const verified = verifier.verify(
      this.publicKey,
      signatureStringHex,
      this.signatureFormat
    );
    return verified;
  }
}

module.exports = SimpleCryptoSignature;
