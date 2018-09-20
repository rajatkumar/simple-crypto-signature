const fs = require('fs');
const crypto = require('crypto');
const SIGN_ALGO = 'sha256';
const SIGN_FORMAT = 'base64';
const UTF8 = 'utf-8';

/**
 * Class representing SimpleCryptoSignature libary.
 * @public
 * @param {Object} options, Options to configure SimpleCryptoSignature
 * @param {String} options.privateKeyPath, Path to private key, used for signing
 * @param {String} options.publicKeyPath, Path to public key, used for verifying
 * @param {String} options.privateKey, You can also pass the private key string value instead of private key path
 * @param {String} options.publicKey, You can also pass the public key string value instead of public key path
 * @param {String} options.passPhrase, The pass phrase used for the private key, if not passed it assumes the private key does not use a pass phrase
 * @param {String} options.signatureFormat, The output of signature format - `hex` | `base64`(default)
 * @param {String} options.signatureAlgorithm, Algo to use to sign the payload  - `sha256` (default) | `md5` | `DSA` ... see `crypto.getHashes()` for all the algorithms supported by NodeJS crypto library
 * @example
 * const defaultOptions = {
 *   privateKeyPath: path.join(__dirname, 'private.pem'),
 *   publicKeyPath: path.join(__dirname, 'public.pem'),
 *   passPhrase: 'secret-passphrase-done-right'
 * };
 * const signatureGenerator = new SimpleCryptoSignature(defaultOptions);
 */
class SimpleCryptoSignature {
    constructor({
        privateKeyPath = null,
        publicKeyPath = null,
        privateKey,
        publicKey,
        passPhrase,
        signatureFormat = SIGN_FORMAT,
        signatureAlgorithm = SIGN_ALGO
    }) {
        this.privateKeyPath = privateKeyPath || null;
        this.publicKeyPath = publicKeyPath || null;
        this.passPhrase = passPhrase;
        this.signatureFormat = signatureFormat;
        this.signatureAlgorithm = signatureAlgorithm;
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
    /**
     * This function creates a signature for the hash of the input 'messageString' payload
     * using the private key and the hashing algorithm specified at the time of creation of
     * SimpleCryptoSignature instance object.
     * This also handles any error without you explicitly writing a try/catch
     * block
     * @public
     * @param {String} messageString the input string
     * @param {safeSignCallback} done the callback function that handles error or signed value
     * @returns {String} signature in the format specified
     * @example
     * const message = 'test-this-the-payload-that-needs-to-be-signed';
     * let signedValue;
     * signatureGenerator.sign(message, function(err, sign){
     *      if(!err) {
     *          signedValue = sign
     *      }
     * });
     * console.log(signedValue);
     */
    safeSign(messageString, done) {
        try {
            const sign = this.sign(messageString);
            return done(null, sign);
        } catch (err) {
            return done(err);
        }
    }
    /**
     * @callback safeSignCallback
     * @param {Error} error, the acual error thrown while creating a signature
     * @param {String} SignatureString, signature in the format specified
     */

    /**
     * This function creates a signature for the hash of the input 'messageString' payload
     * using the private key and the hashing algorithm specified at the time of creation of
     * SimpleCryptoSignature instance object.
     * Note: If signing fails, it will throw an Error. Always use a try/catch
     * block.
     * @public
     * @param {String} messageString the input string
     * @returns {String} signature in the format specified
     * @example
     * const message = 'test-this-the-payload-that-needs-to-be-signed';
     * let signedValue;
     * try {
     *      signedValue = signatureGenerator.sign(message);
     * }
     * catch(err) {
     *      // remember to handle error here
     * }
     * console.log(signedValue);
     */
    sign(messageString) {
        const signer = crypto.createSign(this.signatureAlgorithm);
        signer.update(messageString);
        const signature = signer.sign({
            key: this.privateKey,
            passphrase: this.passPhrase
        });
        return signature.toString(this.signatureFormat);
    }

    /**
     * This function can be used to verify if the signature ('signatureStirngHex')
     * is valid for the given input 'messageString' payload. This uses the Public
     * key and algorithm specified at the time of creation of
     * SimpleCryptoSignature instance object
     * @param {String} messageString, the actual payload string that was signed
     * @param {String} signatureStringHex, the signature that needs to be verified
     * @param {safeVerifyCallback} done the callback function that handles error or signed value
     * @returns {boolean}
     * @example
     * const message = 'test-this-string';
     * signatureGenerator = new SimpleCryptoSignature(defaultOptions);
     * const signedValue = signatureGenerator.sign(message);
     * signatureGenerator.safeVerify(message, signedValue, function(err, isVerified){
     *      if(!err) {
     *          verifiedValue = isVerified;
     *      }
     * });
     * expect(verifiedValue).toEqual(true);
     */
    safeVerify(messageString, signatureStringHex, done) {
        try {
            const isVerified = this.verify(messageString, signatureStringHex);
            return done(null, isVerified);
        } catch (err) {
            return done(err);
        }
    }
    /**
     * @callback safeVerifyCallback
     * @param {Error} error, the acual error thrown while verifying a signature
     * @param {boolean} isVerified, if the signature is verified
     */

    /**
     * This function can be used to verify if the signature ('signatureStirngHex')
     * is valid for the given input 'messageString' payload. This uses the Public
     * key and algorithm specified at the time of creation of
     * SimpleCryptoSignature instance object
     * Note: If verify fails, it might throw an Error. Always use a try/catch
     * block.
     * @param {String} messageString, the actual payload string that was signed
     * @param {String} signatureStringHex, the signature that needs to be verified
     * @returns {boolean}
     * @example
     * const message = 'test-this-string';
     * signatureGenerator = new SimpleCryptoSignature(defaultOptions);
     * const signedValue = signatureGenerator.sign(message);
     * let verifiedValue;
     * try {
     *      verifiedValue = signatureGenerator.verify(message, signedValue);
     * }
     * catch(err){
     *      // remember to handle error
     * }
     * expect(verifiedValue).toEqual(true);
     */
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
