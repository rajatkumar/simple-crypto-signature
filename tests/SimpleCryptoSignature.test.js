const path = require('path');
const fs = require('fs');
const SimpleCryptoSignature = require('../lib');
let signatureGenerator;

const defaultOptions = {
    privateKeyPath: path.join(__dirname, 'private.pem'),
    publicKeyPath: path.join(__dirname, 'public.pem'),
    passPhrase: 'rajat'
};

let globalSignedValue = '';
let globalMessage = '';

describe('SimpleCryptoSignature', () => {
    test('should sign the message', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValue = signatureGenerator.sign(message);
        expect(signedValue).toBeTruthy();
        globalSignedValue = signedValue;
        globalMessage = message;
    });

    test('should produce same signatures', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(message);
        expect(signedValueOne).toEqual(signedValueTwo);
    });

    test('should produce different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        expect(signedValueOne).not.toEqual(signedValueTwo);
    });

    test('should verify signature', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValue = signatureGenerator.sign(message);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        expect(verifiedValue).toEqual(true);
    });

    test('should verify different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValue = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        const verifiedValueTwo = signatureGenerator.verify(
            messageTwo,
            signedValueTwo
        );
        expect(verifiedValue).toEqual(true);
        expect(verifiedValueTwo).toEqual(true);
    });
});

describe('SimpleCryptoSignature with Safe Functions', () => {
    test('should sign the message', (done) => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        signatureGenerator.safeSign(message, function(err, signedValue) {
            expect(err).toBeNull();
            expect(signedValue).toBeTruthy();
            done();
        });
    });

    test('should produce same signatures', (done) => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        let signedValueOne, signedValueTwo;
        signatureGenerator.safeSign(message, function(err, value) {
            expect(err).toBeNull();
            signedValueOne = value;
            signatureGenerator.safeSign(message, function(err2, value2) {
                expect(err2).toBeNull();
                signedValueTwo = value2;
                expect(signedValueOne).toEqual(signedValueTwo);
                done();
            });
        });
    });

    test('should produce different signatures', (done) => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        let signedValueOne, signedValueTwo;
        signatureGenerator.safeSign(message, function(err, value) {
            expect(err).toBeNull();
            signedValueOne = value;
            signatureGenerator.safeSign(messageTwo, function(err2, value2) {
                expect(err2).toBeNull();
                signedValueTwo = value2;
                expect(signedValueOne).not.toEqual(signedValueTwo);
                done();
            });
        });
    });

    test('should verify signature', (done) => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValue = signatureGenerator.sign(message);
        signatureGenerator.safeVerify(message, signedValue, function(
            err,
            verifiedValue
        ) {
            expect(err).toBeNull();
            expect(verifiedValue).toEqual(true);
            done();
        });
    });

    test('should verify different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(defaultOptions);
        const signedValue = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);

        signatureGenerator.safeVerify(message, signedValue, function(
            err,
            verifiedValue
        ) {
            expect(err).toBeNull();
            expect(verifiedValue).toEqual(true);
            signatureGenerator.verify(messageTwo, signedValueTwo, function(
                err2,
                verifiedValueTwo
            ) {
                expect(err2).toBeNull();
                expect(verifiedValueTwo).toEqual(true);
            });
        });
    });
});

describe('SimpleCryptoSignature Formats', () => {
    test('should sign and verify hex', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureFormat: 'hex'
        });
        const signedValue = signatureGenerator.sign(message);
        // lets verify this is indeed hex
        const hexBuffer = Buffer.from(signedValue, 'hex');
        expect(hexBuffer.toString('hex')).toEqual(signedValue);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        expect(verifiedValue).toEqual(true);
    });
    test('should sign and verify base64', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureFormat: 'base64'
        });
        const signedValue = signatureGenerator.sign(message);
        // lets verify this is indeed base64
        const hexBuffer = Buffer.from(signedValue, 'base64');
        expect(hexBuffer.toString('base64')).toEqual(signedValue);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        expect(verifiedValue).toEqual(true);
    });
});

describe('SimpleCryptoSignature Negative Cases', () => {
    test('should throw error if no passphrase is provided', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            privateKeyPath: path.join(__dirname, 'private.pem'),
            publicKeyPath: path.join(__dirname, 'public.pem')
        });
        try {
            signatureGenerator.sign(message);
        } catch (error) {
            expect(error).toBeTruthy();
        }
    });
    test('should throw error if no passphrase is provided', (done) => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            privateKeyPath: path.join(__dirname, 'private.pem'),
            publicKeyPath: path.join(__dirname, 'public.pem')
        });
        signatureGenerator.safeSign(message, function(err, sign) {
            expect(err).toBeTruthy();
            expect(sign).toBeUndefined();
            done();
        });
    });
    test('should throw error if no public key is provided', (done) => {
        signatureGenerator = new SimpleCryptoSignature({
            privateKeyPath: path.join(__dirname, 'private.pem'),
            passPhrase: 'rajat'
        });
        signatureGenerator.safeVerify(
            globalMessage,
            globalSignedValue,
            function(err, data) {
                expect(err).toBeTruthy();
                expect(data).toBeUndefined();
                done();
            }
        );
    });
    test('should throw error if no private key is provided', (done) => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            publicKeyPath: path.join(__dirname, 'public.pem'),
            passPhrase: 'rajat'
        });
        signatureGenerator.safeSign(message, function(err, sign) {
            expect(err).toBeTruthy();
            expect(sign).toBeUndefined();
            done();
        });
    });
});

describe('SimpleCryptoSignature Without PassPhrase', () => {
    const modOpts = {
        privateKeyPath: path.join(__dirname, 'private.nopp.pem'),
        publicKeyPath: path.join(__dirname, 'public.nopp.pem')
    };
    test('should sign the message', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValue = signatureGenerator.sign(message);
        expect(signedValue).toBeTruthy();
    });

    test('should produce same signatures', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(message);
        expect(signedValueOne).toEqual(signedValueTwo);
    });

    test('should produce different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        expect(signedValueOne).not.toEqual(signedValueTwo);
    });

    test('should verify signature', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValue = signatureGenerator.sign(message);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        expect(verifiedValue).toEqual(true);
    });

    test('should verify different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValue = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        const verifiedValueTwo = signatureGenerator.verify(
            messageTwo,
            signedValueTwo
        );
        expect(verifiedValue).toEqual(true);
        expect(verifiedValueTwo).toEqual(true);
    });
});

describe('SimpleCryptoSignature Passing Keys', () => {
    const modOpts = {
        privateKey: fs.readFileSync(
            path.join(__dirname, 'private.nopp.pem'),
            'utf-8'
        ),
        publicKey: fs.readFileSync(
            path.join(__dirname, 'public.nopp.pem'),
            'utf-8'
        )
    };
    test('should sign the message', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValue = signatureGenerator.sign(message);
        expect(signedValue).toBeTruthy();
    });

    test('should produce same signatures', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(message);
        expect(signedValueOne).toEqual(signedValueTwo);
    });

    test('should produce different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        expect(signedValueOne).not.toEqual(signedValueTwo);
    });

    test('should verify signature', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValue = signatureGenerator.sign(message);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        expect(verifiedValue).toEqual(true);
    });

    test('should verify different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature(modOpts);
        const signedValue = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        const verifiedValueTwo = signatureGenerator.verify(
            messageTwo,
            signedValueTwo
        );
        expect(verifiedValue).toEqual(true);
        expect(verifiedValueTwo).toEqual(true);
    });
});

describe('SimpleCryptoSignature using different algorithms', () => {
    test('should sign the message', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureAlgorithm: 'sha512'
        });
        const signedValue = signatureGenerator.sign(message);
        expect(signedValue).toBeTruthy();
    });

    test('should produce same signatures', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureAlgorithm: 'sha512'
        });
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(message);
        expect(signedValueOne).toEqual(signedValueTwo);
    });

    test('should produce different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureAlgorithm: 'sha512'
        });
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        expect(signedValueOne).not.toEqual(signedValueTwo);
    });

    test('should produce different signatures for different algorithms', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureAlgorithm: 'sha512'
        });
        const signatureGeneratorTwo = new SimpleCryptoSignature({
            ...defaultOptions
        });
        const signedValueOne = signatureGenerator.sign(message);
        const signedValueTwo = signatureGeneratorTwo.sign(message);
        expect(signedValueOne).not.toEqual(signedValueTwo);
    });

    test('should verify signature', () => {
        const message = 'test-this-string';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureAlgorithm: 'sha512'
        });
        const signedValue = signatureGenerator.sign(message);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        expect(verifiedValue).toEqual(true);
    });

    test('should verify different signatures', () => {
        const message = 'test-this-string';
        const messageTwo = 'test-this-string-2';
        signatureGenerator = new SimpleCryptoSignature({
            ...defaultOptions,
            signatureAlgorithm: 'sha512'
        });
        const signedValue = signatureGenerator.sign(message);
        const signedValueTwo = signatureGenerator.sign(messageTwo);
        const verifiedValue = signatureGenerator.verify(message, signedValue);
        const verifiedValueTwo = signatureGenerator.verify(
            messageTwo,
            signedValueTwo
        );
        expect(verifiedValue).toEqual(true);
        expect(verifiedValueTwo).toEqual(true);
    });
});
