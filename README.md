# solana-crypto

Cryptography for Solana

```
npm i solana-crypto
```

## Usage

```js
const crypto = require('solana-crypto')

const keyPair = new crypto.Keypair(seed)
// => keyPair.publicKey // PublicKey
// => keyPair.secretKey // Uint8Array
```

## API

#### `keyPair = new crypto.Keypair([seed])`

Generates or re-create a key pair from a seed.

Seed can be a String (base58), Buffer, or Uint8Array.

Seed can have both secret and public key or just the secret key.

Returns:

```js
{
  publicKey, // PublicKey instance
  secretKey // Uint8Array
}
```

#### `validated = crypto.validateKeyPair(keyPair)`

Checks if the secret key aligns with the provided public key.

#### `isOnCurve = crypto.isOnCurve(publicKey)`

Check if the address can have or not a secret key.

#### `hash = crypto.hash(buffer)`

Returns a Buffer with a SHA-256 hash.

#### `signature = crypto.sign(message, secretKey)`

Sign a message with a secret key.

#### `verified = crypto.verify(signature, message, publicKey)`

Check if the signature was signed by the public key.

## License

MIT
