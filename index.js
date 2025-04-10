const crypto = require('crypto')
const { default: bs58 } = require('bs58')
const ed25519 = require('@noble/ed25519')
const PublicKey = require('solana-public-key')
const { sha512 } = require('@noble/hashes/sha512')

ed25519.etc.sha512Sync = sha512

exports.keyPair = function (seed) {
  if (seed && typeof seed === 'string') {
    seed = Buffer.from(bs58.decode(seed))
  }

  if (seed && seed.byteLength === 32) {
    const privateScalar = seed
    const publicKey = Buffer.from(ed25519.getPublicKey(privateScalar))
    const secretKey = Buffer.alloc(64)

    privateScalar.copy(secretKey, 0)
    publicKey.copy(secretKey, 32)

    return { publicKey, secretKey }
  }

  if (seed && seed.byteLength === 64) {
    const privateScalar = seed.slice(0, 32)
    const publicKey = seed.slice(32, 64)

    const computedPublicKey = ed25519.getPublicKey(privateScalar)

    for (let j = 0; j < 32; j++) {
      if (publicKey[j] !== computedPublicKey[j]) {
        throw new Error('Seed is invalid: Public key mismatch')
      }
    }

    return { publicKey, secretKey: seed }
  }

  if (seed) {
    throw new Error('Invalid seed')
  }

  const privateScalar = Buffer.from(ed25519.utils.randomPrivateKey())
  const publicKey = Buffer.from(ed25519.getPublicKey(privateScalar))
  const secretKey = Buffer.alloc(64)

  privateScalar.copy(secretKey, 0)
  publicKey.copy(secretKey, 32)

  return { publicKey, secretKey }
}

exports.validateKeyPair = function (keyPair) {
  const computedPublicKey = ed25519.getPublicKey(keyPair.secretKey)

  return computedPublicKey.equals(keyPair.publicKey)
}

exports.isOnCurve = function (publicKey) {
  try {
    ed25519.ExtendedPoint.fromHex(publicKey)

    return true
  } catch {
    return false
  }
}

exports.hash = function (buffer) {
  if (Array.isArray(buffer)) {
    buffer = Buffer.concat(buffer)
  }

  return crypto.createHash('sha256').update(buffer).digest()
}

// Backwards compat
exports.Keypair = class Keypair {
  constructor (seed) {
    this._keyPair = exports.keyPair(seed)
  }

  get publicKey () {
    return new PublicKey(this._keyPair.publicKey)
  }

  get secretKey () {
    return new Uint8Array(this._keyPair.secretKey)
  }
}
