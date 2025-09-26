const { ed25519 } = require('@noble/curves/ed25519.js')
const { sha256 } = require('@noble/hashes/sha256')
const PublicKey = require('solana-public-key')
const bs58 = maybeDefaultModule(require('bs58'))

exports.keyPair = function (seed) {
  if (seed instanceof Uint8Array) seed = Buffer.from(seed)
  if (seed && typeof seed === 'string') seed = Buffer.from(bs58.decode(seed))

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

  return Buffer.from(sha256(buffer))
}

exports.sign = function (message, secretKey) {
  if (Buffer.isBuffer(secretKey)) {
    secretKey = new Uint8Array(secretKey)
  }

  const signature = ed25519.sign(message, secretKey.slice(0, 32))

  return Buffer.from(signature)
}

exports.verify = function (signature, message, publicKey) {
  if (Buffer.isBuffer(publicKey)) {
    publicKey = new Uint8Array(publicKey)
  }

  return ed25519.verify(signature, message, publicKey)
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

function maybeDefaultModule (mod) {
  return mod.default ? mod.default : mod
}
