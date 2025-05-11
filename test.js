const test = require('brittle')
const PublicKey = require('solana-public-key')
const crypto = require('./index.js')

test('generate key pair', function (t) {
  const a = crypto.keyPair()

  t.unlike(a.secretKey.slice(0, 32), Buffer.alloc(32)) // Not zeroes
  t.unlike(a.publicKey.slice(32), Buffer.alloc(32)) // Not zeroes

  t.ok(a.secretKey.slice(32).equals(a.publicKey))
})

test('64-byte secret key to key pair', function (t) {
  const a = crypto.keyPair()
  const b = crypto.keyPair(a.secretKey)

  t.alike(a.publicKey, b.publicKey)
  t.alike(a.secretKey, b.secretKey)
})

test('32-byte seed to key pair', function (t) {
  const a = crypto.keyPair()
  const b = crypto.keyPair(a.secretKey.slice(0, 32))

  t.alike(a.publicKey, b.publicKey)
  t.alike(a.secretKey, b.secretKey)
})

test('Keypair instance', function (t) {
  const a = crypto.keyPair()
  const b = new crypto.Keypair(a.secretKey)

  t.alike(a.publicKey, b.publicKey.toBuffer())
  t.alike(a.secretKey, Buffer.from(b.secretKey))

  t.ok(b.publicKey instanceof PublicKey)
  t.ok(b.secretKey instanceof Uint8Array)
})

test('hash', function (t) {
  const expected = Buffer.from('7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069', 'hex')

  t.alike(crypto.hash('Hello World!'), expected)
})
