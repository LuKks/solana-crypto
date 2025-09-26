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

test('sign', function (t) {
  const signer = new crypto.Keypair('2VCtBqFU9eWRrqA5YCCFB2ChonwuNzYh6gRzkAy38Kr4fQZQc6oQwuYgUFU8Jyj5VrHcWpT1fBwGRftCCU75rGKU')

  t.is(signer.publicKey.toString(), 'GgEXGYxPPjHFxshU9Gcwcub4NNiak5GKHvVUubGFxDhU', 'signer is correct')

  const message = Buffer.from('01000203e8ec3ea2acef16d784bdb7a6a43ed5938b5801312838fb7b0307a7c4b87c7e3300000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000000e14e5b5e69c74a36db1ae5a711add49cc877890e3ad18cb3e8a50674c5b950902020009031027000000000000010200000c02000000440a020000000000', 'hex')

  const signature = crypto.sign(message, signer.secretKey)
  const expected = Buffer.from('9583856e01f0a4c001ac52444b121f002c95f603e2fdef8c034a6f0f459cda0a4c4db9fa83010ec7a3ff08210967986620061de6c9089e92b43d7fe0c4b8b60e', 'hex')

  t.alike(signature, expected, 'signature matches')

  t.ok(crypto.verify(signature, message, signer.publicKey.toBytes()), 'signature verified')
})
