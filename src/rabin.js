'use strict'

const crypto = require('crypto')

// Rabin signatures — how an ORACLE signs arbitrary data that a Bitcoin covenant
// can verify. ECDSA is out: OP_CHECKSIG only checks a signature against the
// spending transaction's sighash, never against a free message. Rabin needs no
// special opcode — verification is `s² mod N == H(m ‖ pad) mod N`, pure modular
// arithmetic that Script does with OP_MUL and OP_MOD.
//
// The oracle's public key is a modulus N = p·q with p, q ≡ 3 (mod 4). Signing a
// message needs the factorisation (to take a modular square root); verifying needs
// only N, which the covenant hard-codes. This is the standard construction sCrypt
// and the BSV oracle ecosystem use.
//
// Everything is little-endian, to match Script's native OP_BIN2NUM/OP_NUM2BIN, and
// a trailing 0x00 keeps every number positive under Script's signed encoding.

const KEY_BYTES = 64                    // 512-bit modulus: demo-sized, keeps the script small

function toBN (bytesLE) {
  let x = 0n
  for (let i = bytesLE.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(bytesLE[i])
  return x
}
function toBytesLE (x, width) {
  const b = Buffer.alloc(width)
  for (let i = 0; i < width && x > 0n; i++) { b[i] = Number(x & 0xffn); x >>= 8n }
  return b
}
/** The minimal little-endian encoding of a positive number, 0x00-padded so its top
 *  bit is clear — i.e. what OP_BIN2NUM reads back as this exact positive value. */
function toScriptNum (x) {
  let b = toBytesLE(x, Math.ceil((x.toString(2).length + 1) / 8) || 1)
  if (b.length === 0) b = Buffer.from([0])
  if (b[b.length - 1] & 0x80) b = Buffer.concat([b, Buffer.from([0])])
  return b
}

function powmod (base, exp, mod) {
  base %= mod; let r = 1n
  while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; base = (base * base) % mod; exp >>= 1n }
  return r
}
function egcd (a, b) { if (b === 0n) return [a, 1n, 0n]; const [g, x, y] = egcd(b, a % b); return [g, y, x - (a / b) * y] }
function invmod (a, m) { const [, x] = egcd(((a % m) + m) % m, m); return ((x % m) + m) % m }

/** A uniform BigInt in [0, m), from crypto bytes — not Math.random(). */
function randBelow (m) {
  const bytes = Math.ceil(m.toString(2).length / 8) + 1
  return toBN(crypto.randomBytes(bytes)) % m
}

function isProbablePrime (nBig) {
  if (nBig < 2n) return false
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (nBig % p === 0n) return nBig === p
  }
  let d = nBig - 1n, r = 0n
  while (d % 2n === 0n) { d /= 2n; r++ }
  for (let i = 0; i < 20; i++) {
    // Witnesses must span [2, n-2] and be unpredictable. A Math.random() value
    // bounded to ~1e9 is neither for a 256-bit candidate — every witness lands
    // in the same tiny range, materially weakening the test for a real key.
    const a = 2n + randBelow(nBig - 3n)
    let x = powmod(a, d, nBig)
    if (x === 1n || x === nBig - 1n) continue
    let ok = false
    for (let j = 0n; j < r - 1n; j++) { x = (x * x) % nBig; if (x === nBig - 1n) { ok = true; break } }
    if (!ok) return false
  }
  return true
}
/** A random prime ≡ 3 (mod 4) of about `bytes` bytes. */
function randomPrime34 (bytes) {
  for (;;) {
    let x = toBN(crypto.randomBytes(bytes))
    x |= 1n << BigInt(bytes * 8 - 1)          // top bit set
    x = (x - (x % 4n)) + 3n                    // ≡ 3 (mod 4)
    if (isProbablePrime(x)) return x
  }
}

/** The expanded hash of a message: four SHA256 blocks concatenated, as a number. */
function rabinHash (msg) {
  const blocks = []
  for (let i = 1; i <= 4; i++) blocks.push(crypto.createHash('sha256').update(Buffer.concat([msg, Buffer.from([i])])).digest())
  return Buffer.concat(blocks)   // 128 bytes, little-endian-interpreted downstream
}

function keygen () {
  const p = randomPrime34(KEY_BYTES / 2)
  const q = randomPrime34(KEY_BYTES / 2)
  return { p, q, n: p * q }
}

/** Sign a message: find a padding nonce making the hash a quadratic residue, take
 *  its square root via CRT. Returns { sig (Buffer), padding (number) }. */
function sign (msg, key) {
  const { p, q, n } = key
  // The padding is carried on the wire in 2 bytes (padBytes), so it must fit in
  // 16 bits or a larger value would alias a smaller one; a quadratic residue
  // turns up in a handful of tries, so this cap is never reached in practice.
  for (let pad = 0; pad < 0x10000; pad++) {
    const h = toBN(rabinHash(Buffer.concat([msg, Buffer.from([pad & 0xff, (pad >> 8) & 0xff])]))) % n
    if (powmod(h, (p - 1n) / 2n, p) === 1n && powmod(h, (q - 1n) / 2n, q) === 1n) {
      const sp = powmod(h, (p + 1n) / 4n, p)
      const sq = powmod(h, (q + 1n) / 4n, q)
      const s = (sp * q * invmod(q, p) + sq * p * invmod(p, q)) % n
      return { sig: toScriptNum(s), padding: pad }
    }
  }
  throw new Error('rabin: no quadratic residue found')
}

/** Verify in JS (the covenant does the same with OP_MUL/OP_MOD). */
function verify (msg, sig, padding, n) {
  const s = toBN(sig)
  const h = toBN(rabinHash(Buffer.concat([msg, Buffer.from([padding & 0xff, (padding >> 8) & 0xff])]))) % n
  return (s * s) % n === h
}

module.exports = { KEY_BYTES, keygen, sign, verify, rabinHash, toBN, toBytesLE, toScriptNum, powmod }
