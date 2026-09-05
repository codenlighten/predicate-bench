'use strict'

const bsv = require('@smartledger/bsv')

// STATE FIELD LAYOUT — how a `@state` field declaration in a `@contract` class encodes to
// the bytes carried inside the locking script. The point is that the compiler, not the
// developer, owns the state's offsets and push-encoding: a class declares
//
//     owner: hash160
//     balance: u64
//
// and the frontend concatenates the encoded fields, in declaration order, into the exact
// state buffer the predicate expects. Each type below is byte-identical to the predicates'
// own hand-written encoders — in particular `u64` mirrors `balanceLE`: an 8-byte little-
// endian field whose magnitude is written in 6 bytes (the satoshi-safe range), so the top
// two bytes are always zero. Fixed width is load-bearing (pitfall 21): every type is a
// fixed number of bytes, so the covenant's byte offsets never move.

// an unsigned little-endian integer: `width` bytes wide, magnitude written in `mag` bytes.
const uint = (width, mag) => (v) => {
  if (Buffer.isBuffer(v)) {
    if (v.length !== width) throw new Error(`must be ${width} bytes`)
    return v
  }
  const num = Number(v)
  if (!Number.isInteger(num) || num < 0 || num > 2 ** (8 * mag) - 1) {
    throw new Error(`value ${v} is out of range for a ${mag}-byte magnitude (0 .. ${2 ** (8 * mag) - 1})`)
  }
  const b = Buffer.alloc(width)
  b.writeUIntLE(num, 0, mag)
  return b
}

// exactly `width` raw bytes, from a Buffer or a hex string.
const rawBytes = (width) => (v) => {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(String(v), 'hex')
  if (b.length !== width) throw new Error(`must be ${width} bytes, got ${b.length}`)
  return b
}

// a 20-byte HASH160: a base58 address, a 40-char hex string, or a 20-byte Buffer.
const hash160 = (v) => {
  if (Buffer.isBuffer(v)) {
    if (v.length !== 20) throw new Error('must be 20 bytes')
    return v
  }
  if (typeof v === 'string' && /^[0-9a-fA-F]{40}$/.test(v)) return Buffer.from(v, 'hex')
  return bsv.Address.fromString(v).hashBuffer
}

const TYPES = {
  u8: { width: 1, enc: uint(1, 1) },
  u16: { width: 2, enc: uint(2, 2) },
  u32: { width: 4, enc: uint(4, 4) },
  u64: { width: 8, enc: uint(8, 6) },          // = balanceLE: 6-byte magnitude in an 8-byte field
  hash160: { width: 20, enc: hash160 },
  hash256: { width: 32, enc: rawBytes(32) },
  bytes32: { width: 32, enc: rawBytes(32) },
  bytes36: { width: 36, enc: rawBytes(36) },   // an outpoint: reverse(txid)‖vout
  outpoint: { width: 36, enc: rawBytes(36) }
}

// resolve a declared type name to { width, enc }, including the `bytes<N>` family.
function typeOf (name) {
  if (TYPES[name]) return TYPES[name]
  const m = name.match(/^bytes(\d+)$/)
  if (m) return { width: Number(m[1]), enc: rawBytes(Number(m[1])) }
  throw new Error(`state-layout: unknown field type '${name}' (have ${Object.keys(TYPES).join(', ')}, bytes<N>)`)
}

/** The declared state width in bytes — the sum of the fields' fixed widths. */
function width (fields) { return fields.reduce((n, f) => n + typeOf(f.type).width, 0) }

/** Encode a field layout into the state buffer, reading each field's value from `params` by name. */
function encodeState (fields, params) {
  return Buffer.concat(fields.map((f) => {
    if (!(f.name in params)) throw new Error(`state-layout: no value for field '${f.name}: ${f.type}'`)
    try { return typeOf(f.type).enc(params[f.name]) } catch (e) {
      throw new Error(`state-layout: field '${f.name}: ${f.type}' — ${e.message}`)
    }
  }))
}

module.exports = { TYPES, typeOf, width, encodeState }
