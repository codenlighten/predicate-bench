'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A covenant carrying a RECORD, not a field.
//
// `titled` splices one value. Once a script carries several, hand-counted byte
// positions stop being viable — every offset depends on the widths before it,
// and an offset that is wrong by one produces a successor that hashes to
// nothing. A coin that silently cannot be spent, with no error to read.
//
// So the schema is the source of truth. It generates the offsets, the splitting
// sequence in script, the reassembly order, and the JS encoder and decoder. No
// number below is written by hand; change a width and everything follows.
//
// The record demonstrates four different mutation rules in one script, because
// that is what a real record needs:
//
//   owner        20B  REPLACE    the spender supplies it
//   edition       4B  KEEP       immutable for the life of the coin
//   transfers     4B  INCREMENT  computed by the script, +1 exactly
//   maxTransfers  4B  KEEP+GUARD immutable, and transfers < it is enforced
//
// maxTransfers living in the RECORD rather than in the logic is the difference
// from `metered`: the limit is data, so one script serves every limit, and the
// limit is readable by anyone holding the UTXO.
const SCHEMA = [
  { name: 'owner', bytes: 20, rule: 'replace' },
  { name: 'edition', bytes: 4, rule: 'keep' },
  { name: 'transfers', bytes: 4, rule: 'increment' },
  { name: 'maxTransfers', bytes: 4, rule: 'keep' }
]

// A numeric field is read back with Buffer.writeUIntLE/readUIntLE, which top
// out at 6 bytes — and 6 bytes (2^48) is already well inside JS's safe-integer
// range, so the cap is not worth fighting. Checked here, at the schema, rather
// than left to surface as an ERR_OUT_OF_RANGE from deep inside the encoder
// with nothing to say about which field was wrong.
const MAX_NUMERIC_BYTES = 6

for (const f of SCHEMA) {
  if (!Number.isInteger(f.bytes) || f.bytes < 1) {
    throw new Error(`schema: ${f.name} needs a positive byte width`)
  }
  if (f.name !== 'owner' && f.bytes > MAX_NUMERIC_BYTES) {
    throw new Error(
      `schema: ${f.name} is ${f.bytes} bytes; numeric fields are limited to ` +
      `${MAX_NUMERIC_BYTES} (Buffer.writeUIntLE), which is already past 2^48`)
  }
}

const RECORD_BYTES = SCHEMA.reduce((sum, f) => sum + f.bytes, 0)
const VARINT_BYTES = 3                 // scripts of 253..65535
const HEAD_BYTES = VARINT_BYTES + 1    // varint + the record's push opcode

// Offsets derived, never written down.
const OFFSETS = (() => {
  let at = 0
  return Object.fromEntries(SCHEMA.map(f => {
    const entry = [f.name, { at, bytes: f.bytes }]
    at += f.bytes
    return entry
  }))
})()

// Shared covenant primitives — one implementation, in src/clauses.js.
const selfChunk = C.selfChunk
const newValueLE = C.newValueLE
const requireOutputIs = C.requireOutputIs
const hash160Of = C.hash160Of
const fieldFromChunk = (s, name) => C.fieldFromChunk(s, HEAD_BYTES + OFFSETS[name].at, OFFSETS[name].bytes)

const P2PKH_PREFIX = Buffer.from('1976a914', 'hex')
const P2PKH_SUFFIX = Buffer.from('88ac', 'hex')


/** Encode a record from named values, in schema order. */
function encodeRecord (values) {
  return Buffer.concat(SCHEMA.map(f => {
    if (f.name === 'owner') return hash160Of(values.owner)
    const v = values[f.name]
    if (!Number.isInteger(v) || v < 0) throw new Error(`${f.name} must be a non-negative integer`)
    if (v > Math.pow(2, 8 * f.bytes) - 1) {
      throw new Error(`${f.name}=${v} does not fit in ${f.bytes} bytes`)
    }
    const b = Buffer.alloc(f.bytes)
    b.writeUIntLE(v, 0, f.bytes)
    return b
  }))
}

/** Decode a record back out — from a raw record, or from a whole locking script. */
function decodeRecord (input) {
  const buf = Buffer.isBuffer(input) ? input : input.toBuffer()
  // A locking script starts with the push opcode for the record.
  const rec = buf.length === RECORD_BYTES ? buf : buf.slice(1, 1 + RECORD_BYTES)
  const out = {}
  for (const f of SCHEMA) {
    const slice = rec.slice(OFFSETS[f.name].at, OFFSETS[f.name].at + f.bytes)
    out[f.name] = f.name === 'owner'
      ? bsv.Address.fromPublicKeyHash(slice).toString()
      : slice.readUIntLE(0, f.bytes)
  }
  return out
}

/** Read a 4-byte LE field as an unsigned script number. */
function toNumber (s) {
  return s.add(Buffer.from([0])).add(Opcode.OP_CAT).add(Opcode.OP_BIN2NUM)
}





/**
 * Split the record into its fields and rebuild it with the schema's rules
 * applied, leaving the successor's `scriptlen||script` on the stack.
 *
 * in:  [newOwner, preimage, chunk]
 * out: [newOwner, preimage, nextChunk]   (newOwner consumed)
 *
 * Fields are pushed to the altstack as they are finished. Because the altstack
 * is LIFO and the fields are processed last-to-first, popping them back
 * reassembles the record in schema order — the ordering falls out of the
 * traversal rather than being maintained by hand.
 */
function rewriteRecord (s) {
  s.add(n(HEAD_BYTES)).add(Opcode.OP_SPLIT)          // [.., head, rest]
  s.add(n(RECORD_BYTES)).add(Opcode.OP_SPLIT)        // [.., head, record, tail]
  s.add(Opcode.OP_TOALTSTACK)                        // park the tail

  // record -> one stack item per field, in schema order
  for (let i = 0; i < SCHEMA.length - 1; i++) {
    s.add(n(SCHEMA[i].bytes)).add(Opcode.OP_SPLIT)
  }
  // stack: [.., head, owner, edition, transfers, maxTransfers]

  for (let i = SCHEMA.length - 1; i >= 0; i--) {
    const f = SCHEMA[i]
    if (f.rule === 'keep' && f.name === 'maxTransfers') {
      // Keep it, and hold a numeric copy to bound the increment below.
      s.add(Opcode.OP_DUP).add(Opcode.OP_TOALTSTACK)
      toNumber(s)                                    // [.., transfers, maxNum]
      s.add(Opcode.OP_SWAP)                          // [.., maxNum, transfers]
    } else if (f.rule === 'increment') {
      toNumber(s)                                    // [.., maxNum, transNum]
      // transfers < maxTransfers, or the coin has been handed on enough times.
      s.add(Opcode.OP_DUP).add(n(2)).add(Opcode.OP_PICK)
      s.add(Opcode.OP_LESSTHAN).add(Opcode.OP_VERIFY)
      s.add(Opcode.OP_1ADD).add(n(f.bytes)).add(Opcode.OP_NUM2BIN)
      s.add(Opcode.OP_TOALTSTACK)
      s.add(Opcode.OP_DROP)                          // the spare maxNum
    } else if (f.rule === 'keep') {
      s.add(Opcode.OP_TOALTSTACK)
    } else if (f.rule === 'replace') {
      s.add(Opcode.OP_DROP)                          // the old value goes
    }
  }
  // stack: [newOwner, preimage, head]

  s.add(Opcode.OP_ROT)                               // [preimage, head, newOwner]
  s.add(Opcode.OP_SIZE).add(n(OFFSETS.owner.bytes)).add(Opcode.OP_EQUALVERIFY)
  s.add(Opcode.OP_CAT)
  // pop the finished fields back: schema order, then the tail
  for (let i = 0; i < SCHEMA.length; i++) {
    s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)
  }
  return s
}

function buildScript ({ record, transferFee }) {
  const s = new Script()
  s.add(encodeRecord(record)).add(Opcode.OP_DROP)
  // One OP_PUSH_TX preamble above the split, not one per branch.
  C.authenticateThenBranch(s)

  // ---------------- transfer ----------------
  // in: [newOwner, sig, pubkey, preimage]

  selfChunk(s)
  fieldFromChunk(s, 'owner')
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_TOALTSTACK)
  s.add(Opcode.OP_TOALTSTACK)
  s.add(Opcode.OP_CHECKSIGVERIFY)
  s.add(Opcode.OP_FROMALTSTACK)
  s.add(Opcode.OP_FROMALTSTACK)                      // [newOwner, preimage, chunk]

  rewriteRecord(s)                                   // [preimage, nextChunk]

  s.add(Opcode.OP_TOALTSTACK)
  s.add(Opcode.OP_DUP)
  newValueLE(s, transferFee)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)
  requireOutputIs(s)

  s.add(Opcode.OP_ELSE)

  // ---------------- redeem ----------------
  // in: [sig, pubkey, preimage]

  selfChunk(s)
  fieldFromChunk(s, 'owner')
  s.add(Opcode.OP_DUP).add(Opcode.OP_TOALTSTACK)
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_DROP)
  s.add(Opcode.OP_TOALTSTACK)
  s.add(Opcode.OP_CHECKSIGVERIFY)
  s.add(Opcode.OP_FROMALTSTACK)

  s.add(Opcode.OP_DUP)
  newValueLE(s, transferFee)
  s.add(P2PKH_PREFIX).add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)
  s.add(P2PKH_SUFFIX).add(Opcode.OP_CAT)
  requireOutputIs(s)

  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// Fixed addresses so a documented byte count is reproducible rather than
// dependent on whichever key happened to be generated.
const EXAMPLE_ADDRESS = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'
const EXAMPLE_ADDRESS_2 = '18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if'

module.exports = {
  name: 'registry',
  describe: 'a covenant carrying a multi-field record: replace, keep, increment and guard in one script',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ record: { owner: EXAMPLE_ADDRESS, edition: 1, transfers: 0, maxTransfers: 2 }, transferFee: 400 }),

  SCHEMA, OFFSETS, RECORD_BYTES,
  buildScript, encodeRecord, decodeRecord,

  lock ({ record, transferFee }) {
    if (!record) throw new Error('record is required')
    if (!Number.isInteger(transferFee) || transferFee <= 0) {
      throw new Error('transferFee must be a positive integer')
    }
    return buildScript({ record, transferFee })
  },

  outputs ({ record, newOwner, transferFee, satoshis, branch = 'transfer',
             actualScript, actualAmount, actualRecord }) {
    const next = actualRecord || {
      ...record, owner: newOwner, transfers: record.transfers + 1
    }
    const script = actualScript || (branch === 'redeem'
      ? bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(hash160Of(record.owner)))
      : buildScript({ record: next, transferFee }))
    return [new bsv.Transaction.Output({
      script, satoshis: actualAmount ?? (satoshis - transferFee)
    })]
  },

  continuation ({ record, newOwner, transferFee, branch = 'transfer' }) {
    if (branch === 'redeem') return null
    const next = { ...record, owner: newOwner, transfers: record.transfers + 1 }
    return {
      script: buildScript({ record: next, transferFee }),
      params: { record: { ...next, owner: bsv.Address.fromPublicKeyHash(hash160Of(newOwner)).toString() }, transferFee }
    }
  },

  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType, branch = 'transfer',
            ownerKey, ownerWif, key, newOwner, pushNewOwner, signWith }) {
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const signer = signWith || ownerKey ||
      (ownerWif ? bsv.PrivateKey.fromWIF(ownerWif) : null) || key
    if (!signer) throw new Error('no signing key')

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(
        tx, signer, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)
      ).toTxFormat()
      const s = new Script()
      if (branch !== 'redeem') s.add(hash160Of(pushNewOwner ?? newOwner))
      // The flag goes BELOW the preimage: the preimage must be on top for the
      // single hoisted OP_PUSH_TX, which then swaps the flag up for OP_IF.
      s.add(sig).add(signer.publicKey.toBuffer())
      s.add(branch === 'redeem' ? Opcode.OP_0 : Opcode.OP_1)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
