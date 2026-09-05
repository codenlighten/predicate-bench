'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A coin that can only be spent BESIDE a named companion.
//
// Every covenant so far reasons about its own spending transaction — its
// outputs, its value, its own script. This one reaches sideways: it enforces
// that some OTHER, specific input is present in the same transaction.
//
// The only window Script has onto sibling inputs is hashPrevouts (item 2 of the
// BIP-143 preimage): HASH256 of every input's outpoint, concatenated in order.
// A covenant cannot invert a hash, so it cannot read the set out — but the
// spender can PUSH the set, and the covenant checks it:
//
//   HASH256(prefix ‖ <companion> ‖ suffix) == hashPrevouts
//
// If that holds, the real input set genuinely contains <companion> at some
// position, because nothing else hashes to the transaction's true hashPrevouts.
// prefix and suffix are unverified and need no checking — a lie about them
// changes the hash and the spend dies.
//
// This is the honest primitive. It binds the IDENTITY and, optionally, the
// COUNT of the sibling inputs. What it deliberately does NOT do is read a
// sibling's VALUE or SCRIPT: those are in the sibling's preimage, not this
// one's, so "sum the input balances in-script" — the token-merge claim — does
// not follow from this alone. See docs/predicates.md#companion.
//
// Uses:
//   - atomic bonding: two coins that may only move together
//   - forced batching: a coin spendable only in a transaction of exactly N inputs
//   - a dead-man companion: release coin A only when companion B is also spent

/**
 * An outpoint as the 36 bytes hashPrevouts commits to: txid(internal) ‖ vout LE.
 *
 * The txid has to be REVERSED. bsv holds `prevTxId` in display order (the hex
 * you read on an explorer) and reverses it to internal little-endian when it
 * serialises the outpoint into the sighash. Miss this and everything still
 * *looks* right with a palindromic test txid — all-0x07, say — then fails the
 * moment a real txid is used. See docs/pitfalls.md#23.
 */
function outpoint36 (prevTxId, vout) {
  const txid = Buffer.from(Buffer.isBuffer(prevTxId) ? prevTxId : Buffer.from(prevTxId, 'hex'))
  txid.reverse()
  const idx = Buffer.alloc(4)
  idx.writeUInt32LE(vout, 0)
  return Buffer.concat([txid, idx])
}

function companionBytes (companion) {
  if (Buffer.isBuffer(companion)) return companion
  return outpoint36(companion.prevTxId, companion.outputIndex ?? companion.vout)
}

function buildScript ({ companion, groupSize }) {
  const comp = companionBytes(companion)
  if (comp.length !== 36) throw new Error('companion outpoint must be 36 bytes')

  const s = new Script()
  // in: [prefix, suffix, preimage]
  C.authenticate(s)                              // preimage proven; back to [prefix, suffix, preimage]

  C.hashPrevoutsFromFront(s)                     // [prefix, suffix, preimage, hashPrevouts]
  s.add(Opcode.OP_TOALTSTACK)                    // park hashPrevouts
  s.add(Opcode.OP_DROP)                          // [prefix, suffix]

  // Reassemble prefix ‖ companion ‖ suffix.
  s.add(Opcode.OP_SWAP)                          // [suffix, prefix]
  s.add(comp).add(Opcode.OP_CAT)                 // [suffix, prefix‖companion]
  s.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)       // [prefix‖companion‖suffix]

  // Optional: the whole input set is exactly `groupSize` outpoints. Without
  // this a spender may pad the transaction with extra inputs; with it the batch
  // size is fixed. Each outpoint is 36 bytes.
  if (groupSize) {
    s.add(Opcode.OP_SIZE).add(n(36 * groupSize)).add(Opcode.OP_EQUALVERIFY)
  }

  s.add(Opcode.OP_HASH256)                       // [digest]
  s.add(Opcode.OP_FROMALTSTACK)                  // [digest, hashPrevouts]
  return s.add(Opcode.OP_EQUAL)
}

// Fixed companion so a documented byte count is reproducible.
const EXAMPLE_COMPANION = {
  prevTxId: 'a'.repeat(64),
  outputIndex: 1
}

module.exports = {
  name: 'companion',
  describe: 'spendable only beside a named companion input',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ companion: EXAMPLE_COMPANION }),

  buildScript,
  outpoint36,

  lock ({ companion, groupSize }) {
    if (!companion) throw new Error('companion outpoint is required')
    return buildScript({ companion, groupSize })
  },

  /**
   * The sibling inputs this covenant must be spent beside. The harness adds
   * these after input 0, so hashPrevouts covers the real set. `extraSiblings`
   * lets a test add non-companion inputs — to pad the batch, or to place the
   * companion in the middle of the vector.
   */
  siblings ({ companion, wrongCompanion, extraSiblings }) {
    if (wrongCompanion) {
      // The attack: the transaction spends a DIFFERENT sibling than the one the
      // covenant demands. The unlock can only lie about it, and the hash bites.
      return [{ ...siblingFrom(wrongCompanion) }, ...(extraSiblings || [])]
    }
    return [siblingFrom(companion), ...(extraSiblings || [])]
  },

  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType, companion, claimAbsent }) {
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const comp = companionBytes(companion)

    // The real outpoint vector of the transaction being spent.
    const vector = Buffer.concat(tx.inputs.map(i => outpoint36(i.prevTxId, i.outputIndex)))

    // Split the vector around the companion. If it is genuinely present, this is
    // exact; if it is absent (the attack), fall back to a plausible-but-wrong
    // decomposition so the script runs and fails at the hash rather than here.
    let prefix, suffix
    const at = indexOfAligned(vector, comp, 36)
    if (at >= 0 && !claimAbsent) {
      prefix = vector.slice(0, at)
      suffix = vector.slice(at + 36)
    } else {
      prefix = vector.slice(0, 36)
      suffix = vector.slice(36)
    }

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const s = new Script()
      s.add(prefix.length ? prefix : Opcode.OP_0)
      s.add(suffix.length ? suffix : Opcode.OP_0)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}

/** A sibling input spec the harness understands, from a companion outpoint. */
function siblingFrom (companion) {
  if (Buffer.isBuffer(companion)) {
    return { prevTxId: companion.slice(0, 32), outputIndex: companion.readUInt32LE(32) }
  }
  return { prevTxId: companion.prevTxId, outputIndex: companion.outputIndex ?? companion.vout }
}

/** indexOf, but only at multiples of `stride` — an outpoint never straddles a boundary. */
function indexOfAligned (haystack, needle, stride) {
  for (let i = 0; i + needle.length <= haystack.length; i += stride) {
    if (haystack.slice(i, i + needle.length).equals(needle)) return i
  }
  return -1
}
