'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { leanCore } = require('../pushtx')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// Offsets are measured from the END of the preimage, never from the start.
// scriptCode is variable-length, so every field before it moves; every field
// after it does not. A fixed head offset is wrong for all but one scriptCode.
const FROM_END_LOCKTIME = 8   //                            nLockTime(4) sighashType(4)
const FROM_END_SEQUENCE = 44  // nSequence(4) hashOutputs(32) nLockTime(4) sighashType(4)

const SEQUENCE_FINAL = Buffer.from('ffffffff', 'hex')

// Take `len` bytes starting `fromEnd` bytes from the end. Leaves the preimage
// underneath untouched (the caller OP_DUPs first).
function fieldFromEnd (s, fromEnd, len) {
  return s.add(n(fromEnd)).add(Opcode.OP_RIGHT).add(n(len)).add(Opcode.OP_LEFT)
}

module.exports = {
  name: 'timelock',
  describe: 'nLockTime >= floor, enforced properly: preimage bound, sequence non-final, sign-padded',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ notBefore: 964000 }),

  // This predicate refuses a final input by design, so spending it must not
  // start from bsv's 0xffffffff default. Overridable per case.
  unlockDefaults: { sequenceNumber: 0xfffffffe },

  /**
   * Three things have to be true before "spendable no earlier than N" holds,
   * and dropping any one of them leaves a script that still verifies:
   *
   *   1. The preimage on the stack must be THIS transaction's. OP_PUSH_TX
   *      makes the interpreter compute the sighash itself. Hashing a pushed
   *      preimage and comparing to a constant baked in at lock time proves
   *      only that the spender can retype a value the locker already knew.
   *
   *   2. This input must be non-final. nLockTime is inert when every input
   *      has nSequence 0xffffffff — consensus skips the check and the tx is
   *      minable at once. A script that reads nLockTime without reading
   *      nSequence is reading a number the spender may set freely.
   *
   *   3. nLockTime must be read as unsigned. Script numbers carry sign in the
   *      high bit of the last byte; nLockTime is a little-endian uint32, so
   *      any value >= 0x80000000 (from 19 Jan 2038) reads back NEGATIVE and
   *      the comparison silently evaluates false for everyone. Appending a
   *      0x00 byte keeps it positive.
   *
   *      The padded value goes straight into OP_GREATERTHANOREQUAL, which
   *      reads operands at the era's real width. Passing it through
   *      OP_BIN2NUM first also works as of @smartledger/bsv 9.4.0, which
   *      fixed OP_BIN2NUM to take the era's max script-num length instead of
   *      a hardcoded 4 bytes (before that a 5-byte push failed
   *      INVALID_NUMBER_RANGE on mainnet). We keep the direct comparison
   *      because it does not depend on that fix — pre-Genesis, the 4-byte
   *      cap is real consensus and OP_BIN2NUM still rejects, correctly.
   *
   * What this CANNOT express is an upper bound — see `notAfter` below.
   */
  lock ({ notBefore, omitSequenceCheck, omitSignPad }) {
    const s = new Script().add(Opcode.OP_DUP)
    leanCore(s)                   // (1) bind the preimage to this spend
    s.add(Opcode.OP_VERIFY)       // stack: [preimage]

    if (!omitSequenceCheck) {     // (2) or nLockTime means nothing
      s.add(Opcode.OP_DUP)
      fieldFromEnd(s, FROM_END_SEQUENCE, 4)
      s.add(SEQUENCE_FINAL).add(Opcode.OP_EQUAL).add(Opcode.OP_NOT).add(Opcode.OP_VERIFY)
    }

    // (3) read nLockTime unsigned and require it ≥ floor. The default path defers to the
    // shared clause, which also pins the BIP-65 DOMAIN (a height floor demands a height
    // nLockTime, not a past timestamp that is numerically larger) — the same guard the
    // compiler emits, so the two stay byte-identical, and the one implementation is the
    // one place the domain fix lives. The `omitSignPad` variant is an adversarial test of
    // the sign-read itself and keeps its bespoke inline form.
    if (omitSignPad) {
      s.add(Opcode.OP_DUP)
      fieldFromEnd(s, FROM_END_LOCKTIME, 4)
      // OP_BIN2NUM re-encodes minimally; without the sign pad a high-bit value reads negative.
      s.add(Opcode.OP_BIN2NUM)
      s.add(n(notBefore)).add(Opcode.OP_GREATERTHANOREQUAL).add(Opcode.OP_VERIFY)
    } else {
      C.requireLockTimeAtLeast(s, notBefore)
    }

    return s.add(Opcode.OP_DROP).add(Opcode.OP_1)
  },

  /**
   * OP_PUSH_TX needs a preimage whose in-script signature is clean low-S DER,
   * which means grinding some malleable field of the spend. WHICH field matters
   * for a timelock, and getting it wrong quietly ruins the lock:
   *
   *   nLockTime as the nonce moves the unlock time itself. Each try adds one.
   *   For a HEIGHT floor that is one whole block per try — a ~40-try grind turns
   *   a one-block lock into roughly seven hours, and the caller never asked for
   *   that. For a timestamp floor it is 40 seconds, which is why the mistake is
   *   easy to miss until you use heights.
   *
   *   The input's SEQUENCE is malleable too, and this predicate already requires
   *   it to be non-final. Sweeping it down from 0xfffffffe keeps it non-final
   *   and leaves nLockTime pinned at exactly the floor the caller asked for.
   *
   * So: grind the sequence whenever the input is non-final, which is every real
   * timelock. When a caller has deliberately pinned a FINAL sequence — the test
   * that proves the guard works — fall back to nLockTime so that choice is not
   * silently overwritten.
   */
  unlock ({ tx, inputIndex, lockingScript, satoshis, notBefore }) {
    return new Script().add(
      C.grindPreimage(tx, inputIndex, lockingScript, satoshis, notBefore))
  }
}
