'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const { leanCore } = require('./pushtx')
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// Clauses that AND together on one authenticated preimage.
//
// The contract between them: every clause receives the stack as [preimage],
// consumes a *copy*, and leaves [preimage] for the next one. That invariant is
// what makes them composable at all — a clause that consumed the preimage would
// work perfectly on its own and silently break whatever followed it.
//
// Offsets are from the END. scriptCode is variable-length, so everything before
// it moves and everything after it does not.
const FROM_END = { LOCKTIME: 8, HASH_OUTPUTS: 40, SEQUENCE: 44, VALUE: 52 }

/**
 * What a node will actually relay: consensus, plus the standardness bits that
 * are NOT in the consensus flag word.
 *
 * Verifying under consensus alone is not enough and each missing bit costs a
 * broadcast to discover. MINIMALDATA cost 1000 sat (a non-minimal script
 * number); CLEANSTACK cost 2000 sat (a stray preimage left under the result by
 * a duplicated OP_DUP). Both passed every local check at the time.
 *
 * The list is deliberately in one place so the harness, the tracer and the
 * broadcast path cannot drift apart on what "valid" means.
 */
function policyFlags () {
  const I = bsv.Script.Interpreter
  return I.currentConsensusFlags() |
    I.SCRIPT_VERIFY_MINIMALDATA |
    I.SCRIPT_VERIFY_CLEANSTACK |
    I.SCRIPT_VERIFY_SIGPUSHONLY |
    I.SCRIPT_VERIFY_LOW_S |
    I.SCRIPT_VERIFY_NULLFAIL |
    I.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    I.SCRIPT_VERIFY_NULLDUMMY
}

const SEQUENCE_FINAL = Buffer.from('ffffffff', 'hex')

/** Bind the pushed preimage to this spend. Must come first; everything else
 *  is only meaningful once the preimage provably describes this transaction. */
function authenticate (s) {
  s.add(Opcode.OP_DUP)
  leanCore(s)
  return s.add(Opcode.OP_VERIFY)
}

/** Reject anything but SIGHASH_ALL|FORKID. Under SINGLE or NONE, hashOutputs
 *  covers one output or nothing, so any output clause binds the wrong thing. */
function requireSighashAll (s) {
  return PushTx.assertSighashAll(s)
}

/** Take `len` bytes starting `fromEnd` from the end of a copy of the preimage. */
function fieldFromEnd (s, fromEnd, len) {
  return s.add(Opcode.OP_DUP)
    .add(n(fromEnd)).add(Opcode.OP_RIGHT)
    .add(n(len)).add(Opcode.OP_LEFT)
}

/**
 * hashPrevouts — item 2, at the FRONT of the preimage rather than the end.
 *
 * The BIP-143 layout is nVersion(4) ‖ hashPrevouts(32) ‖ … , and only the
 * fixed 4-byte version precedes it, so unlike scriptCode-relative fields this
 * one is addressed from the start. It is HASH256 of every input's outpoint
 * concatenated in order — the only window a covenant has onto the OTHER inputs
 * of its own spending transaction. Leaves a copy of the preimage beneath.
 */
function hashPrevoutsFromFront (s) {
  return s.add(Opcode.OP_DUP)
    .add(n(4)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
    .add(n(32)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
}

/** The spend must create exactly this output set, and nothing else. */
function requireOutputs (s, expectedHashOutputs) {
  if (expectedHashOutputs.length !== 32) throw new Error('hashOutputs must be 32 bytes')
  return fieldFromEnd(s, FROM_END.HASH_OUTPUTS, 32)
    .add(Buffer.from(expectedHashOutputs))
    .add(Opcode.OP_EQUALVERIFY)
}

/** This input must be non-final, or nLockTime is inert and the check below
 *  is reading a number the spender may write freely. */
function requireSequenceNonFinal (s) {
  return fieldFromEnd(s, FROM_END.SEQUENCE, 4)
    .add(SEQUENCE_FINAL).add(Opcode.OP_EQUAL).add(Opcode.OP_NOT).add(Opcode.OP_VERIFY)
}

// BIP-65 threshold: an nLockTime below this is a BLOCK HEIGHT, at/above it is a UNIX time.
const LOCKTIME_THRESHOLD = 500000000

/** nLockTime >= floor. Pads for sign, then OP_BIN2NUM to re-encode minimally —
 *  the pad's trailing zeros are a non-minimal script number, which passes
 *  consensus and is then refused at the broadcast as non-standard.
 *
 *  A numeric compare alone is NOT the whole story. nLockTime carries its meaning
 *  in its magnitude: below LOCKTIME_THRESHOLD it is a height, at/above it a unix
 *  timestamp. A bare `nLockTime >= floor` on a HEIGHT floor (say 900000) is also
 *  satisfied by any past TIMESTAMP (say 1_600_000_000) — numerically far larger,
 *  yet it makes the input final immediately, so the lock is no lock at all. Pass
 *  `{ pinDomain: true }` to also require the presented nLockTime to be in the
 *  SAME domain as the floor (the guard OP_CHECKLOCKTIMEVERIFY applies internally,
 *  and which a hand-rolled preimage timelock must apply too when early spending
 *  advantages an adversary — see [market]'s refund and pitfall 27). It is opt-in
 *  so existing callers keep their exact, deployed bytes; new covenants should set it. */
function requireLockTimeAtLeast (s, floor, { pinDomain = false } = {}) {
  if (!Number.isInteger(floor) || floor <= 0 || floor > 0xffffffff) {
    throw new Error('locktime floor must be a positive uint32')
  }
  fieldFromEnd(s, FROM_END.LOCKTIME, 4)
    .add(Buffer.from([0])).add(Opcode.OP_CAT).add(Opcode.OP_BIN2NUM)   // nLockTime, unsigned
  if (pinDomain) {
    s.add(Opcode.OP_DUP).add(n(LOCKTIME_THRESHOLD))                     // same domain as the floor
      .add(floor < LOCKTIME_THRESHOLD ? Opcode.OP_LESSTHAN : Opcode.OP_GREATERTHANOREQUAL)
      .add(Opcode.OP_VERIFY)
  }
  return s.add(n(floor)).add(Opcode.OP_GREATERTHANOREQUAL).add(Opcode.OP_VERIFY)
}

/**
 * Authenticate the preimage ONCE, above a branch split.
 *
 * A two-branch covenant that authenticates inside each branch carries the
 * OP_PUSH_TX preamble twice, and that preamble is the bulk of the script. It
 * only has to be written once — but the branch flag is on top of the stack when
 * the locking script starts, so the unlocking script must push the flag BELOW
 * the preimage:
 *
 *   unlocking:  ... <flag> <preimage>
 *
 * Then the preimage is on top to be authenticated, and one OP_SWAP brings the
 * flag back up for OP_IF. Each branch begins with exactly the stack it had
 * before — the branches themselves do not change at all.
 *
 * Emits everything up to and including OP_IF; the caller supplies the branches
 * and OP_ENDIF.
 */
function authenticateThenBranch (s) {
  s.add(Opcode.OP_DUP)
  leanCore(s)
  s.add(Opcode.OP_VERIFY)
  PushTx.assertSighashAll(s)   // stack-neutral: DUP, last 4 bytes, EQUALVERIFY
  s.add(Opcode.OP_SWAP)
  return s.add(Opcode.OP_IF)
}

// ---------------------------------------------------------------------------
// Primitives for covenants that read and rebuild their own script.
//
// These were written four times over, once per stateful predicate, and
// `selfChunk` was byte-identical in all four. One implementation each, exercised
// by every predicate's suite, is both less code and better tested: a mistake now
// shows up in 101 cases rather than in whichever predicate happened to copy it.

/**
 * chunk = preimage[104 : len-52] — byte-for-byte the `scriptlen||script` half of
 * a TxOut, varint included. Consumes a copy of the preimage; leaves it beneath.
 */
function selfChunk (s) {
  s.add(Opcode.OP_DUP)
  s.add(n(104)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
  return s.add(Opcode.OP_SIZE).add(n(FROM_END.VALUE)).add(Opcode.OP_SUB)
    .add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
}

/**
 * Take `bytes` from a chunk on top, starting `at` bytes in. Leaves [chunk, field].
 * The offset is measured from the chunk's start — i.e. from the varint — so a
 * caller passes `HEAD_BYTES + fieldOffset`, never a hand-counted absolute.
 */
function fieldFromChunk (s, at, bytes) {
  return s.add(Opcode.OP_DUP)
    .add(n(at)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
    .add(n(bytes)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
}

/** value - fee, as the 8-byte LE amount a TxOut starts with. Consumes a preimage copy. */
function newValueLE (s, fee) {
  s.add(n(FROM_END.VALUE)).add(Opcode.OP_RIGHT).add(n(8)).add(Opcode.OP_LEFT)
  s.add(Opcode.OP_BIN2NUM).add(n(fee)).add(Opcode.OP_SUB)
  return s.add(n(8)).add(Opcode.OP_NUM2BIN)
}

/**
 * Require HASH256(the output set built on top) to equal the preimage's
 * hashOutputs. Expects [preimage, outputs]; leaves the boolean result.
 */
function requireOutputIs (s) {
  s.add(Opcode.OP_HASH256)
  s.add(Opcode.OP_SWAP)
  PushTx.extractHashOutputs(s)
  return s.add(Opcode.OP_EQUAL)
}

/** An address, address string, or raw hash160, as 20 bytes. */
function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}

/**
 * The `scriptlen||script` half of a TxOut for any constant output script — the
 * same framing `selfChunk` extracts, so a covenant can build one and compare.
 * One-byte varint only, which covers every constant output worth hard-coding.
 */
function txOutChunk (script) {
  const buf = Buffer.isBuffer(script) ? script : script.toBuffer()
  if (buf.length > 252) {
    throw new Error(`constant output script is ${buf.length} bytes; needs a 1-byte varint`)
  }
  return Buffer.concat([Buffer.from([buf.length]), buf])
}

/** The same, for a P2PKH paying an address or hash160. */
function p2pkhTxOutChunk (a) {
  return txOutChunk(bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(hash160Of(a))))
}

/**
 * Grind for a preimage whose in-script OP_PUSH_TX signature is clean low-S DER.
 *
 * WHICH field carries the grind matters, and getting it wrong quietly ruins a
 * timelock. Using nLockTime moves the unlock time itself — one unit per attempt,
 * which against a HEIGHT floor is one whole block per attempt, so a ~40-try
 * grind turns a one-block lock into hours. The input's sequence is malleable too
 * and a correct timelock requires it non-final anyway, so sweeping it down from
 * its starting value leaves nLockTime pinned exactly where the caller asked.
 *
 * The exception is a caller who has deliberately pinned a FINAL sequence — the
 * case that proves the non-final guard works. Sweeping it would turn the input
 * non-final and quietly defeat the very test being run, so fall back to
 * grinding nLockTime and leave that choice alone.
 *
 * @param {number} pin the nLockTime to hold, when the sequence carries the grind
 * @returns {Buffer} the preimage
 */
function grindPreimage (tx, inputIndex, lockingScript, satoshis, pin, sighashType) {
  const input = tx.inputs[inputIndex]
  const grindSequence = input.sequenceNumber !== 0xffffffff
  const seqBase = input.sequenceNumber

  for (let t = 0; t < 50000; t++) {
    if (grindSequence) {
      tx.nLockTime = pin
      input.sequenceNumber = seqBase - t
    } else {
      tx.nLockTime = pin + t
    }
    const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
    if (PushTx.sFromPreimage(preimage)) return preimage
  }
  throw new Error('preimage grind failed after 50000 tries')
}

/** Drop the preimage and succeed. Every composition ends here. */
function finish (s) {
  return s.add(Opcode.OP_DROP).add(Opcode.OP_1)
}

module.exports = {
  FROM_END,
  policyFlags,
  authenticate,
  requireSighashAll,
  requireOutputs,
  requireSequenceNonFinal,
  requireLockTimeAtLeast,
  authenticateThenBranch,
  grindPreimage,
  selfChunk,
  fieldFromChunk,
  newValueLE,
  requireOutputIs,
  hash160Of,
  p2pkhTxOutChunk,
  txOutChunk,
  fieldFromEnd,
  hashPrevoutsFromFront,
  finish,
  hashOutputs: PushTx.hashOutputs,
  p2pkhOutput: helpers.p2pkhOutput
}
