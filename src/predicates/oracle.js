'use strict'

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const R = require('../rabin')
const rabinScript = require('../rabinscript')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// ORACLE — the one class of contract the bench had no mechanism for: a spend
// gated on EXTERNAL signed data, not on a key or on the shape of the spending
// transaction. This is the foundation of every parametric contract — a bet, an
// insurance payout, a price-triggered escrow — where "who may spend, and when"
// depends on a fact the chain itself cannot see.
//
// The obstacle is that OP_CHECKSIG is useless here. It verifies an ECDSA
// signature against THIS transaction's sighash, computed by the interpreter —
// it cannot be pointed at a free message an oracle signed off-chain. BSV has no
// OP_CHECKDATASIG. So the oracle signs with a RABIN signature instead, which a
// covenant verifies with nothing but modular arithmetic:
//
//     s² mod N  ==  H(message ‖ padding) mod N
//
// N = p·q is the oracle's public key (hard-coded in the covenant); only the
// holder of the factorisation can produce an s for a given message, and anyone
// can check one with OP_MUL and OP_MOD. See src/rabin.js for the signing side.
//
// This predicate is a BINARY OPTION with two spend paths:
//
//   CLAIM  (selector 1): the winner may take the coins once the oracle attests
//          a value at or above THRESHOLD for the named FEED. Requires the
//          winner's signature (so the attestation, which is public data, does
//          not let a bystander grab the payout) AND a valid oracle signature
//          over `FEED ‖ value` with value ≥ THRESHOLD.
//
//   REFUND (selector 0): if the event never happens, the funder must recover.
//          After DEADLINE (an nLockTime floor, enforced the proper preimage way
//          — bound, sequence non-final, sign-padded) the funder may reclaim with
//          their signature. This is why the option is not a one-way trap.
//
// Honest limits. The Rabin key here is a 512-bit demo key (src/predicates/
// oracle-key.json) — the MECHANISM is the artifact, not the key size; a
// production oracle uses 2048+ bits, which only makes the pushes and the OP_MUL
// wider. And nLockTime is a floor, never a ceiling (see the timelock notes), so
// REFUND opens at DEADLINE and never closes — a claim that has not happened by
// then can still happen after. A real option would race the two paths with a
// pre-signed settlement; here the two mechanisms are isolated and composed, in
// the bench's usual style.

const KEY = require('./oracle-key.json')
const ORACLE_N = BigInt(KEY.n)

const FEED_BYTES = 8            // feed tag, e.g. "BSVUSD\0\0"
const VALUE_BYTES = 4          // attested value, uint32 LE
const MSG_BYTES = FEED_BYTES + VALUE_BYTES
const DUST = 2000

function feedTag (s) {
  const b = Buffer.alloc(FEED_BYTES)
  Buffer.from(s, 'latin1').copy(b, 0, 0, FEED_BYTES)
  return b
}
function valueLE (v) { const b = Buffer.alloc(VALUE_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function message (feed, value) { return Buffer.concat([feedTag(feed), valueLE(value)]) }
function padBytes (padding) { return Buffer.from([padding & 0xff, (padding >> 8) & 0xff]) }

// --- the CLAIM branch: winner signature + oracle attestation over the feed ---
function claimBody (asm, { nBytes, feed, threshold, winnerPKH }) {
  // winner is P2PKH — the attestation is public, so the payout must still be
  // bound to a key or anyone could spend it.
  asm.pick('wpub'); asm.hash160('wh'); asm.data(winnerPKH, 'WPKH'); asm.equalVerify()
  asm.pick('wsig'); asm.pick('wpub'); asm.checkSigVerify()

  // parse a copy of the message: tag must be the feed, value must clear threshold
  asm.pick('msg', 'mc'); asm.splitAt(FEED_BYTES, 'tag', 'val')
  asm.roll('tag'); asm.data(feedTag(feed), 'FEED'); asm.equalVerify()
  // The value is a uint32, but OP_BIN2NUM reads signed — so a 0x00 pad keeps a
  // value with its top bit set (>= 2^31, e.g. a satoshi- or index-denominated
  // feed) positive, or it would read negative and be refused above the threshold.
  asm.data(Buffer.from([0]), 'vz'); asm.cat('valp')
  asm.bin2num('valn'); asm.num(threshold, 'thr'); asm.geVerify()

  // Rabin verification — s² mod N == H(msg ‖ pad) mod N — the shared clause. It
  // leaves one scratch value on the stack; the trailing cleanup in buildScript
  // drops it along with the rest of the branch's residue.
  rabinScript.verify(asm, { nBytes, sig: 'rsig', msg: 'msg', pad: 'pad2' })
}

// --- the REFUND branch: funder signature after the deadline ------------------
// Note this branch does NOT assert SIGHASH_ALL, and correctly so: like `timelock`
// (its exact analog) it reads only the input's own nSequence and nLockTime, which
// are present in the preimage under every sighash flag. The output-binding
// predicates (metered, registry, covenant) assert it because hashOutputs is
// zeroed under NONE/SINGLE — so if an output constraint is ever ADDED here, this
// branch must gain requireSighashAll with it or be silently defeated.
function refundBody (asm, { funderPKH, deadline }) {
  asm.clause(C.authenticate, 0, [])                          // (1) bind the preimage
  asm.pick('fpub'); asm.hash160('fh'); asm.data(funderPKH, 'FPKH'); asm.equalVerify()
  asm.pick('fsig'); asm.pick('fpub'); asm.checkSigVerify()
  asm.clause(C.requireSequenceNonFinal, 0, [])              // (2) or nLockTime is inert
  asm.clause((x) => C.requireLockTimeAtLeast(x, deadline), 0, [])  // (3) split from the end, sign-padded
}

function buildScript ({ feed, threshold, winnerPKH, funderPKH, deadline, oracleN }) {
  const w = Buffer.isBuffer(winnerPKH) ? winnerPKH : Buffer.from(winnerPKH, 'hex')
  const f = Buffer.isBuffer(funderPKH) ? funderPKH : Buffer.from(funderPKH, 'hex')
  if (w.length !== 20 || f.length !== 20) throw new Error('pubkey hashes must be 20 bytes')
  if (!Number.isInteger(threshold) || threshold < 0) throw new Error('threshold must be a non-negative integer')
  const nBytes = R.toScriptNum(oracleN || ORACLE_N)

  const s = new Script()
  const asm = new StackAsm(s)

  s.add(Opcode.OP_IF)                                        // selector consumed here
  asm.main = ['wsig', 'wpub', 'rsig', 'pad2', 'msg']; asm.alt = []
  claimBody(asm, { nBytes, feed, threshold, winnerPKH: w })
  while (asm.main.length) asm.drop()
  asm.raw(Opcode.OP_1, 0, ['ok'])
  const claimDepth = asm.main.length

  s.add(Opcode.OP_ELSE)
  asm.main = ['fsig', 'fpub', 'preimage']; asm.alt = []
  refundBody(asm, { funderPKH: f, deadline })
  while (asm.main.length) asm.drop()
  asm.raw(Opcode.OP_1, 0, ['ok'])

  if (asm.main.length !== claimDepth) {
    throw new Error(`oracle: branches leave different depths (claim ${claimDepth} vs refund ${asm.main.length})`)
  }
  s.add(Opcode.OP_ENDIF)
  return s
}

// ---- scenarios: sign real attestations with the demo oracle key -------------

const ORACLE_KEY = { p: BigInt(KEY.p), q: BigInt(KEY.q), n: ORACLE_N }

function attest (feed, value) {
  const msg = message(feed, value)
  const { sig, padding } = R.sign(msg, ORACLE_KEY)
  return { msg, sig, pad2: padBytes(padding) }
}

module.exports = {
  name: 'oracle',
  describe: 'a binary option: winner claims on an oracle Rabin-signed value >= threshold, funder refunds after a deadline',
  example: () => ({
    feed: 'BSVUSD',
    threshold: 6000,
    winnerPKH: Buffer.alloc(20, 1),
    funderPKH: Buffer.alloc(20, 2),
    deadline: 964000,
    kind: 'claim',
    attestValue: 6543
  }),

  FEED_BYTES,
  VALUE_BYTES,
  DUST,
  ORACLE_N,
  buildScript,
  message,
  attest,

  lock (tc) {
    if (!tc.winnerPKH || !tc.funderPKH) throw new Error('winnerPKH and funderPKH are required')
    return buildScript(tc)
  },

  // REFUND must be spent with a non-final sequence, so nLockTime bites.
  unlockDefaults: { sequenceNumber: 0xfffffffe },

  // A handful of knobs below (forgeValue, attestFeed, pinLockTime) exist only so
  // the suite can express refusals as data — a forged signature, a wrong feed, a
  // premature refund — without hand-assembling unlocking scripts.
  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType, kind } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)

    if (kind === 'refund') {
      // grind the sequence (keeps nLockTime pinned); pinLockTime forces a premature spend
      const pin = tc.pinLockTime ?? tc.deadline
      const preimage = C.grindPreimage(tx, inputIndex, lockingScript, satoshis, pin, type)
      const fpriv = tc.funderKey || tc.key                   // on chain, the wallet is the funder
      const fsig = bsv.Transaction.Sighash.sign(
        tx, fpriv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      return new Script()
        .add(fsig).add(fpriv.publicKey.toBuffer())
        .add(preimage)
        .add(Opcode.OP_0)                                    // selector: refund
    }

    // CLAIM: winner signs the spend, oracle attests the feed value
    const wpriv = tc.winnerKey || tc.key                     // on chain, the wallet is the winner
    const wsig = bsv.Transaction.Sighash.sign(
      tx, wpriv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
    const a = attest(tc.attestFeed || tc.feed, tc.attestValue)   // the oracle's real signature
    // forgeValue: present a DIFFERENT value than the one signed, keeping the
    // signature — proves the Rabin check binds the value, not just the threshold.
    const msg = tc.forgeValue !== undefined
      ? message(tc.attestFeed || tc.feed, tc.forgeValue)
      : a.msg
    return new Script()
      .add(wsig).add(wpriv.publicKey.toBuffer())
      .add(a.sig).add(a.pad2).add(msg)
      .add(Opcode.OP_1)                                      // selector: claim
  }
}
