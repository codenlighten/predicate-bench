'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const { leanCore } = require('../pushtx')
const C = require('../clauses')
const R = require('../rabin')
const rabinScript = require('../rabinscript')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode

// SETTLEMENT — the oracle's value does not merely GATE the spend, it DECIDES the
// split. This is the numeric-payout apex of the oracle line: a contract for
// difference, a ranged insurance payout, a parametric escrow, where the attested
// number determines *how much* each of two parties receives, enforced on chain.
//
// Two parties — LONG (L) and SHORT (S) — lock a pot. At settlement an oracle
// attests a value v for a feed, and the covenant pays L a piecewise-linear share
// of the pot:
//
//     v <= LOW           -> L gets 0,               S gets all
//     v >= HIGH          -> L gets the whole pot,   S gets 0
//     LOW < v < HIGH     -> L gets pot·(v-LOW)/RANGE, S gets the rest
//
// with RANGE = HIGH - LOW. The pot is read from the covenant's OWN input value in
// the preimage (item 7), minus a fixed fee, so it settles whatever it was funded
// with. Conservation is exact by construction: payoutS = pot - payoutL.
//
// It needs no spender signature. The payout is a deterministic function of a
// value only the oracle can sign, and both destinations are fixed at lock time —
// so ANY party may broadcast the settlement, and there is exactly one it can
// broadcast. That is the point: a fair, forced settlement that no party can skew.
//
// This composes three mechanisms unchanged:
//   - the Rabin verifier of [oracle] (src/rabinscript.js) — the external value;
//   - output-binding via hashOutputs, as in [covenant] — the forced payments;
//   - conserved integer arithmetic, as in [token] — the split that sums to the pot.
//
// Honest limits. Like `oracle` it isolates the settlement mechanism and has no
// timeout: if the oracle never attests, the pot is stuck. A complete instrument
// composes this with `oracle`'s refund branch (funder reclaims after a deadline).
// And because the payout binds outputs, this branch MUST and does assert
// SIGHASH_ALL — the case `oracle`'s refund branch deliberately did not need.

const KEY = require('./oracle-key.json')
const ORACLE_N = BigInt(KEY.n)

const FEED_BYTES = 8
const VALUE_BYTES = 4
const DUST = 2000
const DEFAULT_FEE = 300

function feedTag (s) {
  const b = Buffer.alloc(FEED_BYTES)
  Buffer.from(s, 'latin1').copy(b, 0, 0, FEED_BYTES)
  return b
}
function valueLE (v) { const b = Buffer.alloc(VALUE_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function message (feed, value) { return Buffer.concat([feedTag(feed), valueLE(value)]) }
function padBytes (p) { return Buffer.from([p & 0xff, (p >> 8) & 0xff]) }

/** The P2PKH txout chunk — varint(len) ‖ script — the covenant splices a value in front of. */
function p2pkhChunk (pkh) {
  const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pkh, Buffer.from([0x88, 0xac])])
  return Buffer.concat([Buffer.from([script.length]), script])   // 0x19 ‖ 25-byte script
}
function addrOf (pkh) { return bsv.Address.fromPublicKeyHash(pkh) }

/** The split, computed identically in JS and in Script (integer, truncating). */
function payout (pot, v, low, high) {
  const range = high - low
  const t = Math.min(Math.max(v - low, 0), range)
  const payL = Math.floor((pot * t) / range)
  return { payL, payS: pot - payL }
}

function buildScript ({ feed, low, high, pkhL, pkhS, fee = DEFAULT_FEE, oracleN }) {
  const L = Buffer.isBuffer(pkhL) ? pkhL : Buffer.from(pkhL, 'hex')
  const S = Buffer.isBuffer(pkhS) ? pkhS : Buffer.from(pkhS, 'hex')
  if (L.length !== 20 || S.length !== 20) throw new Error('pkhL and pkhS must be 20 bytes')
  if (!(high > low && low >= 0)) throw new Error('need high > low >= 0')
  const range = high - low
  const nBytes = R.toScriptNum(oracleN || ORACLE_N)
  const chunkL = p2pkhChunk(L)
  const chunkS = p2pkhChunk(S)

  const s = new Script().add(Opcode.OP_DUP)
  leanCore(s)                                   // authenticate the preimage
  s.add(Opcode.OP_VERIFY)                        // [.., preimage]
  PushTx.assertSighashAll(s)                     // outputs are bound; SINGLE/NONE must be refused

  const asm = new StackAsm(s).given(['rsig', 'pad2', 'msg', 'preimage'])

  // --- verify the oracle attestation over FEED ‖ value, and read v ------------
  asm.pick('msg', 'mc'); asm.splitAt(FEED_BYTES, 'tag', 'valraw')
  asm.roll('tag'); asm.data(feedTag(feed), 'FEED'); asm.equalVerify()
  asm.data(Buffer.from([0]), 'vz'); asm.cat('valp'); asm.bin2num('v')     // v, unsigned
  asm.toAlt()                                     // park v; preimage back on top
  const scratch = rabinScript.verify(asm, { nBytes, sig: 'rsig', msg: 'msg', pad: 'pad2' })
  asm.roll(scratch); asm.drop()                  // drop the rabin hash scratch

  // --- pot = own input value (preimage item 7) - fee -------------------------
  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8), 0, ['inRaw'])  // DUPs preimage
  asm.bin2num('inVal'); asm.num(fee, 'fee'); asm.sub('pot')

  // --- payoutL = pot · clamp(v - LOW, 0, RANGE) / RANGE ----------------------
  asm.fromAlt()                                   // v back
  asm.num(low, 'LOW'); asm.sub('t0')             // v - LOW
  asm.num(0, 'z0'); asm.max('t1')                // max(·, 0)
  asm.num(range, 'RNG1'); asm.min('t')           // min(·, RANGE)
  asm.pick('pot', 'potA'); asm.pick('t', 'tA'); asm.mul('prod')
  asm.num(range, 'RNG2'); asm.div('payL')        // (pot·t)/RANGE
  asm.pick('pot', 'potB'); asm.pick('payL', 'payLc'); asm.sub('payS')   // pot - payL

  // --- build the two outputs and bind hashOutputs ----------------------------
  asm.pick('payL', 'payLb'); asm.num2bin(8, 'valL'); asm.data(chunkL, 'chunkL'); asm.cat('outL')
  asm.pick('payS', 'paySb'); asm.num2bin(8, 'valS'); asm.data(chunkS, 'chunkS'); asm.cat('outS')
  asm.pick('outL', 'oL'); asm.pick('outS', 'oS'); asm.cat('outs'); asm.hash256('hOut')
  asm.pick('preimage', 'pe')
  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['ho'])  // DUPs pe
  asm.nip()                                       // drop the preimage copy, keep ho
  asm.equalVerify()                               // computed hashOutputs == committed

  while (asm.main.length) asm.drop()
  asm.raw(Opcode.OP_1, 0, ['ok'])
  return s
}

// ---- scenario / harness plumbing -------------------------------------------

const ORACLE_KEY = { p: BigInt(KEY.p), q: BigInt(KEY.q), n: ORACLE_N }
function attest (feed, value) {
  const msg = message(feed, value)
  const { sig, padding } = R.sign(msg, ORACLE_KEY)
  return { msg, sig, pad2: padBytes(padding) }
}

module.exports = {
  name: 'settlement',
  describe: 'an oracle value splits a pot between two parties, piecewise-linear, forced by hashOutputs',
  example: () => ({
    feed: 'BSVUSD', low: 4000, high: 8000,
    pkhL: Buffer.alloc(20, 1), pkhS: Buffer.alloc(20, 2),
    fee: DEFAULT_FEE, attestValue: 6000
  }),

  FEED_BYTES,
  DUST,
  DEFAULT_FEE,
  ORACLE_N,
  buildScript,
  message,
  attest,
  payout,

  lock (tc) {
    if (!tc.pkhL || !tc.pkhS) throw new Error('pkhL and pkhS are required')
    return buildScript(tc)
  },

  /** The exact two outputs the covenant will force: L then S. */
  outputs (tc) {
    const pot = tc.satoshis - (tc.fee ?? DEFAULT_FEE)
    const { payL, payS } = payout(pot, tc.presentValue ?? tc.attestValue, tc.low, tc.high)
    const L = Buffer.isBuffer(tc.pkhL) ? tc.pkhL : Buffer.from(tc.pkhL, 'hex')
    const S = Buffer.isBuffer(tc.pkhS) ? tc.pkhS : Buffer.from(tc.pkhS, 'hex')
    // actualOutputs lets a refusal case create a payout the covenant did not compute
    if (tc.actualOutputs) return tc.actualOutputs({ pot, payL, payS, L, S })
    return [
      helpers.p2pkhOutput(addrOf(L), payL),
      helpers.p2pkhOutput(addrOf(S), payS)
    ]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis } = tc
    // attest the value that decides the split; forgeValue presents a different one
    const a = attest(tc.attestFeed || tc.feed, tc.attestValue)
    const msg = tc.forgeValue !== undefined
      ? message(tc.attestFeed || tc.feed, tc.forgeValue)
      : a.msg
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis)
      if (!PushTx.sFromPreimage(preimage)) continue
      return new Script().add(a.sig).add(a.pad2).add(msg).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
