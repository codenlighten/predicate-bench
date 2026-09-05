'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const R = require('../rabin')
const rabinScript = require('../rabinscript')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode

// MARKET-SCALAR — a fully-collateralised, two-party SCALAR market, settled by an oracle
// QUORUM. Where [`market`](market) pays winner-take-all on a yes/no outcome and
// [`marketN`](marketn) on one of N, this pays a GRADED amount that is a function of the
// number the oracles attest — a contract for difference, a ranged insurance payout, a
// parametric bet. It is [`settlement`](settlement)'s piecewise-linear split lifted from a
// single oracle to m-of-n split trust.
//
//   settle   Σ valid_i( sig_i over question‖value under N_i ) ≥ m, then split the pot:
//              v ≤ LOW        → LONG gets 0,            SHORT gets all
//              v ≥ HIGH       → LONG gets the whole pot, SHORT gets 0
//              LOW < v < HIGH → LONG gets pot·(v−LOW)/RANGE, SHORT gets the rest
//   refund   nLockTime ≥ deadline ∧ input non-final → the pot splits 50/50 back to both
//
// Conservation is exact by construction (payShort = pot − payLong), the value is the
// oracles' to attest (bound to THIS question, a forged or wrong-question value refused),
// and both destinations are fixed at lock time — so any party may broadcast the one
// settlement the attested value determines. Refund pins the BIP-65 domain (pitfall 27).

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map((k) => BigInt(k.n))
const PANEL_KEYS = PANEL.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const QUESTION_BYTES = 32
const VALUE_BYTES = 4
const DEFAULT_FEE = 400
const DEFAULT_DEADLINE = 900000
const DUST = 2000

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string' && /^[0-9a-fA-F]{40}$/.test(a)) return Buffer.from(a, 'hex')
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function valueLE (v) { const b = Buffer.alloc(VALUE_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function oracleMessage (question, v) { return Buffer.concat([buf(question), valueLE(v)]) }
function addrOf (pkh) { return bsv.Address.fromPublicKeyHash(pkh) }

function p2pkhChunk (pkh) {
  const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pkh, Buffer.from([0x88, 0xac])])
  return Buffer.concat([Buffer.from([script.length]), script])
}

/** The split, computed identically in JS and in Script (integer, truncating). */
function payout (pot, v, low, high) {
  const range = high - low
  const t = Math.min(Math.max(v - low, 0), range)
  const payL = Math.floor((pot * t) / range)
  return { payL, payS: pot - payL }
}

// settle (flag = 1): the quorum attests v, the pot is split by the piecewise-linear rule.
function settleBody (asm, { q, low, range, chunkL, chunkS, moduli, m, fee }) {
  const N = moduli.length
  asm.pick('value4'); asm.bin2num('v')                       // the attested number

  // the oracle message is BAKED question ‖ presented value — binds the quorum to THIS market
  asm.data(q, 'Q'); asm.pick('value4'); asm.cat('omsg')
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'omsg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()

  // pot = own input value − fee
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8), 0, ['inRaw'])
  asm.bin2num('inVal'); asm.nip(); asm.num(fee, 'fee'); asm.sub('pot')

  // payL = pot · clamp(v − LOW, 0, RANGE) / RANGE ; payS = pot − payL
  asm.pick('v', 'vA'); asm.num(low, 'LOW'); asm.sub('t0')
  asm.num(0, 'z0'); asm.max('t1')
  asm.num(range, 'RNG1'); asm.min('t')
  asm.pick('pot', 'potA'); asm.pick('t', 'tA'); asm.mul('prod')
  asm.num(range, 'RNG2'); asm.div('payL')
  asm.pick('pot', 'potB'); asm.pick('payL', 'payLc'); asm.sub('payS')

  // two forced outputs: payL → LONG, payS → SHORT, bound to hashOutputs
  asm.pick('payL', 'payLb'); asm.num2bin(8, 'valL'); asm.data(chunkL, 'chunkL'); asm.cat('outL')
  asm.pick('payS', 'paySb'); asm.num2bin(8, 'valS'); asm.data(chunkS, 'chunkS'); asm.cat('outS')
  asm.pick('outL', 'oL'); asm.pick('outS', 'oS'); asm.cat('outs')
  asm.bindOutput('outs')
}

// refund (flag = 0): after the deadline, both parties reclaim their half — the pot splits 50/50.
function refundBody (asm, { chunkL, chunkS, fee, deadline }) {
  asm.clause((x) => C.requireSequenceNonFinal(x), 0, [])
  asm.clause((x) => C.requireLockTimeAtLeast(x, deadline, { pinDomain: true }), 0, [])

  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8), 0, ['inRaw'])
  asm.bin2num('inVal'); asm.num(fee, 'fee'); asm.sub('pot')
  asm.pick('pot', 'potA'); asm.num(2, 'two'); asm.div('half')
  asm.pick('pot', 'potB'); asm.pick('half', 'halfA'); asm.sub('other')

  asm.pick('half', 'hb'); asm.num2bin(8, 'v1'); asm.data(chunkL, 'cL'); asm.cat('out1')
  asm.pick('other', 'ob'); asm.num2bin(8, 'v2'); asm.data(chunkS, 'cS'); asm.cat('out2')
  asm.pick('out1', 'o1'); asm.pick('out2', 'o2'); asm.cat('outs')
  asm.bindOutput('outs')
}

function buildScript ({ question, low, high, pkhL, pkhS, m = 2, panelN, fee = DEFAULT_FEE, deadline = DEFAULT_DEADLINE }) {
  const q = buf(question)
  const L = pkhOf(pkhL); const S = pkhOf(pkhS)
  if (q.length !== QUESTION_BYTES) throw new Error('question must be 32 bytes')
  if (L.length !== 20 || S.length !== 20) throw new Error('pkhL and pkhS must be 20 bytes')
  if (!(high > low && low >= 0)) throw new Error('need high > low >= 0')
  const range = high - low
  const moduli = (panelN || PANEL_N).map((x) => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)
  const chunkL = p2pkhChunk(L)
  const chunkS = p2pkhChunk(S)

  const s = new Script()
  C.authenticateThenBranch(s)

  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)

  const settle = new StackAsm(s); settle.main = ['value4', ...slots, 'preimage']
  settleBody(settle, { q, low, range, chunkL, chunkS, moduli, m, fee })
  while (settle.main.length) settle.drop()
  settle.raw(Opcode.OP_1, 0, ['ok'])
  const d = settle.main.length

  s.add(Opcode.OP_ELSE)
  const refund = new StackAsm(s); refund.main = ['preimage']
  refundBody(refund, { chunkL, chunkS, fee, deadline })
  while (refund.main.length) refund.drop()
  refund.raw(Opcode.OP_1, 0, ['ok'])
  if (refund.main.length !== d) throw new Error(`marketScalar: branches leave different depths (${d} vs ${refund.main.length})`)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- scenarios --------------------------------------------------------------

function attestWith (keyObj, question, v) {
  const msg = oracleMessage(question, v)
  const { sig, padding } = R.sign(msg, keyObj)
  if (padding > 0xffff) throw new Error('rabin padding needs more than 2 bytes — widen the pad encoding')
  return { sig, pad2: Buffer.from([padding & 0xff, (padding >> 8) & 0xff]) }
}

module.exports = {
  name: 'marketScalar',
  describe: 'a fully-collateralised two-party scalar market: an m-of-n oracle quorum attests a value, the pot is split piecewise-linearly between LONG and SHORT, or a 50/50 refund after a deadline',
  example: () => ({
    question: Buffer.alloc(32, 7), low: 6000, high: 7000, pkhL: Buffer.alloc(20, 1), pkhS: Buffer.alloc(20, 2),
    m: 2, signers: [0, 1], attestValue: 6500
  }),

  QUESTION_BYTES,
  DUST,
  DEFAULT_FEE,
  DEFAULT_DEADLINE,
  PANEL_N,
  buildScript,
  payout,
  oracleMessage,
  attestWith,
  p2pkhChunk,
  pkhOf,

  unlockDefaults: { sequenceNumber: 0xfffffffe },

  lock (tc) {
    if (!tc.question || tc.low === undefined || tc.high === undefined) throw new Error('question, low, high are required')
    return buildScript({ question: tc.question, low: tc.low, high: tc.high, pkhL: tc.pkhL, pkhS: tc.pkhS, m: tc.m, panelN: tc.panelN, fee: tc.fee, deadline: tc.deadline })
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const pot = tc.satoshis - fee
    if ((tc.branch || 'settle') === 'refund') {
      const half = Math.floor(pot / 2); const other = pot - half
      if (tc.actualOutputs) return tc.actualOutputs({ fee, pot, half, other })
      return [helpers.p2pkhOutput(addrOf(pkhOf(tc.pkhL)), half), helpers.p2pkhOutput(addrOf(pkhOf(tc.pkhS)), other)]
    }
    const v = tc.forgeValue !== undefined ? tc.forgeValue : tc.attestValue
    const { payL, payS } = payout(pot, v, tc.low, tc.high)
    if (tc.actualOutputs) return tc.actualOutputs({ fee, pot, payL, payS })
    return [helpers.p2pkhOutput(addrOf(pkhOf(tc.pkhL)), payL), helpers.p2pkhOutput(addrOf(pkhOf(tc.pkhS)), payS)]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const N = (tc.panelN || PANEL_N).length

    if ((tc.branch || 'settle') === 'refund') {
      const pin = tc.refundAt ?? (tc.deadline ?? DEFAULT_DEADLINE)
      const preimage = C.grindPreimage(tx, inputIndex, lockingScript, satoshis, pin, type)
      return new Script().add(Opcode.OP_0).add(preimage)
    }

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue

      const signed = tc.attestValue
      const presented = tc.forgeValue !== undefined ? tc.forgeValue : signed
      const attestQuestion = tc.attestQuestion || tc.question
      const slotKeys = tc.slotKeys || (() => {
        const a = new Array(N).fill(null); (tc.signers || []).forEach((idx) => { a[idx] = idx }); return a
      })()

      const us = new Script()
      us.add(valueLE(presented))
      for (let i = 0; i < N; i++) {
        const k = slotKeys[i]
        if (k === null || k === undefined) {
          us.add(Buffer.from([0])).add(Buffer.from([0, 0]))
        } else {
          const a = attestWith(PANEL_KEYS[k], attestQuestion, signed)
          us.add(a.sig).add(a.pad2)
        }
      }
      us.add(Opcode.OP_1).add(preimage)
      return us
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
