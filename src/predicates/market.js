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

// MARKET — a fully-collateralised, two-party, binary prediction market, settled by an
// oracle QUORUM. Two parties lock a pot on a yes/no question; when m of n independent
// oracles attest the outcome, the whole pot (minus a fee) is forced to the winner. It is
// the application of [`settlement`](settlement) — whose oracle value *decides the split*
// — to a binary outcome under [`quorum`](quorum) split trust, and the first END-TO-END
// prediction market on the bench: question in, oracle-agreed outcome out, winner paid,
// no party able to skew it and no single oracle able to lie.
//
//   settle   Σ valid_i( sig_i over question‖outcome under N_i ) ≥ m,  outcome o ∈ {0,1}
//            → the whole pot (own input value − fee) is paid to  o==1 ? YES owner : NO owner
//
// The design is sound for the same reasons `settlement` is, sharpened by the quorum:
//   - The outcome is not the spender's to choose: the oracle message is built from the
//     BAKED question and the presented outcome, and the quorum count is run over it, so a
//     settlement can only pay the side m oracles actually attested — a forged outcome, or
//     a sub-quorum, is refused.
//   - The pot and both destinations are fixed: the pot is read from the covenant's OWN
//     input value in the preimage, and both owners are baked at lock time, so ANY party
//     may broadcast the settlement and there is exactly one payout it can broadcast. A
//     fair, forced, winner-take-all settlement no party can skew.
//   - Because it binds outputs, it MUST and does assert SIGHASH_ALL (pitfall 8).
//
// This is a single-branch settle, like `settlement`: a complete instrument adds a refund
// path (both parties reclaim half after a deadline, so an oracle panel that all vanishes
// cannot strand the pot forever) — the next increment of the prediction-market framework.
// Winner-take-all here is the binary case; a graded payout is `settlement`'s piecewise line.

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map((k) => BigInt(k.n))
const PANEL_KEYS = PANEL.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const QUESTION_BYTES = 32
const OUTCOME_MSG_BYTES = 4
const DEFAULT_FEE = 300
const DEFAULT_DEADLINE = 900000                     // the refund floor (baked); nLockTime ≥ this to reclaim
const DUST = 2000
const YES = 1
const NO = 0

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string' && /^[0-9a-fA-F]{40}$/.test(a)) return Buffer.from(a, 'hex')
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function outcomeLE (o) { const b = Buffer.alloc(OUTCOME_MSG_BYTES); b.writeUInt32LE(o >>> 0, 0); return b }
function oracleMessage (question, o) { return Buffer.concat([buf(question), outcomeLE(o)]) }
function addrOf (pkh) { return bsv.Address.fromPublicKeyHash(pkh) }

/** The P2PKH txout chunk — varint(len) ‖ script — the covenant splices the pot value in front of. */
function p2pkhChunk (pkh) {
  const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pkh, Buffer.from([0x88, 0xac])])
  return Buffer.concat([Buffer.from([script.length]), script])
}

// settle (flag = 1): the quorum decides the outcome, the whole pot goes to the winner.
function settleBody (asm, { q, chunkYes, chunkNo, moduli, m, fee }) {
  const N = moduli.length
  // the outcome must be one the market admits, o ∈ {0, 1}
  asm.pick('outcome4'); asm.bin2num('o')
  asm.pick('o'); asm.num(NO, 'z'); asm.numEqual('is0')
  asm.pick('o'); asm.num(YES, 'one'); asm.numEqual('is1')
  asm.raw(Opcode.OP_BOOLOR, 2, ['inRange']); asm.verify()

  // the oracle message is BAKED question ‖ presented outcome — binds the quorum to THIS market
  asm.data(q, 'Q'); asm.pick('outcome4'); asm.cat('omsg')

  // Σ valid_i(sig_i over question‖outcome under N_i) ≥ m — the same count as [quorum]
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'omsg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()

  // the winner's payout chunk: o==1 → YES owner, else NO owner
  asm.pick('o'); asm.beginIf()
  asm.data(chunkYes, 'wchunk')
  asm.elseBranch()
  asm.data(chunkNo, 'wchunk')
  asm.endIf()

  // the single forced output: (own input value − fee) ‖ winner P2PKH, bound to hashOutputs
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['val8'])
  asm.pick('wchunk', 'wc'); asm.cat('out')
  asm.bindOutput('out')
}

// refund (flag = 0): after the deadline, both parties reclaim their half — so a panel that
// all vanishes cannot strand the pot. No oracle, no signature: any party may broadcast it,
// and the funds are forced back to the two baked owners, split 50/50.
function refundBody (asm, { chunkYes, chunkNo, fee, deadline }) {
  // the timelock is only real if the input is non-final AND nLockTime ≥ deadline (pitfall 6/timelock)
  asm.clause((x) => C.requireSequenceNonFinal(x), 0, [])
  asm.clause((x) => C.requireLockTimeAtLeast(x, deadline, { pinDomain: true }), 0, [])

  // pot = own input value − fee; split half (YES) / the rest (NO), summing exactly
  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8), 0, ['inRaw'])
  asm.bin2num('inVal'); asm.num(fee, 'fee'); asm.sub('pot')
  asm.pick('pot', 'potA'); asm.num(2, 'two'); asm.div('half')
  asm.pick('pot', 'potB'); asm.pick('half', 'halfA'); asm.sub('other')

  // two forced outputs: half → YES owner, the rest → NO owner
  asm.pick('half', 'hb'); asm.num2bin(8, 'v1'); asm.data(chunkYes, 'cY'); asm.cat('out1')
  asm.pick('other', 'ob'); asm.num2bin(8, 'v2'); asm.data(chunkNo, 'cN'); asm.cat('out2')
  asm.pick('out1', 'o1'); asm.pick('out2', 'o2'); asm.cat('outs')
  asm.bindOutput('outs')
}

function buildScript ({ question, yesPKH, noPKH, m = 2, panelN, fee = DEFAULT_FEE, deadline = DEFAULT_DEADLINE }) {
  const q = buf(question)
  const Y = pkhOf(yesPKH); const No = pkhOf(noPKH)
  if (q.length !== QUESTION_BYTES) throw new Error('question must be 32 bytes')
  if (Y.length !== 20 || No.length !== 20) throw new Error('yesPKH and noPKH must be 20 bytes')
  const moduli = (panelN || PANEL_N).map((x) => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)
  const chunkYes = p2pkhChunk(Y)
  const chunkNo = p2pkhChunk(No)

  const s = new Script()
  C.authenticateThenBranch(s)                      // authenticate once; outputs bound → SIGHASH_ALL

  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)

  const settle = new StackAsm(s); settle.main = ['outcome4', ...slots, 'preimage']
  settleBody(settle, { q, chunkYes, chunkNo, moduli, m, fee })
  while (settle.main.length) settle.drop()
  settle.raw(Opcode.OP_1, 0, ['ok'])
  const d = settle.main.length

  s.add(Opcode.OP_ELSE)
  const refund = new StackAsm(s); refund.main = ['preimage']
  refundBody(refund, { chunkYes, chunkNo, fee, deadline })
  while (refund.main.length) refund.drop()
  refund.raw(Opcode.OP_1, 0, ['ok'])
  if (refund.main.length !== d) throw new Error(`market: branches leave different depths (${d} vs ${refund.main.length})`)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- scenarios --------------------------------------------------------------

function attestWith (keyObj, question, outcome) {
  const msg = oracleMessage(question, outcome)
  const { sig, padding } = R.sign(msg, keyObj)
  if (padding > 0xffff) throw new Error('rabin padding needs more than 2 bytes — widen the pad encoding')
  return { sig, pad2: Buffer.from([padding & 0xff, (padding >> 8) & 0xff]) }
}

module.exports = {
  name: 'market',
  describe: 'a fully-collateralised two-party binary prediction market: an m-of-n oracle quorum decides the outcome, the whole pot is forced to the winner',
  example: () => ({
    question: Buffer.alloc(32, 7), yesPKH: Buffer.alloc(20, 1), noPKH: Buffer.alloc(20, 2),
    m: 2, signers: [0, 1], attestOutcome: 1
  }),

  QUESTION_BYTES,
  DUST,
  DEFAULT_FEE,
  DEFAULT_DEADLINE,
  YES,
  NO,
  PANEL_N,
  buildScript,
  oracleMessage,
  attestWith,
  p2pkhChunk,
  pkhOf,

  // a real timelock needs the input non-final, or nLockTime is inert (the refund's guard)
  unlockDefaults: { sequenceNumber: 0xfffffffe },

  lock (tc) {
    if (!tc.question || !tc.yesPKH || !tc.noPKH) throw new Error('question, yesPKH, noPKH are required')
    return buildScript({ question: tc.question, yesPKH: tc.yesPKH, noPKH: tc.noPKH, m: tc.m, panelN: tc.panelN, fee: tc.fee, deadline: tc.deadline })
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const pot = tc.satoshis - fee
    if ((tc.branch || 'settle') === 'refund') {
      const half = Math.floor(pot / 2); const other = pot - half
      if (tc.actualOutputs) return tc.actualOutputs({ fee, pot, half, other })
      return [
        helpers.p2pkhOutput(addrOf(pkhOf(tc.yesPKH)), half),
        helpers.p2pkhOutput(addrOf(pkhOf(tc.noPKH)), other)
      ]
    }
    const o = tc.forgeOutcome !== undefined ? tc.forgeOutcome : tc.attestOutcome
    const winner = (o === YES) ? pkhOf(tc.yesPKH) : pkhOf(tc.noPKH)
    if (tc.actualOutputs) return tc.actualOutputs({ fee, pot })
    return [helpers.p2pkhOutput(addrOf(winner), pot)]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const N = (tc.panelN || PANEL_N).length

    // refund (flag 0): no oracle, no signature — pin nLockTime at/above the deadline
    if ((tc.branch || 'settle') === 'refund') {
      const pin = tc.refundAt ?? (tc.deadline ?? DEFAULT_DEADLINE)
      const preimage = C.grindPreimage(tx, inputIndex, lockingScript, satoshis, pin, type)
      return new Script().add(Opcode.OP_0).add(preimage)
    }

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue

      const signed = tc.attestOutcome
      const presented = tc.forgeOutcome !== undefined ? tc.forgeOutcome : signed
      const attestQuestion = tc.attestQuestion || tc.question
      const slotKeys = tc.slotKeys || (() => {
        const a = new Array(N).fill(null); (tc.signers || []).forEach((idx) => { a[idx] = idx }); return a
      })()

      const us = new Script()
      us.add(outcomeLE(presented))
      for (let i = 0; i < N; i++) {
        const k = slotKeys[i]
        if (k === null || k === undefined) {
          us.add(Buffer.from([0])).add(Buffer.from([0, 0]))
        } else {
          const a = attestWith(PANEL_KEYS[k], attestQuestion, signed)
          us.add(a.sig).add(a.pad2)
        }
      }
      us.add(Opcode.OP_1).add(preimage)             // settle flag, below the preimage
      return us
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
