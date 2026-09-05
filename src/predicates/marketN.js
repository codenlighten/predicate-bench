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

// MARKET-N — a fully-collateralised, N-outcome (categorical) prediction market, settled by
// an oracle QUORUM. It generalises [`market`](market) from a yes/no question to a field of
// N mutually-exclusive outcomes — "which candidate wins", "which team takes the title" — the
// roadmap's multiple-choice market. Everyone stakes into one pot; when m of n independent
// oracles attest the winning outcome index, the whole pot (minus a fee) is forced to that
// outcome's owner.
//
//   settle   Σ valid_i( sig_i over question‖outcome under N_i ) ≥ m,  outcome o ∈ [0, K)
//            → the whole pot (own input value − fee) goes to owner[o]
//   refund   nLockTime ≥ deadline ∧ input non-final
//            → the pot splits into K equal shares, one back to each outcome's owner
//
// The new mechanism over the binary market is the K-way winner SELECTION: the covenant
// carries K baked payout scripts and, from the single attested index o, picks exactly one —
// a nested OP_IF cascade (o==0 ? owner0 : o==1 ? owner1 : … : owner_{K-1}), guarded by a
// range check so the fall-through index cannot be forged. Everything else is [`market`]:
// the outcome is the oracles' (bound to THIS question), the pot and every owner are fixed
// at lock time, it binds outputs so it asserts SIGHASH_ALL, and the refund pins the BIP-65
// domain (pitfall 27) so a losing party cannot reclaim early with a past timestamp.

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map((k) => BigInt(k.n))
const PANEL_KEYS = PANEL.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const QUESTION_BYTES = 32
const OUTCOME_MSG_BYTES = 4
const DEFAULT_FEE = 400
const DEFAULT_DEADLINE = 900000
const DUST = 2000

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string' && /^[0-9a-fA-F]{40}$/.test(a)) return Buffer.from(a, 'hex')
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function outcomeLE (o) { const b = Buffer.alloc(OUTCOME_MSG_BYTES); b.writeUInt32LE(o >>> 0, 0); return b }
function oracleMessage (question, o) { return Buffer.concat([buf(question), outcomeLE(o)]) }
function addrOf (pkh) { return bsv.Address.fromPublicKeyHash(pkh) }

/** The P2PKH txout chunk — varint(len) ‖ script — a value is spliced in front of. */
function p2pkhChunk (pkh) {
  const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pkh, Buffer.from([0x88, 0xac])])
  return Buffer.concat([Buffer.from([script.length]), script])
}

// settle (flag = 1): the quorum names the winning index, the whole pot goes to its owner.
function settleBody (asm, { q, chunks, moduli, m, fee }) {
  const N = moduli.length
  const K = chunks.length

  // the attested index must be a real outcome: 0 ≤ o ≤ K-1 (so the cascade fall-through is safe)
  asm.pick('outcome4'); asm.bin2num('o')
  asm.pick('o'); asm.num(0, 'zero'); asm.geVerify()          // o ≥ 0
  asm.pick('o'); asm.num(K - 1, 'kmax'); asm.leVerify()      // o ≤ K-1

  // the oracle message is BAKED question ‖ presented outcome — binds the quorum to THIS market
  asm.data(q, 'Q'); asm.pick('outcome4'); asm.cat('omsg')
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'omsg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()

  // K-way winner selection: o==0 ? chunk0 : o==1 ? chunk1 : … : chunk_{K-1}
  for (let i = 0; i < K - 1; i++) {
    asm.pick('o'); asm.num(i, 'i' + i); asm.numEqual('isI')
    asm.beginIf()
    asm.data(chunks[i], 'wchunk')
    asm.elseBranch()
  }
  asm.data(chunks[K - 1], 'wchunk')                          // the last outcome (fall-through, range-guarded)
  for (let i = 0; i < K - 1; i++) asm.endIf()

  // the single forced output: (own input value − fee) ‖ winner P2PKH, bound to hashOutputs
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['val8'])
  asm.pick('wchunk', 'wc'); asm.cat('out')
  asm.bindOutput('out')
}

// refund (flag = 0): after the deadline, the pot splits into K equal shares, one per owner.
function refundBody (asm, { chunks, fee, deadline }) {
  const K = chunks.length
  asm.clause((x) => C.requireSequenceNonFinal(x), 0, [])
  asm.clause((x) => C.requireLockTimeAtLeast(x, deadline, { pinDomain: true }), 0, [])

  // pot = own input value − fee; share = pot / K; the last owner takes the remainder so the sum is exact
  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8), 0, ['inRaw'])
  asm.bin2num('inVal'); asm.num(fee, 'fee'); asm.sub('pot')
  asm.pick('pot', 'potA'); asm.num(K, 'K'); asm.div('share')
  asm.pick('share', 'shareM'); asm.num(K - 1, 'Km1'); asm.mul('taken')
  asm.pick('pot', 'potB'); asm.pick('taken', 'takenB'); asm.sub('last')

  // K outputs: share to each of the first K-1 owners, the remainder to the last
  for (let i = 0; i < K - 1; i++) {
    asm.pick('share', 'sh' + i); asm.num2bin(8, 'sv' + i); asm.data(chunks[i], 'c' + i); asm.cat('out' + i)
  }
  asm.pick('last', 'lastV'); asm.num2bin(8, 'lv'); asm.data(chunks[K - 1], 'cL'); asm.cat('out' + (K - 1))
  asm.pick('out0', 'acc')
  for (let i = 1; i < K; i++) { asm.pick('out' + i, 'o' + i); asm.cat('acc') }
  asm.bindOutput('acc')
}

function buildScript ({ question, owners, m = 2, panelN, fee = DEFAULT_FEE, deadline = DEFAULT_DEADLINE }) {
  const q = buf(question)
  if (q.length !== QUESTION_BYTES) throw new Error('question must be 32 bytes')
  if (!Array.isArray(owners) || owners.length < 2) throw new Error('a categorical market needs at least two outcome owners')
  const chunks = owners.map((o) => { const p = pkhOf(o); if (p.length !== 20) throw new Error('each owner must be a 20-byte pkh'); return p2pkhChunk(p) })
  const moduli = (panelN || PANEL_N).map((x) => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)

  const s = new Script()
  C.authenticateThenBranch(s)                      // authenticate once; outputs bound → SIGHASH_ALL

  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)

  const settle = new StackAsm(s); settle.main = ['outcome4', ...slots, 'preimage']
  settleBody(settle, { q, chunks, moduli, m, fee })
  while (settle.main.length) settle.drop()
  settle.raw(Opcode.OP_1, 0, ['ok'])
  const d = settle.main.length

  s.add(Opcode.OP_ELSE)
  const refund = new StackAsm(s); refund.main = ['preimage']
  refundBody(refund, { chunks, fee, deadline })
  while (refund.main.length) refund.drop()
  refund.raw(Opcode.OP_1, 0, ['ok'])
  if (refund.main.length !== d) throw new Error(`marketN: branches leave different depths (${d} vs ${refund.main.length})`)
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
  name: 'marketN',
  describe: 'a fully-collateralised N-outcome (categorical) prediction market: an m-of-n oracle quorum names the winning outcome, the whole pot goes to its owner, or an equal K-way refund after a deadline',
  example: () => ({
    question: Buffer.alloc(32, 7),
    owners: [Buffer.alloc(20, 1), Buffer.alloc(20, 2), Buffer.alloc(20, 3)],
    m: 2, signers: [0, 1], attestOutcome: 1
  }),

  QUESTION_BYTES,
  DUST,
  DEFAULT_FEE,
  DEFAULT_DEADLINE,
  PANEL_N,
  buildScript,
  oracleMessage,
  attestWith,
  p2pkhChunk,
  pkhOf,

  unlockDefaults: { sequenceNumber: 0xfffffffe },

  lock (tc) {
    if (!tc.question || !tc.owners) throw new Error('question and owners are required')
    return buildScript({ question: tc.question, owners: tc.owners, m: tc.m, panelN: tc.panelN, fee: tc.fee, deadline: tc.deadline })
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const pot = tc.satoshis - fee
    const K = tc.owners.length
    if ((tc.branch || 'settle') === 'refund') {
      const share = Math.floor(pot / K); const last = pot - share * (K - 1)
      if (tc.actualOutputs) return tc.actualOutputs({ fee, pot, share, last })
      return tc.owners.map((o, i) => helpers.p2pkhOutput(addrOf(pkhOf(o)), i === K - 1 ? last : share))
    }
    const o = tc.forgeOutcome !== undefined ? tc.forgeOutcome : tc.attestOutcome
    const winner = pkhOf(tc.owners[o] ?? tc.owners[0])   // out-of-range o is the SCRIPT's to refuse, not a JS crash
    if (tc.actualOutputs) return tc.actualOutputs({ fee, pot })
    return [helpers.p2pkhOutput(addrOf(winner), pot)]
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
      us.add(Opcode.OP_1).add(preimage)
      return us
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
