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

// BULLETIN — a REUSABLE, oracle-quorum-established outcome fact. It is [`resolution`](resolution)
// made persistent: it begins OPEN, the quorum moves it once to RESOLVED, and thereafter it
// RECREATES ITSELF on every spend, unchanged, so it lives on as a co-spendable reference. This
// is the enabler for markets of MANY positions: one bulletin, settled by no one's permission
// and everyone's agreement, can be co-spent by any number of position coins that read the
// committed outcome out of it — no position ever consumes the fact, because the bulletin
// re-emits itself every time it is touched.
//
//   state = question(32) ‖ status(1) ‖ outcome(1)          (always at output 0 of its tx)
//
//   resolve   OPEN → RESOLVED, where Σ valid_i(sig_i over question‖outcome under N_i) ≥ m
//             and o ∈ {0,1}. The question is spliced UNCHANGED; the successor is RESOLVED(o).
//   read      RESOLVED → RESOLVED, the whole coin recreated byte-for-byte (minus a fee).
//             Permissionless — any transaction may co-spend the bulletin to reference the
//             outcome, and the covenant forces the fact to persist at output 0.
//
// Because the read branch recreates the coin identically, the outcome can never change once
// resolved, and the bulletin's OWN covenant runs on every hop — so a position that co-spends
// it and reads output 0 is reading a fact the chain, not the spender, guarantees.

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map((k) => BigInt(k.n))
const PANEL_KEYS = PANEL.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const QUESTION_BYTES = 32
const STATUS_BYTES = 1
const OUTCOME_BYTES = 1
const STATE_BYTES = QUESTION_BYTES + STATUS_BYTES + OUTCOME_BYTES   // 34, push-op 0x22
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const OUTCOME_MSG_BYTES = 4
// where the outcome byte sits inside output 0: value(8) ‖ scriptVarint(3) ‖ push-op(1) ‖ question(32) ‖ status(1)
const OUTCOME_OFFSET = 8 + VARINT_BYTES + 1 + QUESTION_BYTES + STATUS_BYTES   // 45
const QUESTION_OFFSET = 8 + VARINT_BYTES + 1                                   // 12
const DEFAULT_FEE = 250
const DUST = 2000

const OPEN = 0
const RESOLVED = 1

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function outcomeLE (o) { const b = Buffer.alloc(OUTCOME_MSG_BYTES); b.writeUInt32LE(o >>> 0, 0); return b }
function oracleMessage (question, o) { return Buffer.concat([buf(question), outcomeLE(o)]) }
function state (question, status, outcome) { return Buffer.concat([buf(question), Buffer.from([status]), Buffer.from([outcome])]) }

function readState (asm) {
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(QUESTION_BYTES, 'question', 'r2')
  asm.splitAt(STATUS_BYTES, 'status1', 'r3')
  asm.splitAt(OUTCOME_BYTES, 'outcome1', 'tail')
}
function requireStatus (asm, want) {
  asm.pick('status1'); asm.bin2num('st#'); asm.num(want, 'want'); asm.numEqualVerify()
}

// OPEN → RESOLVED, gated by the oracle quorum.
function resolveBody (asm, { moduli, m, fee }) {
  const N = moduli.length
  readState(asm)
  requireStatus(asm, OPEN)

  asm.pick('outcome4'); asm.bin2num('o')
  asm.pick('o'); asm.num(OPEN, 'z'); asm.numEqual('is0')
  asm.pick('o'); asm.num(RESOLVED, 'one'); asm.numEqual('is1')
  asm.raw(Opcode.OP_BOOLOR, 2, ['inRange']); asm.verify()

  asm.pick('question'); asm.pick('outcome4'); asm.cat('omsg')
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'omsg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()

  // successor: question UNCHANGED, status → RESOLVED, outcome → o (its low byte)
  asm.pick('outcome4'); asm.splitAt(1, 'ocLo', 'ocHi')
  asm.pick('question'); asm.num(RESOLVED, 'rb'); asm.cat('qs')
  asm.pick('ocLo'); asm.cat('newState')
  asm.pick('header'); asm.pick('newState'); asm.cat('hn')
  asm.pick('tail'); asm.cat('newChunk')
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('nextOutput')
  asm.bindOutput('nextOutput')
}

// RESOLVED → RESOLVED, recreated byte-for-byte at OUTPUT 0 (minus fee). Permissionless.
// A `pTail` of arbitrary trailing outputs is allowed and unverified, so any number of
// position coins can be co-settled in the same transaction — their payouts ride in the
// tail while the bulletin is forced to persist unchanged at output 0 (cf. pitfall 26).
function readBody (asm, { fee }) {
  readState(asm)
  requireStatus(asm, RESOLVED)
  // rebuild the whole coin unchanged: header ‖ question ‖ status ‖ outcome ‖ tail
  asm.pick('header'); asm.pick('question'); asm.cat('hq')
  asm.pick('status1'); asm.cat('hqs'); asm.pick('outcome1'); asm.cat('hqso')
  asm.pick('tail'); asm.cat('newChunk')
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('output0')
  // full outputs = output0 (the recreated bulletin) ‖ pTail (the position payouts, free)
  asm.pick('output0'); asm.pick('pTail'); asm.cat('allOuts'); asm.hash256('oh')
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['hoField'])
  asm.nip(); asm.equalVerify()
}

function buildScript ({ question, status = OPEN, outcome = 0, m = 2, panelN, fee = DEFAULT_FEE }) {
  const q = buf(question)
  if (q.length !== QUESTION_BYTES) throw new Error('question must be 32 bytes')
  const moduli = (panelN || PANEL_N).map((x) => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)

  const s = new Script()
  s.add(state(q, status, outcome)).add(Opcode.OP_DROP)
  C.authenticateThenBranch(s)

  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)
  const rv = new StackAsm(s); rv.main = ['outcome4', ...slots, 'preimage']
  resolveBody(rv, { moduli, m, fee })
  while (rv.main.length) rv.drop()
  rv.raw(Opcode.OP_1, 0, ['ok'])
  const d = rv.main.length

  s.add(Opcode.OP_ELSE)
  const rd = new StackAsm(s); rd.main = ['pTail', 'preimage']
  readBody(rd, { fee })
  while (rd.main.length) rd.drop()
  rd.raw(Opcode.OP_1, 0, ['ok'])
  if (rd.main.length !== d) throw new Error(`bulletin: branches leave different depths (${d} vs ${rd.main.length})`)
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
  name: 'bulletin',
  describe: 'a reusable, oracle-quorum-established outcome fact: OPEN→RESOLVED once, then recreates itself on every spend so any number of positions can read the committed outcome without consuming it',
  example: () => ({ question: Buffer.alloc(32, 7), m: 2, signers: [0, 1], attestOutcome: 1, branch: 'resolve' }),

  QUESTION_BYTES,
  STATE_BYTES,
  HEAD_BYTES,
  OUTCOME_OFFSET,
  QUESTION_OFFSET,
  DUST,
  DEFAULT_FEE,
  OPEN,
  RESOLVED,
  PANEL_N,
  buildScript,
  state,
  oracleMessage,
  attestWith,

  lock (tc) {
    if (!tc.question) throw new Error('question is required')
    return buildScript({ question: tc.question, status: tc.status ?? OPEN, outcome: tc.outcome ?? 0, m: tc.m, panelN: tc.panelN, fee: tc.fee })
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const branch = tc.branch || 'resolve'
    const o = branch === 'read' ? (tc.outcome ?? 0) : (tc.forgeOutcome !== undefined ? tc.forgeOutcome : tc.attestOutcome)
    const status = RESOLVED
    const script = buildScript({ question: tc.question, status, outcome: o, m: tc.m, panelN: tc.panelN, fee })
    if (tc.actualOutputs) return tc.actualOutputs({ fee, script })
    return [new bsv.Transaction.Output({ script, satoshis: tc.satoshis - fee }), ...(tc.tailOutputs || [])]
  },

  continuation (tc) {
    const branch = tc.branch || 'resolve'
    const o = branch === 'read' ? (tc.outcome ?? 0) : tc.attestOutcome
    const params = { question: buf(tc.question).toString('hex'), status: RESOLVED, outcome: o, m: tc.m, fee: tc.fee ?? DEFAULT_FEE }
    return { script: buildScript(params), params }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const branch = tc.branch || 'resolve'
    const N = (tc.panelN || PANEL_N).length

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue

      if (branch === 'read') {
        const pTail = tc.pTail && tc.pTail.length ? tc.pTail : Buffer.alloc(0)
        return new Script().add(pTail).add(Opcode.OP_0).add(preimage)
      }

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
