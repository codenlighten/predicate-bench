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

// RESOLUTION — the keystone of a prediction market: an on-chain object that begins
// OPEN and can move exactly once to RESOLVED, carrying the outcome an oracle QUORUM
// attested. It is a [lifecycle] state machine (an immutable core, a bounded status,
// a terminal state) whose one transition is gated not by an owner's signature but by
// [quorum] — m of n independent Rabin oracles must attest the SAME outcome for THIS
// question before the object may resolve.
//
//   state = question(32) ‖ status(1) ‖ outcome(1) ‖ resolver(20)
//
//   resolve   OPEN -> RESOLVED, where the outcome is a value o ∈ {0, 1} that at least
//             m panel oracles signed together with this question. The question and the
//             resolver are spliced UNCHANGED into the successor (the immutable core);
//             the successor is RESOLVED with outcome = o. No key authorises this — the
//             quorum does. This is why a market can be settled by no one's permission
//             and everyone's agreement.
//   sweep     once RESOLVED, the resolver may sweep the remaining dust (the exit). The
//             RESOLVED fact lives on in the transaction that produced it — the history
//             a position proves descent from — so sweeping later does not erase it.
//
// The two properties that make it sound are inherited from its parts:
//   - The outcome the successor commits to is exactly the value the oracles signed:
//     the covenant builds the oracle message from its OWN question field and the
//     presented outcome, so a resolver cannot record an outcome the quorum did not attest.
//   - RESOLVED is terminal on the resolve path (its first byte can never begin an OPEN
//     transition again), so a market cannot be re-resolved to flip a settled outcome.
//
// This is the first covenant whose transition authority is a THRESHOLD of external
// attestations rather than a signature — split trust as a state-machine guard.

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map((k) => BigInt(k.n))
const PANEL_KEYS = PANEL.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const QUESTION_BYTES = 32
const STATUS_BYTES = 1
const OUTCOME_BYTES = 1
const RESOLVER_BYTES = 20
const STATE_BYTES = QUESTION_BYTES + STATUS_BYTES + OUTCOME_BYTES + RESOLVER_BYTES // 54
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1                 // 3-byte varint ‖ 1-byte state push-op (54 < 76)
const OUTCOME_MSG_BYTES = 4                          // the value the oracles sign, 4-byte LE
const DUST = 2000
const DEFAULT_FEE = 250
const P2PKH_PRE = Buffer.from('1976a914', 'hex')
const P2PKH_POST = Buffer.from('88ac', 'hex')

const OPEN = 0
const RESOLVED = 1

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string' && /^[0-9a-fA-F]{40}$/.test(a)) return Buffer.from(a, 'hex')
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function outcomeLE (o) { const b = Buffer.alloc(OUTCOME_MSG_BYTES); b.writeUInt32LE(o >>> 0, 0); return b }
function oracleMessage (question, o) { return Buffer.concat([buf(question), outcomeLE(o)]) }

function state (question, status, outcome, resolver) {
  return Buffer.concat([buf(question), Buffer.from([status]), Buffer.from([outcome]), pkhOf(resolver)])
}

// read our own state out of the preimage: [.., preimage, question, status1, outcome1, resolver, tail]
function readState (asm) {
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(QUESTION_BYTES, 'question', 'r2')
  asm.splitAt(STATUS_BYTES, 'status1', 'r3')
  asm.splitAt(OUTCOME_BYTES, 'outcome1', 'resolver_tail')
  asm.splitAt(RESOLVER_BYTES, 'resolver', 'tail')
}

// status1 (a raw byte) numerically equals `want` — via bin2num so 0x00 == 0 (pitfall 12).
function requireStatus (asm, want) {
  asm.pick('status1'); asm.bin2num('st#'); asm.num(want, 'want'); asm.numEqualVerify()
}

// OPEN -> RESOLVED, gated by the oracle quorum.
function resolveBody (asm, { moduli, m, fee }) {
  const N = moduli.length
  readState(asm)
  requireStatus(asm, OPEN)

  // the presented outcome must be a value the market admits: o ∈ {0, 1}
  asm.pick('outcome4'); asm.bin2num('o')
  asm.pick('o'); asm.num(OPEN, 'z'); asm.numEqual('is0')
  asm.pick('o'); asm.num(RESOLVED, 'one'); asm.numEqual('is1')
  asm.raw(Opcode.OP_BOOLOR, 2, ['inRange']); asm.verify()

  // the oracle message is built from OUR question and the presented outcome, so the
  // quorum is bound to THIS question and cannot be replayed onto another.
  asm.pick('question'); asm.pick('outcome4'); asm.cat('omsg')

  // Σ valid_i(sig_i over question‖outcome under N_i) ≥ m — the same count as [quorum]
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'omsg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()

  // successor: question UNCHANGED, status -> RESOLVED, outcome -> o (its low byte),
  // resolver UNCHANGED. o ∈ {0,1} so outcome4's first byte is exactly the outcome byte.
  asm.pick('outcome4'); asm.splitAt(1, 'ocLo', 'ocHi')
  asm.pick('question'); asm.num(RESOLVED, 'rb'); asm.cat('qs')
  asm.pick('ocLo'); asm.cat('qso')
  asm.pick('resolver'); asm.cat('newState')
  asm.pick('header'); asm.pick('newState'); asm.cat('hn')
  asm.pick('tail'); asm.cat('newChunk')
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('nextOutput')
  asm.bindOutput('nextOutput')
}

// once RESOLVED, the resolver sweeps the dust — the exit (pitfall 18).
function sweepBody (asm, { fee }) {
  readState(asm)
  requireStatus(asm, RESOLVED)
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('resolver'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.data(P2PKH_PRE, 'pre'); asm.pick('resolver'); asm.cat('rk1'); asm.data(P2PKH_POST, 'post'); asm.cat('resolverChunk')
  asm.cat('sweepOutput')
  asm.bindOutput('sweepOutput')
}

function buildScript ({ question, status = OPEN, outcome = 0, resolver, m = 2, panelN, fee = DEFAULT_FEE }) {
  const q = buf(question); const res = pkhOf(resolver)
  if (q.length !== QUESTION_BYTES) throw new Error('question must be 32 bytes')
  if (res.length !== RESOLVER_BYTES) throw new Error('resolver must be a 20-byte pkh')
  const moduli = (panelN || PANEL_N).map((x) => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)

  const s = new Script()
  s.add(state(q, status, outcome, res)).add(Opcode.OP_DROP)
  C.authenticateThenBranch(s)

  // resolve branch: [outcome4, sig0, pad0, … sig_{N-1}, pad_{N-1}, preimage]
  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)
  const rv = new StackAsm(s); rv.main = ['outcome4', ...slots, 'preimage']
  resolveBody(rv, { moduli, m, fee })
  while (rv.main.length) rv.drop()
  rv.raw(Opcode.OP_1, 0, ['ok'])
  const rvDepth = rv.main.length

  s.add(Opcode.OP_ELSE)
  const sw = new StackAsm(s); sw.main = ['pubkey', 'sig', 'preimage']
  sweepBody(sw, { fee })
  while (sw.main.length) sw.drop()
  sw.raw(Opcode.OP_1, 0, ['ok'])
  if (sw.main.length !== rvDepth) throw new Error(`resolution: branches leave different depths (${rvDepth} vs ${sw.main.length})`)
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
  name: 'resolution',
  describe: 'an OPEN→RESOLVED market outcome, gated by an m-of-n oracle quorum; the transition authority is a threshold of attestations, not a key',
  example: () => ({
    question: Buffer.alloc(32, 7), resolver: Buffer.alloc(20, 2),
    m: 2, signers: [0, 1], attestOutcome: 1, branch: 'resolve'
  }),

  QUESTION_BYTES,
  STATE_BYTES,
  HEAD_BYTES,
  DUST,
  DEFAULT_FEE,
  OPEN,
  RESOLVED,
  PANEL_N,
  buildScript,
  state,
  oracleMessage,
  attestWith,
  pkhOf,

  lock (tc) {
    if (!tc.question || !tc.resolver) throw new Error('question and resolver are required')
    return buildScript({ question: tc.question, status: tc.status ?? OPEN, outcome: tc.outcome ?? 0, resolver: tc.resolver, m: tc.m, panelN: tc.panelN, fee: tc.fee })
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    if ((tc.branch || 'resolve') === 'sweep') {
      const res = pkhOf(tc.resolver)
      if (tc.actualOutputs) return tc.actualOutputs({ fee, res })
      return [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(res), tc.satoshis - fee)]
    }
    const o = tc.forgeOutcome !== undefined ? tc.forgeOutcome : tc.attestOutcome
    const succResolver = tc.tamperResolver ? pkhOf(tc.tamperResolver) : pkhOf(tc.resolver)  // tamper: change the immutable core
    const succQuestion = tc.tamperQuestion || tc.question
    const script = buildScript({ question: succQuestion, status: RESOLVED, outcome: o, resolver: succResolver, m: tc.m, panelN: tc.panelN, fee })
    if (tc.actualOutputs) return tc.actualOutputs({ fee, script })
    return [new bsv.Transaction.Output({ script, satoshis: tc.satoshis - fee })]
  },

  continuation (tc) {
    if ((tc.branch || 'resolve') === 'sweep') return null
    const o = tc.forgeOutcome !== undefined ? tc.forgeOutcome : tc.attestOutcome   // match outputs()
    const params = { question: buf(tc.question).toString('hex'), status: RESOLVED, outcome: o, resolver: pkhOf(tc.resolver).toString('hex'), m: tc.m, fee: tc.fee ?? DEFAULT_FEE }
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

      if (branch === 'sweep') {
        const priv = tc.resolverKey || tc.key
        const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
        const pub = priv.publicKey.toBuffer()
        return new Script().add(pub).add(sig).add(Opcode.OP_0).add(preimage)
      }

      // resolve: the value the oracles signed (may differ from the presented value in a forge test)
      const signed = tc.attestOutcome
      const presented = tc.forgeOutcome !== undefined ? tc.forgeOutcome : signed

      // slotKeys[i] = which panel key signs slot i (null = a dummy that counts as 0)
      const slotKeys = tc.slotKeys || (() => {
        const a = new Array(N).fill(null); (tc.signers || []).forEach((idx) => { a[idx] = idx }); return a
      })()
      const attestFeedOutcome = tc.attestOutcome    // oracles sign this outcome…
      const attestQuestion = tc.attestQuestion || tc.question   // …for this question (mismatch => quorum fails)

      const us = new Script()
      us.add(outcomeLE(presented))
      for (let i = 0; i < N; i++) {
        const k = slotKeys[i]
        if (k === null || k === undefined) {
          us.add(Buffer.from([0])).add(Buffer.from([0, 0]))     // dummy sig + pad => check() = 0
        } else {
          const a = attestWith(PANEL_KEYS[k], attestQuestion, attestFeedOutcome)
          us.add(a.sig).add(a.pad2)
        }
      }
      us.add(Opcode.OP_1).add(preimage)
      return us
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
