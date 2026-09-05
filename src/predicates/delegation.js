'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// DELEGATION — authority as a DIVISIBLE, INDUCTIVE budget.
//
// `token` conserved a value across a merge; `lifecycle` made authority a field.
// This composes both: a capability carrying a quantitative budget that a holder
// may split into children, each child itself delegable, with the tree-wide
// invariant that the SUM of every budget never exceeds the root's — enforced one
// hop at a time, so it holds for the whole tree by induction.
//
//   state = root(32) ‖ budget(4) ‖ owner(20)
//
//   delegate   owner splits off a child of budget b (1 ≤ b ≤ budget): the node
//              recreates itself carrying budget − b, and a NEW node carries b
//              under a delegate's key. Two outputs, in order (self, child); their
//              budgets sum to exactly the old budget, so the split conserves.
//   exercise   owner consumes c units (1 ≤ c ≤ budget); the node recreates with
//              budget − c. This is the capability being USED — the leaf case is a
//              use-counter (budget = remaining uses), spent down to nothing.
//   revoke     owner sweeps the remainder and stops (the exit).
//
// `root` is spliced UNCHANGED into every successor — every node in the tree
// proves descent from the same authority ([`lineage`](lineage) immutability),
// while its budget moves within bounds ([`lifecycle`](lifecycle)). Because a
// child's budget is carved out of the parent's and the parent recreates with the
// remainder, no path can conjure authority the root never granted: Σ ≤ root, on
// chain.

const ROOT_BYTES = 32
const BUDGET_BYTES = 4
const OWNER_BYTES = 20
const STATE_BYTES = ROOT_BYTES + BUDGET_BYTES + OWNER_BYTES   // 56, push-op 0x38
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const CHILD_SATS = 1200          // fixed gas a delegated child is funded with
const DEFAULT_FEE = 350
const P2PKH_PRE = Buffer.from('1976a914', 'hex')
const P2PKH_POST = Buffer.from('88ac', 'hex')

const DELEGATE = 0
const EXERCISE = 1
const REVOKE = 2

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  return /^[0-9a-f]{40}$/i.test(a) ? Buffer.from(a, 'hex') : hash160Of(a)
}
function budgetLE (v) { const b = Buffer.alloc(BUDGET_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function satsLE (v) { const b = Buffer.alloc(8); b.writeUIntLE(v, 0, 6); return b }
function state (root, budget, owner) {
  return Buffer.concat([buf(root), budgetLE(budget), pkhOf(owner)])
}

// preimage-field readers: pull the parked preimage off the alt stack, extract a
// field, re-park it — the same trick `token`/`asset` use to authenticate once.
const F_VALUE = (x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8)
const F_HASHOUTPUTS = (x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32)
function readField (asm, fn, name) {
  asm.fromAlt(); asm.clause(fn, 0, [name]); asm.swap(); asm.toAlt()
}
function readState (asm) {
  readField(asm, C.selfChunk, 'chunk')
  asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(ROOT_BYTES, 'root', 'r2')
  asm.splitAt(BUDGET_BYTES, 'budget4', 'r3')
  asm.splitAt(OWNER_BYTES, 'owner', 'tail')
}
function requireOwnerSig (asm) {
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('owner'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
}
// node script = header ‖ root ‖ budget4 ‖ ownerField ‖ tail — same width every hop
function nodeScript (asm, budgetName, ownerName, out) {
  asm.pick('header'); asm.pick('root'); asm.cat(out + '_a')
  asm.pick(budgetName); asm.cat(out + '_b')
  asm.pick(ownerName); asm.cat(out + '_c')
  asm.pick('tail'); asm.cat(out)
}
function bindHashOutputs (asm, outsName) {
  asm.pick(outsName); asm.hash256('oh')
  readField(asm, F_HASHOUTPUTS, 'ho'); asm.equalVerify()
}
function finishBranch (asm) {
  while (asm.main.length) asm.drop()
  asm.fromAlt(); asm.drop()
  asm.raw(Opcode.OP_1, 0, ['true'])
}

function emitDelegate (asm, { fee }) {
  readState(asm)
  requireOwnerSig(asm)
  // b = the child's budget (4-byte LE from the spender); 1 ≤ b ≤ budget
  asm.pick('childBudget4'); asm.size('bsz'); asm.num(BUDGET_BYTES, 'bb'); asm.equalVerify()
  asm.pick('childBudget4'); asm.bin2num('b')
  asm.pick('b'); asm.num(1, 'one'); asm.geVerify()
  asm.pick('budget4'); asm.bin2num('P')
  asm.pick('b'); asm.pick('P'); asm.leVerify()
  // the node keeps budget − b — this is the conservation: (P−b) + b = P
  asm.pick('P'); asm.pick('b'); asm.sub('keepNum'); asm.num2bin(BUDGET_BYTES, 'keep4')
  // delegate key is a 20-byte pkh
  asm.pick('delegate'); asm.size('dsz'); asm.num(OWNER_BYTES, 'ob'); asm.equalVerify()
  // self output: value − fee − CHILD_SATS ‖ recreated node (same owner, reduced budget)
  readField(asm, F_VALUE, 'value8'); asm.bin2num('V')
  asm.pick('V'); asm.num(fee + CHILD_SATS, 'fc'); asm.sub('selfV')
  asm.pick('selfV'); asm.num(1, 'one2'); asm.geVerify()
  asm.pick('selfV'); asm.num2bin(8, 'selfValue8')
  nodeScript(asm, 'keep4', 'owner', 'selfScript')
  asm.pick('selfValue8'); asm.pick('selfScript'); asm.cat('selfOut')
  // child output: fixed CHILD_SATS ‖ new node (delegate owner, budget b)
  asm.data(satsLE(CHILD_SATS), 'childValue8'); nodeScript(asm, 'childBudget4', 'delegate', 'childScript')
  asm.pick('childValue8'); asm.pick('childScript'); asm.cat('childOut')
  // outputs are ordered: self first, then child (hashOutputs commits to order)
  asm.pick('selfOut'); asm.pick('childOut'); asm.cat('outs')
  bindHashOutputs(asm, 'outs')
  finishBranch(asm)
}

function emitExercise (asm, { fee }) {
  readState(asm)
  requireOwnerSig(asm)
  // c = units consumed (4-byte LE); 1 ≤ c ≤ budget
  asm.pick('spend4'); asm.size('csz'); asm.num(BUDGET_BYTES, 'bb'); asm.equalVerify()
  asm.pick('spend4'); asm.bin2num('c')
  asm.pick('c'); asm.num(1, 'one'); asm.geVerify()
  asm.pick('budget4'); asm.bin2num('P')
  asm.pick('c'); asm.pick('P'); asm.leVerify()
  asm.pick('P'); asm.pick('c'); asm.sub('leftNum'); asm.num2bin(BUDGET_BYTES, 'left4')
  // single output: value − fee ‖ recreated node (same owner, budget − c)
  readField(asm, F_VALUE, 'value8'); asm.bin2num('V')
  asm.pick('V'); asm.num(fee, 'f'); asm.sub('selfV'); asm.num2bin(8, 'selfValue8')
  nodeScript(asm, 'left4', 'owner', 'selfScript')
  asm.pick('selfValue8'); asm.pick('selfScript'); asm.cat('selfOut')
  bindHashOutputs(asm, 'selfOut')
  finishBranch(asm)
}

function emitRevoke (asm, { fee }) {
  readState(asm)
  requireOwnerSig(asm)
  readField(asm, F_VALUE, 'value8'); asm.bin2num('V')
  asm.pick('V'); asm.num(fee, 'f'); asm.sub('outV'); asm.num2bin(8, 'outValue8')
  asm.data(P2PKH_PRE, 'pre'); asm.pick('owner'); asm.cat('op1'); asm.data(P2PKH_POST, 'post'); asm.cat('ownerChunk')
  asm.pick('outValue8'); asm.pick('ownerChunk'); asm.cat('revokeOut')
  bindHashOutputs(asm, 'revokeOut')
  finishBranch(asm)
}

function buildScript ({ root, budget, owner, fee = DEFAULT_FEE }) {
  const r = buf(root); const o = pkhOf(owner)
  if (r.length !== ROOT_BYTES) throw new Error('root must be 32 bytes')
  if (o.length !== OWNER_BYTES) throw new Error('owner must be a 20-byte pkh')

  const s = new Script()
  s.add(state(r, budget, o)).add(Opcode.OP_DROP)
  C.authenticate(s)                                         // preimage proven, on top
  s.add(Opcode.OP_TOALTSTACK)                               // park it; selector on top

  s.add(Opcode.OP_DUP).add(n(DELEGATE)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  emitDelegate(new StackAsm(s).given(['childBudget4', 'delegate', 'sig', 'pubkey']).seedAlt(['preimage']), { fee })
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DUP).add(n(EXERCISE)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  emitExercise(new StackAsm(s).given(['spend4', 'sig', 'pubkey']).seedAlt(['preimage']), { fee })
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DROP)                                     // REVOKE (default)
  emitRevoke(new StackAsm(s).given(['sig', 'pubkey']).seedAlt(['preimage']), { fee })
  s.add(Opcode.OP_ENDIF)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

const A = bsv.PrivateKey.fromRandom()
const B = bsv.PrivateKey.fromRandom()

module.exports = {
  name: 'delegation',
  describe: 'a divisible, inductive authority budget: delegate a child, exercise a use, revoke — Σ budgets ≤ root',
  example: () => ({ root: Buffer.alloc(32, 1), budget: 100, owner: A.toAddress().toString(), ownerKey: A, branch: 'delegate', childBudget: 40, delegate: B.toAddress().toString() }),

  ROOT_BYTES,
  BUDGET_BYTES,
  CHILD_SATS,
  DEFAULT_FEE,
  DELEGATE,
  EXERCISE,
  REVOKE,
  buildScript,
  state,
  budgetLE,
  pkhOf,

  lock (tc) {
    if (!tc.root || tc.budget === undefined || !tc.owner) throw new Error('root, budget and owner are required')
    return buildScript(tc)
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const branch = tc.branch || 'delegate'
    const root = buf(tc.root)
    const owner = pkhOf(tc.owner)
    if (tc.actualOutputs) return tc.actualOutputs({ fee, root, owner })
    if (branch === 'revoke') {
      return [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(owner), tc.satoshis - fee)]
    }
    if (branch === 'exercise') {
      const left = tc.budget - tc.spend
      const script = buildScript({ root, budget: left, owner, fee })
      return [new bsv.Transaction.Output({ script, satoshis: tc.satoshis - fee })]
    }
    // delegate: [ self (budget − b), child (b) ]
    const keep = tc.budget - tc.childBudget
    const selfScript = buildScript({ root, budget: keep, owner, fee })
    const childScript = buildScript({ root, budget: tc.childBudget, owner: pkhOf(tc.delegate), fee })
    return [
      new bsv.Transaction.Output({ script: selfScript, satoshis: tc.satoshis - fee - CHILD_SATS }),
      new bsv.Transaction.Output({ script: childScript, satoshis: CHILD_SATS })
    ]
  },

  // Only the SELF successor is auto-recorded on chain; the delegated child is a
  // second covenant output and the driver records it explicitly.
  continuation (tc) {
    const branch = tc.branch || 'delegate'
    if (branch === 'revoke') return null
    const fee = tc.fee ?? DEFAULT_FEE
    const root = buf(tc.root).toString('hex')
    const owner = pkhOf(tc.owner).toString('hex')
    const budget = branch === 'exercise' ? tc.budget - tc.spend : tc.budget - tc.childBudget
    const params = { root, budget, owner, fee }
    return { script: buildScript(params), params }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const priv = tc.ownerKey || tc.key
    const branch = tc.branch || 'delegate'
    const pub = (tc.wrongPubkey || priv).publicKey.toBuffer()
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      if (branch === 'revoke') {
        return new Script().add(sig).add(pub).add(n(REVOKE)).add(preimage)
      }
      if (branch === 'exercise') {
        const spend4 = tc.presentSpend4 || budgetLE(tc.spend)
        return new Script().add(spend4).add(sig).add(pub).add(n(EXERCISE)).add(preimage)
      }
      const childBudget4 = tc.presentChild4 || budgetLE(tc.childBudget)
      const delegate = pkhOf(tc.delegate)
      return new Script().add(childBudget4).add(delegate).add(sig).add(pub).add(n(DELEGATE)).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
