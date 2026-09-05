'use strict'

const bsv = require('@smartledger/bsv')
const C = require('./clauses')
const covsteps = require('./covsteps')
const { leanCore } = require('./pushtx')
const { StackAsm } = require('./stackasm')
const Opcode = bsv.Opcode
const n = require('@smartledger/bsv/lib/covenant/helpers').scriptNum

// A predicate, as DATA — and a compiler that turns the bench's hardest-won
// pitfalls into COMPILE-TIME guarantees.
//
// StackAsm made a covenant's body writable without hand-counting stack depths.
// This is the layer above it: a predicate is a spec — a linear clause list, or a
// leading state field and two branch bodies — plus declared intent, and `compile`
// (a) refuses any spec that violates an invariant a real broadcast taught us, then
// (b) emits the exact bytes. The codegen is deliberately thin — every step is a
// clause already proven correct and deployed, and the branch-body steps live in
// src/covsteps.js, shared with the predicates themselves — so correctness is
// inherited and the compiler's value is entirely in what it REFUSES.
//
// The proof it is faithful, not a re-implementation, is byte identity: the specs
// in this repo compile to the SAME locking scripts the predicates build
// (tools/compile-selftest.js), including the branching, stateful ones.

const SIGHASH_ALL_FORKID = 0x41
const SIGHASH_SINGLE_ACP_FORKID = 0xc3   // SINGLE | ANYONECANPAY | FORKID — deliberate open-endedness

// Each step: how it emits (to a Script, or to a StackAsm), and what it declares
// about commitment and stack. `binds:'outputs'`, `selfRecreates`, `exit`,
// `terminal` are what the invariant pass reads.
const STEPS = {
  // --- preamble / linear-body steps ---
  auth: { emit: (s) => C.authenticate(s), bakesFlag: 'all' },
  authOpen: {
    emit: (s) => { s.add(Opcode.OP_DUP); leanCore(s, { sighashType: SIGHASH_SINGLE_ACP_FORKID }); s.add(Opcode.OP_VERIFY) },
    bakesFlag: 'open'
  },
  assertSighashAll: { emit: (s) => C.requireSighashAll(s) },
  requireOutputs: { emit: (s, { expected }) => C.requireOutputs(s, expected), binds: 'outputs' },
  recreateSelfMinusFee: {
    emit: (s, { fee }) => {
      C.selfChunk(s); s.add(Opcode.OP_OVER); C.newValueLE(s, fee)
      s.add(Opcode.OP_SWAP).add(Opcode.OP_CAT); C.requireOutputIs(s)
    },
    binds: 'outputs', selfRecreates: true, terminal: true
  },
  dropTrue: { emit: (s) => s.add(Opcode.OP_DROP).add(Opcode.OP_1), terminal: true },

  // --- metered branch steps (raw Script) ---
  meteredReadCounterKeep: { emit: (s, p) => covsteps.meteredReadCounterKeep(s, p) },
  meteredGuardBelow: { emit: (s, p) => covsteps.meteredGuardBelow(s, p) },
  meteredIncrementRecreate: { emit: (s, p) => covsteps.meteredIncrementRecreate(s, p), binds: 'outputs', selfRecreates: true },
  meteredReadCounterDrop: { emit: (s, p) => covsteps.meteredReadCounterDrop(s, p) },
  meteredGuardAtLeast: { emit: (s, p) => covsteps.meteredGuardAtLeast(s, p) },
  meteredPayFixed: { emit: (s, p) => covsteps.meteredPayFixed(s, p), binds: 'outputs', exit: true },

  // --- vesting branch steps (StackAsm), gate → read → compute → guard → pay ---
  vestGate: { emitAsm: (a, p) => covsteps.vestGate(a, p) },
  vestReadValueParkChunk: { emitAsm: (a, p) => covsteps.vestReadValueParkChunk(a, p) },
  vestReadValueOnly: { emitAsm: (a, p) => covsteps.vestReadValueOnly(a, p) },
  vestComputeUnvested: { emitAsm: (a, p) => covsteps.vestComputeUnvested(a, p) },
  vestGuardVesting: { emitAsm: (a, p) => covsteps.vestGuardVesting(a, p) },
  vestGuardVested: { emitAsm: (a, p) => covsteps.vestGuardVested(a, p) },
  vestPayWithdraw: { emitAsm: (a, p) => covsteps.vestPayWithdraw(a, p), binds: 'outputs', selfRecreates: true },
  vestPayFinish: { emitAsm: (a, p) => covsteps.vestPayFinish(a, p), binds: 'outputs', exit: true },

  // --- token: merge (backtrace) and split (StackAsm, self-terminating bodies) ---
  tokMergeReadSelf: { emitAsm: (a) => covsteps.tokMergeReadSelf(a) },
  tokMergeConserve: { emitAsm: (a) => covsteps.tokMergeConserve(a), readsSiblingValue: true },
  tokVerifySiblingVector: { emitAsm: (a) => covsteps.tokVerifySiblingVector(a) },
  tokVerifySibSlice: { emitAsm: (a) => covsteps.tokVerifySibSlice(a) },
  tokVerifyFunding: { emitAsm: (a) => covsteps.tokVerifyFunding(a), backtrace: true },
  tokBindMergeOutput: { emitAsm: (a) => covsteps.tokBindMergeOutput(a), binds: 'outputs' },
  tokFinishBranch: { emitAsm: (a) => covsteps.tokFinishBranch(a), terminal: true },
  tokSplitReadSelf: { emitAsm: (a) => covsteps.tokSplitReadSelf(a) },
  tokSplitConserve: { emitAsm: (a) => covsteps.tokSplitConserve(a) },
  tokBindSplitOutputs: { emitAsm: (a) => covsteps.tokBindSplitOutputs(a), binds: 'outputs' },

  // --- lineage: authenticity by descent (linear-asm body) ---
  linReadSelf: { emitAsm: (a) => covsteps.linReadSelf(a) },
  linSuccessor: { emitAsm: (a) => covsteps.linSuccessor(a), binds: 'outputs', recreatesGenesis: true },
  descentReadParent: { emitAsm: (a) => covsteps.descentReadParent(a) },   // shared: lineage + provenance
  linGenesisOrParent: { emitAsm: (a) => covsteps.linGenesisOrParent(a), provesDescent: true },

  // --- provenance: authenticity + ownership (linear-asm body) ---
  provReadSelf: { emitAsm: (a) => covsteps.provReadSelf(a) },
  provAuthorise: { emitAsm: (a) => covsteps.provAuthorise(a), authorisesOwner: true },
  provSuccessor: { emitAsm: (a) => covsteps.provSuccessor(a), binds: 'outputs', recreatesGenesis: true, writesOwner: true },
  provGenesisOrParent: { emitAsm: (a) => covsteps.provGenesisOrParent(a), provesDescent: true },

  // --- sovereign: conservation + ownership + authenticity (3-way dispatch) ---
  sovExtractState: { emitAsm: (a) => covsteps.sovExtractState(a) },
  sovRequireOwnerSig: { emitAsm: (a) => covsteps.sovRequireOwnerSig(a), authorisesOwner: true },
  sovDescent: { emitAsm: (a) => covsteps.sovDescent(a), provesDescent: true },
  sovTransferSuccessor: { emitAsm: (a) => covsteps.sovTransferSuccessor(a), binds: 'outputs', recreatesGenesis: true, writesOwner: true },
  sovSplitConserve: { emitAsm: (a) => covsteps.sovSplitConserve(a) },
  sovSplitOutputs: { emitAsm: (a) => covsteps.sovSplitOutputs(a), binds: 'outputs', recreatesGenesis: true, writesOwner: true },
  sovNewOwnerCheck: { emitAsm: (a) => covsteps.sovNewOwnerCheck(a) },
  sovMergeVector: { emitAsm: (a) => covsteps.sovMergeVector(a) },
  sovMergeSiblingBacktrace: { emitAsm: (a) => covsteps.sovMergeSiblingBacktrace(a), backtrace: true },
  sovMergeConserve: { emitAsm: (a) => covsteps.sovMergeConserve(a), binds: 'outputs', recreatesGenesis: true, writesOwner: true, readsSiblingValue: true },

  // --- timelock: nLockTime is enforceable ONLY with a non-final sequence ---
  timelockSeqNonFinal: { emit: (s) => C.requireSequenceNonFinal(s), givesNonFinalSequence: true },
  timelockAtLeast: { emit: (s, { floor }) => C.requireLockTimeAtLeast(s, floor), needsEnforceableLockTime: true },

  // --- asset: conservation + ownership (4-way dispatch, with an atomic swap) ---
  assetExtractState: { emitAsm: (a) => covsteps.assetExtractState(a) },
  assetStride: { emitAsm: (a) => covsteps.assetStride(a) },
  assetRequireOwnerSig: { emitAsm: (a) => covsteps.assetRequireOwnerSig(a), authorisesOwner: true },
  assetTransferSuccessor: { emitAsm: (a) => covsteps.assetTransferSuccessor(a), binds: 'outputs', writesOwner: true },
  assetSplitConserve: { emitAsm: (a) => covsteps.assetSplitConserve(a) },
  assetSplitOutputs: { emitAsm: (a) => covsteps.assetSplitOutputs(a), binds: 'outputs', writesOwner: true },
  assetMergeConserve: { emitAsm: (a) => covsteps.assetMergeConserve(a), readsSiblingValue: true, writesOwner: true },
  assetMergeVector: { emitAsm: (a) => covsteps.assetMergeVector(a) },
  assetMergeSibSlice: { emitAsm: (a) => covsteps.assetMergeSibSlice(a) },
  assetVerifyFunding: { emitAsm: (a) => covsteps.assetVerifyFunding(a), backtrace: true },
  assetBindMergeOutput: { emitAsm: (a) => covsteps.assetBindMergeOutput(a), binds: 'outputs' },
  assetSwapPin: { emitAsm: (a) => covsteps.assetSwapPin(a), binds: 'outputs', writesOwner: true }
}

function stepsOf (spec) {
  if (spec.body) return Array.isArray(spec.body) ? spec.body : (spec.body.steps || [])
  if (spec.branch) {
    return [...((spec.branch.if && spec.branch.if.steps) || []),
      ...((spec.branch.else && spec.branch.else.steps) || [])]
  }
  if (spec.dispatch) return spec.dispatch.cases.reduce((a, c) => a.concat(c.steps || []), [])
  return []
}

// ---- a semantic type / capability system ------------------------------------
//
// This is the step from "the compiler rejects the bug" to "the bug cannot be
// written". A value produced inside a spend path carries a semantic CAPABILITY —
// an authenticated preimage, a proven sibling balance, an enforceable locktime —
// and a step that CONSUMES such a value declares the capability it NEEDS. A body
// type-checks only if every step's needs are established, somewhere in that same
// path, by a step that GIVES them. So `readLockTime` alone yields an inert value;
// only paired with a non-final-sequence guard does an `EnforceableLockTime` exist
// to satisfy `timelockAtLeast`. The check is order-agnostic (every clause is a
// VERIFY; the script passes only if all hold), which is why proofs may follow
// their use — what matters is that the capability is present in the path.
//
// Capabilities can be DERIVED: an EnforceableLockTime exists where an authenticated
// preimage and a non-final sequence both do. That composition is the type system's
// leverage — sound values arise only from sound combinations.

const CAP_CODE = {
  Authenticated: 'E_UNVERIFIED_PREIMAGE',
  BoundToWholeTx: 'E_REPLAYABLE_OUTPUTS',
  ProvenSibling: 'E_INFLATION',
  ProvenDescent: 'E_COUNTERFEIT',
  AuthorisedOwner: 'E_THEFT',
  EnforceableLockTime: 'E_LOCKTIME_INERT'
}
const CAP_MESSAGE = {
  Authenticated: 'reads a preimage field without an authenticated preimage — forgeable',
  BoundToWholeTx: 'binds outputs without committing to the whole transaction — replayable (pitfall 8)',
  ProvenSibling: 'uses a sibling balance with no backtrace to prove it — the inflation attack (cross-input.md)',
  ProvenDescent: 'recreates a genesis-carrying token without proving descent — a counterfeit (lineage)',
  AuthorisedOwner: 'writes a spender-chosen owner without authorising the current one — theft (titled)',
  EnforceableLockTime: 'uses nLockTime without a non-final sequence — the lock is inert (pitfall 11)'
}
// derived capability -> the capabilities that, together, establish it (ordered so
// deriveRefusals removes the meaningful provider first).
const DERIVED = { EnforceableLockTime: ['NonFinalSequence', 'Authenticated'] }

function stepGives (op) {
  const s = STEPS[op]; const out = []
  if (s.bakesFlag === 'all') out.push('Authenticated', 'BoundToWholeTx')
  else if (s.bakesFlag === 'open') out.push('Authenticated')
  if (s.backtrace) out.push('ProvenSibling')
  if (s.provesDescent) out.push('ProvenDescent')
  if (s.authorisesOwner) out.push('AuthorisedOwner')
  if (s.givesNonFinalSequence) out.push('NonFinalSequence')
  return out
}
function stepNeeds (op) {
  const s = STEPS[op]; const out = []
  if (s.binds === 'outputs') out.push('Authenticated', 'BoundToWholeTx')
  if (s.readsSiblingValue) out.push('ProvenSibling')
  if (s.recreatesGenesis) out.push('ProvenDescent')
  if (s.writesOwner) out.push('AuthorisedOwner')
  if (s.needsEnforceableLockTime) out.push('EnforceableLockTime')
  return out
}

const P = (code, message) => ({ code, message })

/** The bodies whose steps share a spend path (capabilities are per body). */
function bodiesOf (spec) {
  if (spec.branch) return [spec.branch.if, spec.branch.else]
  if (spec.dispatch) return spec.dispatch.cases
  return [{ steps: stepsOf(spec) }]
}

/** Capabilities established in a body: structural entry caps ∪ every step's gives,
 *  closed under the derivation rules. */
function available (steps, entry) {
  const caps = new Set(entry)
  for (const st of steps) for (const g of stepGives(st.op)) caps.add(g)
  let changed = true
  while (changed) {
    changed = false
    for (const [cap, deps] of Object.entries(DERIVED)) {
      if (!caps.has(cap) && deps.every((d) => caps.has(d))) { caps.add(cap); changed = true }
    }
  }
  return caps
}

/** A body's structural entry capabilities: a branch/dispatch/preamble covenant is
 *  already authenticated and bound to the whole tx before its body runs. */
function entryCaps (spec) {
  return (spec.branch || spec.dispatch || spec.preamble === 'authenticate') ? ['Authenticated', 'BoundToWholeTx'] : []
}

function invariants (spec) {
  const problems = []
  const all = stepsOf(spec)
  for (const st of all) if (!STEPS[st.op]) problems.push(P('E_UNKNOWN_STEP', `unknown step '${st.op}'`))
  if (problems.length) return problems

  // the semantic type check — per spend path, every step's needed capabilities
  // must be established somewhere in that path (structural entry caps + gives,
  // closed under derivation). A missing capability is a typed error.
  const entry = entryCaps(spec)
  for (const b of bodiesOf(spec)) {
    const steps = (b && b.steps) || []
    const caps = available(steps, entry)
    const reported = new Set()
    for (const st of steps) {
      for (const need of stepNeeds(st.op)) {
        if (!caps.has(need) && !reported.has(need)) { reported.add(need); problems.push(P(CAP_CODE[need], CAP_MESSAGE[need])) }
      }
    }
  }
  // a covenant that never authenticates at all cannot read its own spend.
  const authAnywhere = entry.includes('Authenticated') || all.some((st) => stepGives(st.op).includes('Authenticated'))
  const needsAuth = bodiesOf(spec).some((b) => ((b && b.steps) || []).some((st) => stepNeeds(st.op).includes('Authenticated')))
  if (!authAnywhere && !needsAuth) problems.push(P('E_UNVERIFIED_PREIMAGE', 'no auth step: the preimage is unverified'))

  // pitfall 18 — a self-recreating, value-draining covenant must be able to
  // terminate, or the tail strands (an exit branch, or a `terminates` acknowledgement).
  const selfRecreates = all.some((st) => STEPS[st.op].selfRecreates)
  if (selfRecreates) {
    const hasExit = all.some((st) => STEPS[st.op].exit)
    if (!hasExit && !spec.exit && !spec.terminates) {
      problems.push(P('E_STATE_STRANDING', 'self-recreating and value-draining, but no exit branch or terminates (pitfall 18)'))
    }
  }

  if (spec.branch) {
    if (!spec.branch.if || !spec.branch.else) problems.push(P('E_MALFORMED_BRANCH', 'a branch covenant needs both an if and an else body'))
  } else if (spec.dispatch) {
    if (!spec.dispatch.cases || spec.dispatch.cases.length < 2) problems.push(P('E_MALFORMED_DISPATCH', 'a dispatch covenant needs at least two selector cases'))
  } else {
    const last = all[all.length - 1]
    if (!last || !STEPS[last.op].terminal) {
      problems.push(P('E_DIRTY_STACK', 'does not end on a terminal step — the final stack would not be a single true value (CLEANSTACK)'))
    }
  }
  return problems
}

/** A copy of `spec` with step `stepIdx` removed from body `bi`. Only the mutated
 *  body's steps change; everything else is shared (the mutant is invariant-checked,
 *  never compiled). */
function removeStep (spec, bi, stepIdx) {
  const drop = (steps) => steps.filter((_, j) => j !== stepIdx)
  if (spec.branch) {
    const key = bi === 0 ? 'if' : 'else'
    return { ...spec, branch: { ...spec.branch, [key]: { ...spec.branch[key], steps: drop(spec.branch[key].steps) } } }
  }
  if (spec.dispatch) {
    return { ...spec, dispatch: { ...spec.dispatch, cases: spec.dispatch.cases.map((c, i) => i === bi ? { ...c, steps: drop(c.steps) } : c) } }
  }
  if (Array.isArray(spec.body)) return { ...spec, body: drop(spec.body) }
  return { ...spec, body: { ...spec.body, steps: drop(spec.body.steps) } }
}

/**
 * The source IS the security spec: from a spec's own structure, derive the
 * adversarial mutations its invariants must reject. For every obligation a spend
 * path satisfies (a claim paired with its proof), removing the proof must fire the
 * matching code. Returns [{ code, label, removed, mutant }] — the negative tests a
 * developer would otherwise write by hand, generated instead.
 */
// The step whose removal makes capability `cap` unavailable in this path — its
// direct provider, or (for a derived capability) a provider of one of its
// removable dependencies. Returns -1 if `cap` comes from the structural entry.
function providerIndex (steps, cap, entry) {
  if (entry.includes(cap)) return -1
  const direct = steps.findIndex((st) => stepGives(st.op).includes(cap))
  if (direct >= 0) return direct
  for (const dep of (DERIVED[cap] || [])) {
    if (entry.includes(dep)) continue
    const di = steps.findIndex((st) => stepGives(st.op).includes(dep))
    if (di >= 0) return di
  }
  return -1
}

function deriveRefusals (spec) {
  const out = []
  const paths = spec.branch ? [['if', spec.branch.if], ['else', spec.branch.else]]
    : spec.dispatch ? spec.dispatch.cases.map((c) => ['case ' + c.selector, c])
      : [['body', bodiesOf(spec)[0]]]
  const entry = entryCaps(spec)
  paths.forEach(([label, body], bi) => {
    const steps = (body && body.steps) || []
    const needed = new Set()
    for (const st of steps) for (const c of stepNeeds(st.op)) needed.add(c)
    for (const cap of needed) {
      const idx = providerIndex(steps, cap, entry)
      if (idx >= 0) out.push({ code: CAP_CODE[cap], capability: cap, label, removed: steps[idx].op, mutant: removeStep(spec, bi, idx) })
    }
  })
  return out
}

// A branch body: `given` names the unlocking stack it inherits, its steps run, and
// (unless the body terminates itself, `epilogue:false`) the clean-stack OP_1
// epilogue is appended. `raw` bodies are plain opcode lists.
function emitBranchBody (s, style, branch, fallbackGiven) {
  if (style === 'asm') {
    const asm = new StackAsm(s); asm.main = (branch.given || fallbackGiven || []).slice()
    for (const st of branch.steps) STEPS[st.op].emitAsm(asm, st)
    if (branch.epilogue !== false) { while (asm.main.length) asm.drop(); asm.raw(Opcode.OP_1, 0, ['ok']) }
  } else {
    for (const st of branch.steps) STEPS[st.op].emit(s, st)
  }
}

// A dispatch case body: a StackAsm seeded with its `given` stack and the parked
// preimage on the altstack. Self-terminating (a finish step is the last one).
function emitDispatchBody (s, c) {
  const asm = new StackAsm(s).given(c.given).seedAlt(['preimage'])
  for (const st of c.steps) STEPS[st.op].emitAsm(asm, st)
}

/** Compile a spec to a locking Script, or throw if any invariant is violated. */
function compile (spec) {
  const problems = invariants(spec)
  if (problems.length) throw new Error(`compile(${spec.name || '?'}): ${problems.map((p) => p.message).join('; ')}`)
  const s = new bsv.Script()

  if (spec.branch) {
    if (spec.state) s.add(spec.state).add(Opcode.OP_DROP)   // leading state, read from scriptCode
    C.authenticateThenBranch(s)                             // one auth, SIGHASH_ALL, flag → OP_IF
    emitBranchBody(s, spec.branch.style, spec.branch.if, spec.branch.given)
    s.add(Opcode.OP_ELSE)
    emitBranchBody(s, spec.branch.style, spec.branch.else, spec.branch.given)
    s.add(Opcode.OP_ENDIF)
    return s
  }

  // dispatch: a leading state field, an `authenticate` preamble, the preimage
  // parked on the altstack, and a selector chosen by nested OP_IF ([sovereign] —
  // transfer / split / merge). Each case body runs over a StackAsm seeded with the
  // parked preimage and terminates itself.
  if (spec.dispatch) {
    if (spec.state) s.add(spec.state).add(Opcode.OP_DROP)
    C.authenticate(s)
    s.add(Opcode.OP_TOALTSTACK)                            // park the preimage
    const cases = spec.dispatch.cases
    for (let i = 0; i < cases.length - 1; i++) {
      s.add(Opcode.OP_DUP).add(n(cases[i].selector)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
      s.add(Opcode.OP_DROP)                                // consume the matched selector
      emitDispatchBody(s, cases[i])
      s.add(Opcode.OP_ELSE)
    }
    s.add(Opcode.OP_DROP)                                  // the final case (fall-through)
    emitDispatchBody(s, cases[cases.length - 1])
    for (let i = 0; i < cases.length - 1; i++) s.add(Opcode.OP_ENDIF)
    return s
  }

  // linear-asm: a single body over StackAsm, behind a leading state field and an
  // `authenticate` preamble ([lineage] — one path, genesis-or-parent inside).
  if (spec.body && !Array.isArray(spec.body) && spec.body.style === 'asm') {
    if (spec.state) s.add(spec.state).add(Opcode.OP_DROP)
    if (spec.preamble === 'authenticate') C.authenticate(s)
    emitBranchBody(s, 'asm', spec.body)
    return s
  }

  // linear-raw: a plain clause list ([covenant], [perpetual]).
  for (const st of spec.body) STEPS[st.op].emit(s, st)
  return s
}

module.exports = { compile, invariants, deriveRefusals, STEPS, CAP_CODE, SIGHASH_ALL_FORKID, SIGHASH_SINGLE_ACP_FORKID }
