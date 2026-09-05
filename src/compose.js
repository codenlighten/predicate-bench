'use strict'

// COMPOSITION SAFETY — a resource model over predicates, so the compiler can decide
// whether two (or more) predicates can share one covenant BEFORE anyone writes it.
//
// The bench has composed predicates by hand (sovereign, guarded, audited) and proven
// each on chain. But the graph will happily *specify* compositions no one has built —
// `pool ∧ journal`, `guarded ∧ audited` — and the open question the predicate algebra
// raises is: which of those are even sound to attempt? Not every P_A ∧ P_B is safe.
//
// The answer is a resource/type check. Each composable aspect declares what state it
// READS, what it WRITES (mutates in the successor), what it must keep unchanged
// (PRESERVES), how it claims the transaction's OUTPUTS, and the capabilities it
// REQUIRES. Two aspects compose only when those resources don't conflict:
//
//   · two aspects that WRITE the same field          → E_WRITE_CONFLICT
//   · one WRITES a field another PRESERVES           → E_WRITE_PRESERVE_CONFLICT
//   · two aspects that both bind the OUTPUT SET       → E_OUTPUT_CLAIM_CONFLICT
//
// This is composition made a type problem: the graph can now report, for an unbuilt
// composition, whether it is *safe to build* — and refuse to imply otherwise.

// The composable aspects the bench's predicates are built from, as resource profiles.
// `outputs`: 'bound-set' claims the whole output set; 'bound-single' claims one output;
// 'rides' contributes state to a carrier's binding but claims nothing itself; 'none'.
const ASPECTS = {
  // balance conservation across the co-spent members (conserve/pool): reads and rewrites
  // each member's balance, keeps identity fields, and binds the member output set.
  conserve: { reads: ['balance'], writes: ['balance'], preserves: ['genesis', 'side', 'owner'], outputs: 'bound-set', requires: ['auth', 'descent', 'coSpendPartner'] },
  // an append-only audit chain (journal): reads and advances seq + head; claims no outputs
  // of its own — it rides the carrier's successor.
  journal: { reads: ['seq', 'head'], writes: ['seq', 'head'], preserves: [], outputs: 'rides', requires: [] },
  // a gate on a named oracle coin (witness): adds an oracle co-input and reads its flag;
  // writes no state, claims no outputs.
  witnessGate: { reads: [], writes: [], preserves: [], outputs: 'rides', requires: ['coSpendOracle', 'backtraceOracle'] },
  // ownership: the owner field authorises the spend; read, preserved, not rewritten.
  ownership: { reads: ['owner'], writes: [], preserves: ['owner'], outputs: 'none', requires: ['auth'] },
  // lineage/descent: reads and preserves the genesis, proves descent; no output claim.
  lineage: { reads: ['genesis'], writes: [], preserves: ['genesis'], outputs: 'none', requires: ['descent'] },
  // --- aspects used to demonstrate genuine conflicts (not yet realised as predicates) ---
  // an exit that sweeps to a single output — a second output-set claimant.
  exclusiveExit: { reads: [], writes: [], preserves: [], outputs: 'bound-single', requires: ['auth'] },
  // a freeze that forbids the balance from changing — collides with conserve rewriting it.
  freeze: { reads: ['balance'], writes: [], preserves: ['balance'], outputs: 'rides', requires: [] }
}

const MESSAGE = {
  E_WRITE_CONFLICT: 'two aspects write the same state field — their transition rules collide',
  E_WRITE_PRESERVE_CONFLICT: 'one aspect rewrites a field another requires unchanged',
  E_OUTPUT_CLAIM_CONFLICT: 'two aspects each bind the transaction output set — incompatible output layouts'
}

function intersect (a, b) { const s = new Set(b); return a.filter((x) => s.has(x)) }

/**
 * Analyse a proposed composition of aspects (by name).
 * Returns { sound, conflicts: [{code, message, aspects, fields?}], profile }.
 * `profile` is the unioned resource footprint of the whole composition.
 */
function analyze (aspectNames) {
  const names = [...new Set(aspectNames)]
  for (const nm of names) if (!ASPECTS[nm]) throw new Error(`unknown aspect '${nm}'`)
  const conflicts = []

  // pairwise write/write and write/preserve
  for (let i = 0; i < names.length; i++) {
    for (let j = i + 1; j < names.length; j++) {
      const A = ASPECTS[names[i]]; const B = ASPECTS[names[j]]
      const ww = intersect(A.writes, B.writes)
      if (ww.length) conflicts.push({ code: 'E_WRITE_CONFLICT', message: MESSAGE.E_WRITE_CONFLICT, aspects: [names[i], names[j]], fields: ww })
      const wp1 = intersect(A.writes, B.preserves)
      if (wp1.length) conflicts.push({ code: 'E_WRITE_PRESERVE_CONFLICT', message: MESSAGE.E_WRITE_PRESERVE_CONFLICT, aspects: [names[i], names[j]], fields: wp1 })
      const wp2 = intersect(B.writes, A.preserves)
      if (wp2.length) conflicts.push({ code: 'E_WRITE_PRESERVE_CONFLICT', message: MESSAGE.E_WRITE_PRESERVE_CONFLICT, aspects: [names[j], names[i]], fields: wp2 })
    }
  }
  // at most one aspect may bind the output set
  const claimers = names.filter((nm) => ASPECTS[nm].outputs === 'bound-set' || ASPECTS[nm].outputs === 'bound-single')
  if (claimers.length > 1) conflicts.push({ code: 'E_OUTPUT_CLAIM_CONFLICT', message: MESSAGE.E_OUTPUT_CLAIM_CONFLICT, aspects: claimers })

  const profile = {
    reads: [...new Set(names.flatMap((nm) => ASPECTS[nm].reads))],
    writes: [...new Set(names.flatMap((nm) => ASPECTS[nm].writes))],
    preserves: [...new Set(names.flatMap((nm) => ASPECTS[nm].preserves))],
    requires: [...new Set(names.flatMap((nm) => ASPECTS[nm].requires))],
    outputs: claimers.length ? ASPECTS[claimers[0]].outputs : 'rides'
  }
  return { sound: conflicts.length === 0, conflicts, profile }
}

function isSafe (aspectNames) { return analyze(aspectNames).sound }

module.exports = { ASPECTS, MESSAGE, analyze, isSafe }
