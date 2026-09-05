'use strict'

// RELATIONAL SOUNDNESS — a type ladder for cross-object predicates.
//
// The single-object type system in compile.js checks one coin's spend path. This
// checks the harder thing this bench discovered empirically: what one coin may
// soundly conclude about ANOTHER coin it is spent beside.
//
// A covenant can see sibling OUTPOINTS (hashPrevouts) and committed OUTPUTS
// (hashOutputs), but never a sibling's unlocking script or signature. So every
// fact about a sibling has to be EARNED, and the facts form a ladder — each rung
// a proof the transaction actually carries:
//
//   UntrustedSibling                      bytes the spender pushed; prove nothing
//     └─ coSpend  ─────────────────▶  SiblingCoSpent
//          the sibling's outpoint is in hashPrevouts — it is a LIVE input of this
//          tx, being spent now (companion). Its state is therefore CURRENT.
//     └─ backtrace ────────────────▶  SiblingAuthenticated
//          the sibling's source tx, rebuilt and hashed, is that outpoint's txid —
//          so the committed bytes at that outpoint are real, not forged (token).
//     └─ descent ──────────────────▶  SiblingDescent
//          the sibling descends from a unique genesis — it is a canonical member,
//          not a look-alike minted from a plain UTXO (lineage).
//
//   SiblingCanonical  ⇐  SiblingCoSpent ∧ SiblingAuthenticated ∧ SiblingDescent
//          a live, authentic, non-counterfeit member. The top rung.
//
// The leverage is the DERIVATION: an invariant asks for a rung, and the relation
// type-checks only if its proofs establish that rung. The rung an invariant needs
// is exactly the soundness result:
//
//   stateGate           reads a sibling's committed state    needs Authenticated + CoSpent
//   localConservation   sum preserved across THIS co-spend   needs Authenticated
//   globalConservation  a total that cannot be inflated      needs Canonical
//
// The last line is the crux. Reading a sibling's amount WITHOUT proving descent
// lets a counterfeit sibling carry any balance and inflate the total; proving
// descent WITHOUT reading the amount cannot enforce a sum. Global conservation
// needs both — plus the co-spend that makes it the real, current partner. Encoded
// here, a relation that claims to bound a total but omits the descent proof is not
// merely refused at runtime — it does not type-check.

const RUNGS = ['SiblingCoSpent', 'SiblingAuthenticated', 'SiblingDescent', 'SiblingCanonical']

// a proof step and the rung it establishes
const PROVES = {
  coSpend: 'SiblingCoSpent',           // outpoint ∈ hashPrevouts (companion)
  backtrace: 'SiblingAuthenticated',   // source tx rebuilt, hashes to the outpoint's txid (token)
  descent: 'SiblingDescent'            // proven descent from a unique genesis (lineage)
}

// SiblingCanonical is DERIVED, exactly as EnforceableLockTime is in compile.js:
// it exists where the three independent proofs all do.
const DERIVED = { SiblingCanonical: ['SiblingCoSpent', 'SiblingAuthenticated', 'SiblingDescent'] }

// what each kind of cross-object claim REQUIRES to be sound
const NEEDS = {
  stateGate: ['SiblingCoSpent', 'SiblingAuthenticated'],
  localConservation: ['SiblingAuthenticated'],
  globalConservation: ['SiblingCanonical']
}

const CODE = {
  SiblingCoSpent: 'E_STALE_SIBLING',
  SiblingAuthenticated: 'E_UNAUTHENTIC_SIBLING',
  SiblingDescent: 'E_UNCANONICAL_SIBLING',
  SiblingCanonical: 'E_COUNTERFEIT_INFLATION'
}
const MESSAGE = {
  SiblingCoSpent: 'reads a sibling that is not proven co-spent — its state may be historical, not current (companion)',
  SiblingAuthenticated: 'uses a sibling’s committed bytes with no backtrace proving its source — forgeable (token)',
  SiblingDescent: 'treats a sibling as a canonical member without proving descent from the genesis (lineage)',
  SiblingCanonical: 'bounds a total using a sibling balance that is not proven canonical — a counterfeit can inflate it (conserve)'
}

const P = (code, message) => ({ code, message })

/** Rungs a relation's proofs establish, closed under the derivation. */
function established (proofs) {
  const caps = new Set()
  for (const pr of proofs) if (PROVES[pr]) caps.add(PROVES[pr])
  let changed = true
  while (changed) {
    changed = false
    for (const [cap, deps] of Object.entries(DERIVED)) {
      if (!caps.has(cap) && deps.every((d) => caps.has(d))) { caps.add(cap); changed = true }
    }
  }
  return caps
}

/**
 * Type-check a relationship spec.
 *   { name, sibling, proofs: [<proof steps>], claims: [<claim kinds>] }
 * A relation is sound iff, for every claim, the rung it needs is established by the
 * proofs. Returns [] when sound, else the typed soundness errors.
 */
function check (rel) {
  const problems = []
  for (const pr of rel.proofs || []) if (!PROVES[pr]) problems.push(P('E_UNKNOWN_PROOF', `unknown proof step '${pr}'`))
  for (const cl of rel.claims || []) if (!NEEDS[cl]) problems.push(P('E_UNKNOWN_CLAIM', `unknown claim '${cl}'`))
  if (problems.length) return problems

  const caps = established(rel.proofs || [])
  const reported = new Set()
  for (const cl of rel.claims || []) {
    for (const need of NEEDS[cl]) {
      if (!caps.has(need) && !reported.has(need)) { reported.add(need); problems.push(P(CODE[need], MESSAGE[need])) }
    }
  }
  return problems
}

function isSound (rel) { return check(rel).length === 0 }

/**
 * Read the ladder backwards: for a SOUND relation, drop each load-bearing proof in
 * turn and confirm the drop makes it UNSOUND — the adversarial mutant, and the
 * typed error it must raise. Mirrors compile.js's deriveRefusals.
 */
function deriveRefusals (rel) {
  if (!isSound(rel)) throw new Error(`${rel.name}: cannot derive refusals from an already-unsound relation`)
  const out = []
  for (let i = 0; i < (rel.proofs || []).length; i++) {
    const mutantProofs = rel.proofs.slice(0, i).concat(rel.proofs.slice(i + 1))
    const mutant = { ...rel, name: `${rel.name}−${rel.proofs[i]}`, proofs: mutantProofs }
    const problems = check(mutant)
    if (problems.length) out.push({ removed: rel.proofs[i], code: problems[0].code, message: problems[0].message, mutant })
  }
  return out
}

// The cross-object predicates of this bench, as relationship specs. Each is a claim
// about a sibling and the proofs it carries; `check` confirms the proofs earn the
// rung the claim needs. These are the ground truth the self-test holds the ladder to.
const RELATIONS = {
  // witness: release gated on a named sibling's committed state (its flag), read from
  // the live co-spent coin whose source tx is authenticated.
  witness: { name: 'witness', sibling: 'taggedCoin', proofs: ['coSpend', 'backtrace'], claims: ['stateGate'] },
  // token merge: conserves balance across the two coins spent together — locally. It
  // authenticates the sibling's balance but makes no global-supply claim.
  token: { name: 'token', sibling: 'tokenCoin', proofs: ['backtrace'], claims: ['localConservation'] },
  // sovereign merge: token's conservation plus descent — a conserved, authentic token.
  sovereign: { name: 'sovereign', sibling: 'sovereignCoin', proofs: ['backtrace', 'descent'], claims: ['localConservation'] },
  // conserve: the capstone — a total that cannot be inflated, so it needs the top rung.
  conserve: { name: 'conserve', sibling: 'pairCoin', proofs: ['coSpend', 'backtrace', 'descent'], claims: ['globalConservation'] }
}

module.exports = { RUNGS, PROVES, DERIVED, NEEDS, CODE, MESSAGE, established, check, isSound, deriveRefusals, RELATIONS }
