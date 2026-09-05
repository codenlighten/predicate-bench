'use strict'

const relational = require('./relational')
const conserve = require('./predicates/conserve')
const witness = require('./predicates/witness')
const pool = require('./predicates/pool')

// RELATIONSHIP COMPILER — a protocol of interacting objects, from a declaration.
//
// The single-object compiler (compile.js) turns one predicate spec into one coin's
// bytes. This turns a RELATIONSHIP declaration — several coins and an invariant that
// spans them — into the coins that realise it, but only after the relational type
// ladder (relational.js) confirms the relationship is sound. The point is the gate:
// a declaration whose invariant its proofs cannot support does not compile. You
// cannot, by construction, emit a bounded-total pair that a counterfeit could inflate
// — the same discipline the byte-compiler applies to one coin, applied to the graph.
//
//   declaration                         lowering
//   ───────────                         ────────
//   conservedPair {                     side-0 coin  (conserve, genesis G)
//     invariant: sum fixed forever  ⟶   side-1 coin  (conserve, genesis G)
//     members: [side0, side1]           + the obligation plan each coin carries
//   }
//
// The invariant names a CLAIM on the ladder; the lowering names the PROOFS its coins
// carry. compile() checks the proofs establish the rung the claim needs, and refuses
// with the ladder's typed error when they do not.

// A relationship template: the claim its invariant makes, the proofs its lowering's
// coins carry, and how it lowers a declaration to concrete coin scripts.
const TEMPLATES = {
  // two coins, one conserved total that can never be inflated — the `conserve` capstone.
  conservedPair: {
    invariant: 'a total fixed for the life of the pair, uncounterfeitable',
    claim: 'globalConservation',
    proofs: ['coSpend', 'backtrace', 'descent'],
    lower ({ genesis, members }) {
      if (!members || members.length !== 2) throw new Error('conservedPair needs exactly two members')
      const sides = members.map((m) => m.side)
      if (!(sides.includes(0) && sides.includes(1))) throw new Error('conservedPair members must be side 0 and side 1')
      return members
        .slice().sort((a, b) => a.side - b.side)
        .map((m) => ({ side: m.side, balance: m.balance, owner: m.owner,
          script: conserve.buildScript({ genesis, side: m.side, balance: m.balance, owner: m.owner }) }))
    }
  },
  // N coins whose balances always sum to a constant — `conserve` for N bodies, `pool`.
  conservedGroup: {
    invariant: 'a total fixed across N members forever, uncounterfeitable',
    claim: 'globalConservation',
    proofs: ['coSpend', 'backtrace', 'descent'],
    lower ({ genesis, members }) {
      if (!members || members.length < 2) throw new Error('conservedGroup needs at least two members')
      const N = members.length
      return members
        .slice().sort((a, b) => a.index - b.index)
        .map((m, i) => {
          if (m.index !== i) throw new Error('conservedGroup members must be indexed 0..N-1 in order')
          return { index: m.index, balance: m.balance, owner: m.owner,
            script: pool.buildScript({ genesis, index: m.index, balance: m.balance, owner: m.owner, N }) }
        })
    }
  },
  // one coin's release gated on a NAMED other coin's committed state — the `witness`
  // predicate. A state gate, so it needs the sibling live (co-spent) and authentic.
  dependsOn: {
    invariant: 'release only while a named coin is co-spent carrying the required state',
    claim: 'stateGate',
    proofs: ['coSpend', 'backtrace'],
    lower ({ beneficiary, sibling, requiredFlag }) {
      if (!beneficiary || !sibling || requiredFlag === undefined) {
        throw new Error('dependsOn needs a beneficiary, a sibling outpoint, and a requiredFlag')
      }
      return [{ role: 'gate', beneficiary, sibling, requiredFlag,
        script: witness.buildScript({ beneficiary, sibling, requiredFlag }) }]
    }
  }
}

// The concrete on-chain obligation each proof becomes in a coin's covenant — the plan
// the relationship compiles TO, and the bridge to the predicates that implement it.
const OBLIGATION = {
  coSpend: 'require the partner’s outpoint in hashPrevouts (companion)',
  backtrace: 'rebuild the shared parent tx and hash it to this coin’s funding txid (token)',
  descent: 'prove the parent spent the genesis outpoint, or its parent was a genuine member (lineage)'
}
const CLAIM_BINDING = {
  globalConservation: 'bind [side0′, side1′] to hashOutputs with side0.balance + side1.balance preserved',
  localConservation: 'bind the merged output to hashOutputs with the summed balance',
  stateGate: 'read the sibling’s committed state field and gate the spend on it'
}

/**
 * Compile a relationship declaration to its coins, or refuse with a typed soundness
 * error. Returns { name, claim, proofs, coins, obligations }.
 */
function compile (decl) {
  const tpl = TEMPLATES[decl.relationship]
  if (!tpl) throw new Error(`unknown relationship '${decl.relationship}'`)

  // the claim the invariant makes, and the proofs the lowering carries. A declaration
  // may OVERRIDE the proofs (to model a weaker lowering) — used to prove the gate bites.
  const claim = decl.claim || tpl.claim
  const proofs = decl.proofs || tpl.proofs

  const rel = { name: decl.name || decl.relationship, proofs, claims: [claim] }
  const problems = relational.check(rel)
  if (problems.length) {
    const e = new Error(`${rel.name}: will not compile — ${problems[0].code}: ${problems[0].message}`)
    e.code = problems[0].code
    e.problems = problems
    throw e
  }

  const coins = tpl.lower(decl)
  const obligations = proofs.map((p) => OBLIGATION[p]).concat([CLAIM_BINDING[claim]])
  return { name: rel.name, relationship: decl.relationship, claim, proofs, coins, obligations }
}

module.exports = { compile, TEMPLATES, OBLIGATION, CLAIM_BINDING }
