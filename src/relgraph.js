'use strict'

const relational = require('./relational')
const { TEMPLATES, OBLIGATION, CLAIM_BINDING } = require('./relcompile')
const conserve = require('./predicates/conserve')
const witness = require('./predicates/witness')
const guarded = require('./predicates/guarded')
const audited = require('./predicates/audited')
const ledger = require('./predicates/ledger')
const pool = require('./predicates/pool')
const compose = require('./compose')

// the composable aspects each covenant-bearing role contributes, for the safety check
const ROLE_ASPECTS = {
  'conservedPair:member': ['conserve', 'ownership', 'lineage'],
  'conservedGroup:member': ['conserve', 'ownership', 'lineage'],
  'dependsOn:gate': ['witnessGate'],
  'journal:logged': ['journal']
}

// CONSTRAINT GRAPH — a protocol as a graph of objects and the relationships that
// bind them, not a single relationship. This is the step past relcompile: an object
// may sit in MORE THAN ONE relationship at once, and then its coin must carry the
// obligations of all of them. The graph compiler works that out.
//
//   objects:        A, B, O
//   relationships:  A conservesWith B     (a conservedPair)
//                   A dependsOn O          (a dependsOn gate)
//
//   ⇒ B carries the conserve obligations         → a conserve coin (byte-identical)
//   ⇒ O is a passive tagged coin                 → a witness sibling
//   ⇒ A carries conserve ∧ witness obligations   → needs a COMPOSED predicate
//
// The graph type-checks iff every relationship type-checks on the relational ladder.
// Each object's obligation set is the UNION over its relationships. Where that union
// is satisfied by a single existing predicate, the compiler emits its bytes; where it
// spans two predicates the bench has not composed, it emits the obligation plan and
// says so — honest about the frontier rather than inventing a coin.

// how each relationship touches its objects: which role each named object plays, and
// the obligations that role's covenant must carry.
const ROLES = {
  conservedPair: {
    // every member is a full conserve coin
    roleOf: (objName, rel) => (rel.members || []).includes(objName) ? 'member' : null,
    obligations: () => TEMPLATES.conservedPair.proofs.map((p) => OBLIGATION[p]).concat([CLAIM_BINDING.globalConservation]),
    // a single-relationship member lowers to a conserve coin
    lower: (objName, rel) => {
      const m = (rel.memberParams || []).find((x) => x.name === objName)
      if (!m) return null
      return conserve.buildScript({ genesis: rel.genesis, side: m.side, balance: m.balance, owner: m.owner })
    }
  },
  conservedGroup: {
    roleOf: (objName, rel) => (rel.members || []).includes(objName) ? 'member' : null,
    obligations: () => TEMPLATES.conservedGroup.proofs.map((p) => OBLIGATION[p]).concat([CLAIM_BINDING.globalConservation]),
    lower: (objName, rel) => {
      const m = (rel.memberParams || []).find((x) => x.name === objName)
      if (!m) return null
      return pool.buildScript({ genesis: rel.genesis, index: m.index, balance: m.balance, owner: m.owner, N: (rel.memberParams || []).length })
    }
  },
  dependsOn: {
    // the gate carries the witness obligations; the sibling is passive (a tagged coin)
    roleOf: (objName, rel) => (objName === rel.gate ? 'gate' : (objName === rel.sibling ? 'sibling' : null)),
    obligations: (role) => role === 'gate'
      ? TEMPLATES.dependsOn.proofs.map((p) => OBLIGATION[p]).concat([CLAIM_BINDING.stateGate])
      : ['carry the committed flag a gate reads (a tagged coin: <flag> OP_DROP <P2PKH>)'],
    lower: (objName, rel) => {
      if (objName !== rel.gate) return null                       // only the gate has a covenant to emit
      const p = rel.gateParams || {}
      if (p.beneficiary === undefined || p.sibling === undefined || p.requiredFlag === undefined) return null
      return witness.buildScript({ beneficiary: p.beneficiary, sibling: p.sibling, requiredFlag: p.requiredFlag })
    }
  },
  // a TEMPORAL relationship: an object appends every transition to its own audit chain.
  // Not a sibling relationship, so it does not ride the sibling ladder — its soundness is
  // self-recreation (seq += 1, head = HASH256(oldHead ‖ record)). It composes; on its own
  // it carries only the audit obligation.
  journal: {
    roleOf: (objName, rel) => (objName === rel.object ? 'logged' : null),
    obligations: () => ['advance the audit chain: seq += 1 and head = HASH256(oldHead ‖ recordHash) (journal)'],
    lower: () => null
  }
}
// relationship types that make a sibling claim on the relational ladder (temporal ones do not)
const SIBLING_TYPES = new Set(['conservedPair', 'conservedGroup', 'dependsOn'])

// the predicate each relationship type lowers to
const IMPL = { conservedPair: 'conserve', conservedGroup: 'pool', dependsOn: 'witness', journal: 'journal' }

// COMPOSITIONS — role-sets the bench HAS composed into a single predicate. An object
// carrying exactly these covenant roles lowers to the composed predicate's bytes,
// instead of being flagged as a frontier. This is how a named "needs composing…"
// becomes a real coin: build the predicate, register it here.
const COMPOSITIONS = [
  {
    roles: ['conservedPair:member', 'dependsOn:gate'],
    predicate: 'guarded',
    lower (objName, rels) {
      const cp = rels.find((r) => r.type === 'conservedPair')
      const dep = rels.find((r) => r.type === 'dependsOn')
      const m = (cp.memberParams || []).find((x) => x.name === objName)
      const g = dep.gateParams || {}
      return guarded.buildScript({ genesis: cp.genesis, side: m.side, balance: m.balance, owner: m.owner, oracle: g.sibling, requiredFlag: g.requiredFlag })
    }
  },
  {
    // relational ∧ temporal: a conserved pair that also appends every rebalance to an audit chain
    roles: ['conservedPair:member', 'journal:logged'],
    predicate: 'audited',
    lower (objName, rels) {
      const cp = rels.find((r) => r.type === 'conservedPair')
      const j = rels.find((r) => r.type === 'journal')
      const m = (cp.memberParams || []).find((x) => x.name === objName)
      return audited.buildScript({ genesis: cp.genesis, side: m.side, balance: m.balance, owner: m.owner, seq: j.seq ?? 0, head: j.head })
    }
  },
  {
    // N-body conservation ∧ temporal audit chain: the pool ∧ journal composition
    roles: ['conservedGroup:member', 'journal:logged'],
    predicate: 'ledger',
    lower (objName, rels) {
      const cg = rels.find((r) => r.type === 'conservedGroup')
      const j = rels.find((r) => r.type === 'journal')
      const m = (cg.memberParams || []).find((x) => x.name === objName)
      const N = (cg.memberParams || []).length
      return ledger.buildScript({ genesis: cg.genesis, index: m.index, balance: m.balance, owner: m.owner, seq: j.seq ?? 0, head: j.head, N })
    }
  }
]
function matchComposition (roles) {
  const set = roles.filter((r) => !r.endsWith(':sibling')).sort()
  return COMPOSITIONS.find((c) => c.roles.slice().sort().join('|') === set.join('|'))
}

// the claim each relationship makes, for the ladder soundness check
function relClaim (rel) {
  const tpl = TEMPLATES[rel.type]
  if (!tpl) throw new Error(`unknown relationship type '${rel.type}'`)
  return { name: rel.name || rel.type, proofs: rel.proofs || tpl.proofs, claims: [rel.claim || tpl.claim] }
}

/**
 * Compile a constraint graph.
 *   { name, objects: [names], relationships: [ {type, ...} ] }
 * Returns { name, sound, objects: { <name>: { relationships, roles, obligations, coin?, composition? } } }
 * or throws with the first relationship soundness error.
 */
function compile (graph) {
  // 1. every SIBLING relationship must type-check on the ladder (temporal ones don't make
  //    a sibling claim — their soundness is self-recreation, enforced by the predicate)
  for (const rel of graph.relationships) {
    if (!SIBLING_TYPES.has(rel.type)) continue
    const problems = relational.check(relClaim(rel))
    if (problems.length) {
      const e = new Error(`${graph.name}: relationship '${rel.name || rel.type}' will not compile — ${problems[0].code}: ${problems[0].message}`)
      e.code = problems[0].code
      throw e
    }
  }

  // 2. for each object, gather its relationships, roles, and the UNION of obligations
  const out = {}
  for (const name of graph.objects) {
    const inRels = []
    const myRels = []
    const roles = []
    const obligations = new Set()
    let coin = null
    for (const rel of graph.relationships) {
      const spec = ROLES[rel.type]
      const role = spec.roleOf(name, rel)
      if (!role) continue
      inRels.push(rel.name || rel.type)
      myRels.push(rel)
      roles.push(`${rel.type}:${role}`)
      for (const ob of spec.obligations(role)) obligations.add(ob)
      const lowered = spec.lower(name, rel)
      if (lowered) coin = coin || lowered
    }
    if (!inRels.length) continue

    const entry = { relationships: inRels, roles, obligations: [...obligations] }
    const covenantRoles = roles.filter((r) => !r.endsWith(':sibling'))
    if (covenantRoles.length <= 1 && coin) {
      // a single covenant-bearing relationship lowers to that predicate's bytes
      entry.coin = coin
    } else if (covenantRoles.length > 1) {
      // obligations span two predicates — emit the COMPOSED predicate if the bench has
      // built it, otherwise name the frontier rather than inventing a coin.
      const comp = matchComposition(roles)
      if (comp) { entry.coin = comp.lower(name, myRels); entry.composedBy = comp.predicate }
      else {
        // no predicate composes these yet — name the frontier, and run the resource
        // check so the graph reports whether that predicate is even SAFE to build.
        const predicates = covenantRoles.map((r) => IMPL[r.split(':')[0]] || r.split(':')[0])
        const aspects = covenantRoles.flatMap((r) => ROLE_ASPECTS[r] || [])
        const safety = compose.analyze(aspects)
        entry.composition = `needs a predicate composing: ${predicates.join(' ∧ ')}`
        entry.safeToBuild = safety.sound
        entry.conflicts = safety.conflicts.map((c) => ({ code: c.code, aspects: c.aspects, fields: c.fields }))
      }
    }
    out[name] = entry
  }

  return { name: graph.name, sound: true, objects: out }
}

module.exports = { compile, ROLES }
