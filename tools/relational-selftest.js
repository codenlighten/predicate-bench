'use strict'

// The relational type ladder holds if: every cross-object predicate of the bench
// type-checks as sound, and removing any load-bearing proof makes it UNSOUND with
// the right typed error — the same "prove it by what it refuses" discipline the
// predicates themselves are held to, lifted to the language layer.

const R = require('../src/relational')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

console.log('the bench’s cross-object predicates all type-check as sound:')
for (const rel of Object.values(R.RELATIONS)) {
  const problems = R.check(rel)
  ok(problems.length === 0, `${rel.name}: {${rel.proofs.join(', ')}} ⊢ ${rel.claims.join(', ')}` +
    (problems.length ? `  — ${problems.map((p) => p.code).join(', ')}` : ''))
}

console.log('\nevery load-bearing proof is load-bearing (drop it → a typed soundness error):')
let derived = 0
for (const rel of Object.values(R.RELATIONS)) {
  const refusals = R.deriveRefusals(rel)
  for (const r of refusals) {
    derived++
    console.log(`  ${rel.name} − ${r.removed}  →  ${r.code}`)
  }
}
ok(derived >= 6, `${derived} adversarial mutants derived from the sound relations`)

console.log('\nthe crux — global conservation needs the top rung:')
// conserve, minus its descent proof, must fail with the counterfeit-inflation error
const conserveNoDescent = { ...R.RELATIONS.conserve, name: 'conserve−descent', proofs: ['coSpend', 'backtrace'] }
const cnd = R.check(conserveNoDescent)
ok(cnd.some((p) => p.code === 'E_COUNTERFEIT_INFLATION'),
  'conserve without descent ⊬ globalConservation — E_COUNTERFEIT_INFLATION')

// the exact unsound design the review warned of: claim a bounded total, prove only the balance
const inflatable = { name: 'naive-pair', sibling: 'x', proofs: ['coSpend', 'backtrace'], claims: ['globalConservation'] }
ok(!R.isSound(inflatable) && R.check(inflatable)[0].code === 'E_COUNTERFEIT_INFLATION',
  'a pair that reads a sibling balance without descent cannot claim a bounded total')

console.log('\nand the distinctions the ladder draws:')
// local conservation is fine WITHOUT descent (token): the sum holds across this co-spend
ok(R.isSound({ name: 'token', sibling: 'x', proofs: ['backtrace'], claims: ['localConservation'] }),
  'token conserves LOCALLY with only a backtrace — no descent required')
// but a stateGate that never proves the sibling co-spent reads possibly-stale state
const staleGate = { name: 'stale', sibling: 'x', proofs: ['backtrace'], claims: ['stateGate'] }
ok(!R.isSound(staleGate) && R.check(staleGate).some((p) => p.code === 'E_STALE_SIBLING'),
  'a state gate that omits the co-spend proof reads stale state — E_STALE_SIBLING')
// reading committed bytes with no backtrace at all is forgeable
const forgeable = { name: 'forge', sibling: 'x', proofs: ['coSpend'], claims: ['stateGate'] }
ok(!R.isSound(forgeable) && R.check(forgeable).some((p) => p.code === 'E_UNAUTHENTIC_SIBLING'),
  'a state gate with no backtrace uses forgeable bytes — E_UNAUTHENTIC_SIBLING')

console.log(failed ? `\n${failed} failing` : '\nthe relational ladder holds: sound relations pass, unsound ones cannot be expressed')
process.exit(failed ? 1 : 0)
