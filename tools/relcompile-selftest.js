'use strict'

// The relationship compiler holds if: a sound declaration lowers to the EXACT coins
// deployed on mainnet, its plan names the real obligations, and an unsound
// declaration — one whose invariant its proofs cannot support — refuses to compile
// with the ladder's typed error. Same bar as the byte-compiler, one level up.

const relc = require('../src/relcompile')
const onchain = require('../src/onchain')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

// the conserve pair deployed on mainnet (genesis 54c9…), recovered from the ledger
const deployed = onchain.requireDeployed('conserve')
const genesis = deployed.params.genesis
const owner = deployed.params.owner

const decl = {
  name: 'treasury-pair',
  relationship: 'conservedPair',
  genesis,
  members: [
    { side: 0, balance: 60, owner },
    { side: 1, balance: 40, owner }
  ]
}

console.log('a sound conservedPair compiles to the deployed coins, byte-for-byte:')
const out = relc.compile(decl)
ok(out.claim === 'globalConservation', `claim resolved to ${out.claim}`)
ok(out.coins.length === 2, 'two coins emitted')
const side0 = out.coins.find((c) => c.side === 0)
ok(side0.script.toHex() === deployed.lockHex,
  `side-0 coin is byte-identical to the deployed ${deployed.txid.slice(0, 12)}…:0 (${side0.script.toBuffer().length} B)`)

console.log('\nthe compiled plan names the real on-chain obligations:')
for (const o of out.obligations) console.log(`  · ${o}`)
ok(out.obligations.some((o) => /companion/.test(o)) &&
   out.obligations.some((o) => /token/.test(o)) &&
   out.obligations.some((o) => /lineage/.test(o)) &&
   out.obligations.some((o) => /hashOutputs/.test(o)),
'the plan carries the companion, backtrace, descent, and output-binding obligations')

console.log('\na dependsOn declaration lowers to the deployed witness, byte-for-byte:')
const wt = onchain.requireDeployed('witness')
const gate = relc.compile({
  name: 'escrow-leg', relationship: 'dependsOn',
  beneficiary: wt.params.beneficiary, sibling: wt.params.sibling, requiredFlag: wt.params.requiredFlag
})
ok(gate.claim === 'stateGate', `claim resolved to ${gate.claim}`)
ok(gate.coins[0].script.toHex() === wt.lockHex,
  `witness is byte-identical to the deployed ${wt.txid.slice(0, 12)}…:${wt.vout} (${gate.coins[0].script.toBuffer().length} B)`)

console.log('\na conservedGroup lowers to the deployed N-body pool, byte-for-byte:')
const pl = onchain.requireDeployed('pool')
const N = pl.params.N
const group = relc.compile({
  name: 'treasury-N', relationship: 'conservedGroup', genesis: pl.params.genesis,
  members: Array.from({ length: N }, (_, i) => ({ index: i, balance: i === 0 ? pl.params.balance : 10, owner: pl.params.owner }))
})
ok(group.coins.length === N, `${N} coins emitted`)
ok(group.coins[0].script.toHex() === pl.lockHex,
  `bucket-0 is byte-identical to the deployed ${pl.txid.slice(0, 12)}…:0 (N=${N}, ${group.coins[0].script.toBuffer().length} B)`)

console.log('\nthe gate bites — an unsound declaration will not compile:')
// a pair that wants a bounded total but whose lowering omits the descent proof
try {
  relc.compile({ ...decl, name: 'naive-pair', proofs: ['coSpend', 'backtrace'] })
  ok(false, 'a bounded total without descent should NOT compile')
} catch (e) {
  ok(e.code === 'E_COUNTERFEIT_INFLATION',
    `a bounded total without descent refuses to compile — ${e.code}`)
}
// and one that omits the co-spend, so the partner need not even be present
try {
  relc.compile({ ...decl, name: 'lonely-pair', proofs: ['backtrace', 'descent'] })
  ok(false, 'a bounded total without the co-spend should NOT compile')
} catch (e) {
  ok(e.code === 'E_COUNTERFEIT_INFLATION', `a bounded total without the partner co-spent refuses — ${e.code}`)
}

console.log(failed
  ? `\n${failed} failing`
  : '\nthe relationship compiler holds: a sound protocol lowers to the deployed bytes, an unsound one cannot be built')
process.exit(failed ? 1 : 0)
