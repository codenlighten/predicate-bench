'use strict'

// The constraint-graph compiler holds if: a graph of sound relationships type-checks
// and lowers single-relationship objects to the deployed bytes; an object standing in
// two relationships gets the UNION of their obligations and is honestly flagged as
// needing a composed predicate; and a graph containing an unsound relationship refuses.

const graphc = require('../src/relgraph')
const onchain = require('../src/onchain')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

const cv = onchain.readLedger().filter((x) => x.predicate === 'conserve').slice(-1)[0]
const wt = onchain.readLedger().filter((x) => x.predicate === 'witness').slice(-1)[0]
const gd = onchain.readLedger().filter((x) => x.predicate === 'guarded').slice(-1)[0]
const genesis = cv.params.genesis
const owner = cv.params.owner

const conservedPair = {
  type: 'conservedPair', name: 'treasury', genesis,
  members: ['A', 'B'],
  memberParams: [{ name: 'A', side: 0, balance: 60, owner }, { name: 'B', side: 1, balance: 40, owner }]
}
const dependsOn = {
  type: 'dependsOn', name: 'armed-by-oracle', gate: 'A', sibling: 'O',
  gateParams: { beneficiary: wt.params.beneficiary, sibling: wt.params.sibling, requiredFlag: wt.params.requiredFlag }
}
// a graph whose (conservedPair + dependsOn) on A matches the deployed `guarded` coin,
// so A's composed lowering is byte-identical to what is on chain.
const gConservedPair = {
  type: 'conservedPair', name: 'gtreasury', genesis: gd.params.genesis,
  members: ['A', 'B'],
  memberParams: [{ name: 'A', side: 0, balance: gd.params.balance, owner: gd.params.owner }, { name: 'B', side: 1, balance: 40, owner: gd.params.owner }]
}
const gDependsOn = {
  type: 'dependsOn', name: 'gate-A', gate: 'A', sibling: 'O',
  gateParams: { sibling: Buffer.from(gd.params.oracle, 'hex'), requiredFlag: gd.params.requiredFlag }
}

console.log('a graph of one relationship lowers its objects to the deployed bytes:')
const g1 = graphc.compile({ name: 'plain-pair', objects: ['A', 'B'], relationships: [conservedPair] })
ok(g1.objects.A.coin && g1.objects.A.coin.toHex() === cv.lockHex,
  `A → conserve side-0, byte-identical to ${cv.txid.slice(0, 12)}…:0`)
ok(g1.objects.B.coin && g1.objects.B.coin.toBuffer().length === 1025, 'B → conserve side-1 coin emitted')

console.log('\na graph where one object stands in TWO relationships lowers to the COMPOSED predicate:')
const g2 = graphc.compile({ name: 'escrowed-treasury', objects: ['A', 'B', 'O'], relationships: [gConservedPair, gDependsOn] })
console.log('  A is in:', g2.objects.A.relationships.join(', '), '| roles:', g2.objects.A.roles.join(', '))
ok(g2.objects.A.relationships.length === 2, 'A participates in both relationships')
ok(g2.objects.A.composedBy === 'guarded', `A's two relationships compose to → ${g2.objects.A.composedBy}`)
ok(g2.objects.A.coin && g2.objects.A.coin.toHex() === gd.lockHex,
  `A lowers to the deployed guarded coin, byte-identical to ${gd.txid.slice(0, 12)}…:0 (${g2.objects.A.coin ? g2.objects.A.coin.toBuffer().length : '?'} B)`)
ok(g2.objects.A.obligations.length >= 5, `A carries the UNION of obligations (${g2.objects.A.obligations.length})`)
ok(g2.objects.O.roles.some((r) => r.endsWith(':sibling')), 'O is a passive tagged coin — a sibling')

console.log("\n  A's combined obligation plan (now one covenant):")
for (const o of g2.objects.A.obligations) console.log(`    · ${o}`)

console.log('\na cross-class composition (conservedPair + journal) lowers to the deployed audited coin:')
const au = onchain.readLedger().filter((x) => x.predicate === 'audited').slice(-1)[0]
const g3 = graphc.compile({ name: 'auditable-treasury', objects: ['A', 'B'], relationships: [
  { type: 'conservedPair', name: 'gt', genesis: au.params.genesis, members: ['A', 'B'],
    memberParams: [{ name: 'A', side: 0, balance: au.params.balance, owner: au.params.owner }, { name: 'B', side: 1, balance: 40, owner: au.params.owner }] },
  { type: 'journal', name: 'audit', object: 'A', seq: 0 }
] })
ok(g3.objects.A.composedBy === 'audited', `A composes to → ${g3.objects.A.composedBy}`)
ok(g3.objects.A.coin && g3.objects.A.coin.toHex() === au.lockHex,
  `A is byte-identical to the deployed audited coin ${au.txid.slice(0, 12)}…:0`)
ok(g3.objects.A.obligations.some((o) => /journal/.test(o)) && g3.objects.A.obligations.some((o) => /conserve/.test(o) || /hashOutputs/.test(o)),
  'A carries both the conserve and the journal obligations')

console.log('\nan UNBUILT composition is judged safe to build (no resource conflict):')
const g4 = graphc.compile({ name: 'guarded-audited', objects: ['A', 'B', 'O'], relationships: [
  { type: 'conservedPair', name: 'p', genesis: cv.params.genesis, members: ['A', 'B'],
    memberParams: [{ name: 'A', side: 0, balance: 60, owner }, { name: 'B', side: 1, balance: 40, owner }] },
  { type: 'dependsOn', name: 'g', gate: 'A', sibling: 'O', gateParams: { sibling: wt.params.sibling, requiredFlag: wt.params.requiredFlag } },
  { type: 'journal', name: 'j', object: 'A', seq: 0 }
] })
ok(!g4.objects.A.coin && /conserve . witness . journal/.test(g4.objects.A.composition),
  `A → ${g4.objects.A.composition}`)
ok(g4.objects.A.safeToBuild === true && g4.objects.A.conflicts.length === 0,
  'the graph proves that composition is SAFE to build (no resource conflict) — a named, checked frontier')

console.log('\nan unsound relationship in the graph refuses the whole graph:')
try {
  graphc.compile({
    name: 'inflatable', objects: ['A', 'B'],
    relationships: [{ ...conservedPair, proofs: ['coSpend', 'backtrace'] }]  // bounded total, no descent
  })
  ok(false, 'a graph with an inflatable pair should not compile')
} catch (e) {
  ok(e.code === 'E_COUNTERFEIT_INFLATION', `refused — ${e.code}`)
}

console.log(failed
  ? `\n${failed} failing`
  : '\nthe constraint graph holds: sound objects lower to deployed bytes, compositions are named, unsound graphs refuse')
process.exit(failed ? 1 : 0)
