'use strict'

// The .graph surface syntax holds if a whole protocol, written as text, compiles to
// the coins the objects deploy as — the composed object byte-identical to what is on
// chain. The third and final tier of the language: .pred (predicates), .rel
// (relationships), .graph (protocols), all writable, all matching mainnet.

const fs = require('fs')
const path = require('path')
const graphlang = require('../src/graphlang')
const onchain = require('../src/onchain')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

const gd = onchain.requireDeployed('guarded')
const src = fs.readFileSync(path.join(__dirname, '..', 'graphlang', 'escrowed-treasury.graph'), 'utf8')

const g = graphlang.build(src, {
  genesis: gd.params.genesis,
  owner: gd.params.owner,
  oracle: Buffer.from(gd.params.oracle, 'hex')
})

console.log('a .graph protocol compiles its objects to their coins:')
ok(g.objects.A && g.objects.B && g.objects.O, 'all three objects resolved (A, B, O)')
ok(g.objects.A.relationships.length === 2, 'A stands in both relationships (conservedPair + dependsOn)')
ok(g.objects.A.composedBy === 'guarded', `A composes to → ${g.objects.A.composedBy}`)
ok(g.objects.A.coin && g.objects.A.coin.toHex() === gd.lockHex,
  `A is byte-identical to the deployed guarded coin ${gd.txid.slice(0, 12)}…:0 (${g.objects.A.coin ? g.objects.A.coin.toBuffer().length : '?'} B)`)
ok(g.objects.B.coin && !g.objects.B.composedBy, 'B, in one relationship, lowers to a plain conserve coin')
ok(g.objects.O.roles.some((r) => r.endsWith(':sibling')), 'O is a passive tagged coin — a sibling')

// a cross-class .graph: conservedPair + journal → the composed audited coin
const au = onchain.requireDeployed('audited')
const asrc = fs.readFileSync(path.join(__dirname, '..', 'graphlang', 'auditable-treasury.graph'), 'utf8')
const ag = graphlang.build(asrc, { genesis: au.params.genesis, owner: au.params.owner })
console.log('\na cross-class .graph lowers to the composed audited coin:')
ok(ag.objects.A.composedBy === 'audited' && ag.objects.A.coin && ag.objects.A.coin.toHex() === au.lockHex,
  `auditable-treasury.graph → A is byte-identical to the deployed audited ${au.txid.slice(0, 12)}…:0`)

console.log(failed
  ? `\n${failed} failing`
  : '\nthe whole protocol is expressible as text, and the text compiles to the deployed bytes')
process.exit(failed ? 1 : 0)
