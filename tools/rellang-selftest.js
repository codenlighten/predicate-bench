'use strict'

// The relationship surface syntax holds if: a `.rel` source parses and compiles to
// the EXACT coins deployed on mainnet, and a `.rel` that declares an unsound protocol
// refuses to compile with the ladder's typed error. The same faithfulness bar as the
// single-predicate `.pred` language.

const fs = require('fs')
const path = require('path')
const rellang = require('../src/rellang')
const onchain = require('../src/onchain')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }
const read = (f) => fs.readFileSync(path.join(__dirname, '..', 'rellang', f), 'utf8')
const deployed = (name) => onchain.requireDeployed(name)

console.log('a .rel protocol compiles to the deployed coins, byte-for-byte:')

// conservedPair -> the deployed conserve genesis pair (54c9…)
const cv = deployed('conserve')
const pair = rellang.build(read('treasury-pair.rel'), { genesis: cv.params.genesis, owner: cv.params.owner })
const side0 = pair.coins.find((c) => c.side === 0)
ok(side0 && side0.script.toHex() === cv.lockHex,
  `treasury-pair.rel → conserve side-0 is byte-identical to ${cv.txid.slice(0, 12)}…:0 (${side0.script.toBuffer().length} B)`)

// dependsOn -> the deployed witness (1754…)
const wt = deployed('witness')
const gate = rellang.build(read('escrow-leg.rel'),
  { beneficiary: wt.params.beneficiary, sibling: wt.params.sibling })
ok(gate.coins[0].script.toHex() === wt.lockHex,
  `escrow-leg.rel → witness is byte-identical to ${wt.txid.slice(0, 12)}…:${wt.vout} (${gate.coins[0].script.toBuffer().length} B)`)

console.log('\nan unsound .rel refuses to compile:')
try {
  rellang.build(read('naive-pair.rel'), { genesis: cv.params.genesis, owner: cv.params.owner })
  ok(false, 'naive-pair.rel should not compile')
} catch (e) {
  ok(e.code === 'E_COUNTERFEIT_INFLATION',
    `naive-pair.rel (bounded total, no descent) refuses — ${e.code}`)
}

console.log(failed
  ? `\n${failed} failing`
  : '\nevery relationship is expressible as text, and the text compiles to the deployed bytes')
process.exit(failed ? 1 : 0)
