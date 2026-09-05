#!/usr/bin/env node
'use strict'

// Measure what the network enforces. Local isolation checks by default;
// --broadcast additionally sends each probe, which is free because a refused
// transaction never touches the chain.
const { run, MEASURED } = require('../src/probe')

const broadcast = process.argv.includes('--broadcast')

run({ broadcast }).then(rows => {
  console.log(broadcast
    ? 'probing mainnet policy (violating probes first, baseline last)\n'
    : 'comparing the library against the last measurement — pass --broadcast to re-measure\n')
  for (const r of rows) {
    const verdict = r.control ? 'control'
      : r.agrees === null ? 'unmeasured'
        : r.agrees ? 'agrees' : 'DIVERGES'
    console.log(`${r.name.padEnd(13)} ${verdict.padEnd(11)} ${r.describe}`)
    if (r.flag) {
      const lib = r.libraryTreatsAsConsensus ? 'consensus' : 'not consensus'
      const net = r.networkSaysMandatory ? 'mandatory' : 'policy'
      console.log(`${''.padEnd(14)}library: ${lib.padEnd(14)} network: ${net}`)
    }
    if (r.network) console.log(`${''.padEnd(14)}network: ${r.network}`)
    const m = MEASURED[r.name]
    if (m && !r.network) console.log(`${''.padEnd(14)}last measured: ${m.kind}${m.code ? ' (code ' + m.code + ')' : ''} — ${m.says}`)
  }
  const { MEASURED: M2, DEPLOYED_PROBE } = require('../src/probe')
  const nop = M2.DISCOURAGE_UPGRADABLE_NOPS
  console.log(`\nDISCOURAGE_UPGRADABLE_NOPS  ${nop.kind} (code ${nop.code}) — ${nop.says}`)
  console.log(`${''.padEnd(14)}${nop.note}`)
  console.log(`${''.padEnd(14)}probe script: ${DEPLOYED_PROBE.script().toASM()}`)
  console.log('\ncode 16 = mandatory (consensus)   code 64 = non-mandatory (standardness)')
}).catch(e => { console.error('error:', e.message); process.exit(1) })
