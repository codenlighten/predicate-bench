#!/usr/bin/env node
'use strict'

const bsv = require('@smartledger/bsv')
const path = require('path')
const onchain = require('../src/onchain')
const woc = require('../src/woc')

// A documented txid is a claim. This checks it.
//
// Three things can be true or false independently, and conflating them is how
// documentation starts lying:
//
//   1. the transaction exists on chain
//   2. the bytes on chain match what the ledger recorded
//   3. the CURRENT code, given the recorded params, rebuilds those same bytes
//
// (3) failing is not necessarily a bug — this session hoisted the OP_PUSH_TX
// preamble and trimmed the core, so anything deployed before those changes is
// expected to differ. What matters is that the difference is *known* rather than
// discovered later by someone trusting a stale example. So a mismatch is
// reported as a generation gap, and only (1) or (2) failing is an error.

// Outputs that exist, match the ledger, and can never be spent. Both were
// script-valid and refused by node policy, and both differ from their corrected
// sibling by a SINGLE byte — which is why they are called out here rather than
// left looking like ordinary history.
const STRANDED = {
  '865288a8d4a9a7498bd7b8b732c37a3d3360f9ea45ed2721095874408f7a80a5':
    '1000 sat — no OP_BIN2NUM, so nLockTime is a non-minimal script number (MINIMALDATA)',
  '7102453e9751b88a0cae6d5d68535ad2cd20380ad0723267fe40c8d5a84818e1':
    '2000 sat — a duplicated OP_DUP leaves a stray preimage on the stack (CLEANSTACK)'
}

function rebuild (entry) {
  try {
    const predicate = onchain.loadPredicate(entry.predicate)
    // The ledger stores params as JSON; predicates accept address strings.
    const ctx = { ...entry.params }
    return predicate.lock(ctx).toHex()
  } catch (err) {
    return { error: err.message }
  }
}

async function main () {
  const ledger = onchain.readLedger()
  if (!ledger.length) { console.log('no deployments recorded'); return }

  const counts = { checked: 0, missing: 0, ledgerMismatch: 0, current: 0, olderGeneration: 0, unbuildable: 0, stranded: 0 }
  let lastPredicate = null

  for (const e of ledger) {
    if (e.predicate !== lastPredicate) { console.log(`\n${e.predicate}`); lastPredicate = e.predicate }
    counts.checked++
    const short = e.txid.slice(0, 14) + '…:' + e.vout

    let onChainHex
    try {
      const tx = new bsv.Transaction(await woc.getRawTx(e.txid))
      const out = tx.outputs[e.vout]
      if (!out) throw new Error(`no output ${e.vout}`)
      onChainHex = out.script.toHex()
    } catch (err) {
      counts.missing++
      console.log(`  ${short}  NOT FOUND ON CHAIN — ${err.message.slice(0, 60)}`)
      continue
    }

    if (onChainHex !== e.lockHex) {
      counts.ledgerMismatch++
      console.log(`  ${short}  LEDGER DISAGREES WITH CHAIN (${e.lockHex.length / 2}B recorded, ${onChainHex.length / 2}B on chain)`)
      continue
    }

    const built = rebuild(e)
    if (built && built.error) {
      counts.unbuildable++
      console.log(`  ${short}  ${onChainHex.length / 2}B  on chain = ledger; current code cannot rebuild: ${built.error.slice(0, 50)}`)
    } else if (built === onChainHex) {
      counts.current++
      console.log(`  ${short}  ${onChainHex.length / 2}B  on chain = ledger = current code`)
    } else {
      counts.olderGeneration++
      const now = typeof built === 'string' ? built.length / 2 : '?'
      console.log(`  ${short}  ${onChainHex.length / 2}B  on chain = ledger; current code builds ${now}B (earlier generation)`)
    }

    if (STRANDED[e.txid]) {
      counts.stranded++
      console.log(`  ${''.padEnd(short.length)}  UNSPENDABLE: ${STRANDED[e.txid]}`)
    }
  }

  console.log('\n' + '-'.repeat(60))
  console.log(`checked            ${counts.checked}`)
  console.log(`reproduced exactly ${counts.current}`)
  console.log(`earlier generation ${counts.olderGeneration}   (expected: the core was hoisted and trimmed)`)
  if (counts.unbuildable) console.log(`unbuildable        ${counts.unbuildable}`)
  console.log(`stranded           ${counts.stranded}   (script-valid, refused by policy, unspendable)`)
  console.log(`ledger disagrees   ${counts.ledgerMismatch}`)
  console.log(`not on chain       ${counts.missing}`)

  // Only a broken claim is a failure. A known generation gap is not.
  if (counts.missing || counts.ledgerMismatch) process.exit(1)
}

main().catch(e => { console.error('error:', e.message); process.exit(1) })
