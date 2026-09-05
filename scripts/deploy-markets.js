'use strict'

// One-shot mainnet deploy + prove-spend for the four prediction-market predicates.
//
// Run it yourself so the broadcasts come from your session, not the agent's:
//
//     ! node scripts/deploy-markets.js
//
// Every owner/resolver is the funding wallet's own pkh, so every payout returns to
// you — the net cost is just miner fees. Each step runs the real consensus Interpreter
// locally BEFORE broadcasting (onchain.unlock), so a bad spend never goes out. Safe to
// re-run: it skips a resolution that is already resolved and always deploys fresh markets.

const onchain = require('../src/onchain')
const bsv = require('@smartledger/bsv')
const wallet = require('../src/wallet')

const w = wallet.load()
const PKH = bsv.crypto.Hash.sha256ripemd160(w.publicKey.toBuffer()).toString('hex')
const Q = (s) => bsv.crypto.Hash.sha256(Buffer.from(s, 'utf8')).toString('hex')
const log = (...a) => console.log(...a)

async function main () {
  log(`funding wallet ${w.address}  (pkh ${PKH})`)
  const b = await wallet.balance()
  log(`balance: ${b.total} sat\n`)

  // ── resolution: resolve the OPEN coin already deployed, then sweep the RESOLVED coin ──
  const open = onchain.readLedger().filter((d) => d.predicate === 'resolution' && !d.hopFrom).slice(-1)[0]
  if (open) {
    log(`resolution: resolving OPEN coin ${open.txid.slice(0, 16)}…`)
    const rv = await onchain.unlock(open, { branch: 'resolve', signers: [0, 1], attestOutcome: 1 })
    log(`  resolved → ${rv.txid}  (quorum 0,1 attested outcome=1)`)
    const resolved = (rv.recreated || [])[0]
    if (resolved) {
      log(`  sweeping RESOLVED coin ${resolved.txid.slice(0, 16)}…:${resolved.vout}`)
      const sw = await onchain.unlock(resolved, { branch: 'sweep' })
      log(`  swept → ${sw.txid}  (resolver = funding wallet, funds recovered)\n`)
    }
  } else {
    log('resolution: no OPEN coin found; deploying a fresh one')
    const dep = await onchain.deploy('resolution', { question: Q('bench: does an oracle quorum resolve a market on BSV mainnet?'), resolver: PKH, m: 2 })
    log(`  deployed → ${dep.txid}`)
    const rv = await onchain.unlock(dep, { branch: 'resolve', signers: [0, 1], attestOutcome: 1 })
    log(`  resolved → ${rv.txid}`)
    const resolved = (rv.recreated || [])[0]
    if (resolved) { const sw = await onchain.unlock(resolved, { branch: 'sweep' }); log(`  swept → ${sw.txid}\n`) }
  }

  // ── market (binary): deploy, then settle YES (pot → funding wallet) ──
  {
    log('market: deploying a binary market (YES=NO=funding wallet)')
    const dep = await onchain.deploy('market', { question: Q('bench: will the binary market settle to the quorum-attested side?'), yesPKH: PKH, noPKH: PKH, m: 2 })
    log(`  deployed → ${dep.txid}`)
    const s = await onchain.unlock(dep, { branch: 'settle', signers: [0, 1], attestOutcome: 1 })
    log(`  settled YES → ${s.txid}  (whole pot to the winner)\n`)
  }

  // ── marketN (categorical, K=3): deploy, then settle outcome 1 ──
  {
    log('marketN: deploying a categorical market (3 outcomes, all = funding wallet)')
    const dep = await onchain.deploy('marketN', { question: Q('bench: which of three outcomes does the quorum name?'), owners: [PKH, PKH, PKH], m: 2 })
    log(`  deployed → ${dep.txid}`)
    const s = await onchain.unlock(dep, { branch: 'settle', signers: [0, 2], attestOutcome: 1 })
    log(`  settled outcome 1 → ${s.txid}\n`)
  }

  // ── marketScalar: deploy (LOW=6000, HIGH=7000), then settle v=6500 (split LONG/SHORT) ──
  {
    log('marketScalar: deploying a scalar market (LONG=SHORT=funding wallet, LOW 6000 HIGH 7000)')
    const dep = await onchain.deploy('marketScalar', { question: Q('bench: what value do the oracles attest for the scalar market?'), low: 6000, high: 7000, pkhL: PKH, pkhS: PKH, m: 2 })
    log(`  deployed → ${dep.txid}`)
    const s = await onchain.unlock(dep, { branch: 'settle', signers: [0, 1], attestValue: 6500 })
    log(`  settled v=6500 → ${s.txid}  (piecewise split, both legs to funding wallet)\n`)
  }

  const after = await wallet.balance()
  log(`done. balance ${after.total} sat (was ${b.total}); every txid above is on BSV mainnet.`)
  log('the deployments are recorded in deployments.json.')
}

main().catch((e) => { console.error('FAILED:', e.message); process.exit(1) })
