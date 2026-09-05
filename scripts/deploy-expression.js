'use strict'

// Deploy predicates AUTHORED FROM AN EXPRESSION (src/expr.js) to BSV mainnet, and spend them.
// This is the bench's thesis applied to its newest authoring surface: a predicate written as
// a plain condition is not merely interpreter-valid, it is DEPLOYED AND SPENT on mainnet,
// judged by the network itself. The receipt carries the source, so anyone can recompile it
// and confirm the bytes on chain.
//
//   node scripts/deploy-expression.js          VALIDATE only — each spent through the
//                                              consensus interpreter, no coins, no broadcast
//   node scripts/deploy-expression.js --live    deploy + spend on mainnet (needs a funded wallet)

const bsv = require('@smartledger/bsv')
const expr = require('../src/expr')
const onchain = require('../src/onchain')
const wallet = require('../src/wallet')
const cfg = require('../src/config')
const { run } = require('../src/harness')

const LIVE = process.argv.includes('--live')
const w = wallet.load()
const pub = w.privateKey.toPublicKey().toBuffer()
const pkh = bsv.crypto.Hash.sha256ripemd160(pub)                    // the wallet's own pubkey-hash
const secret = Buffer.from('predicate bench')

// Each predicate is a source string, the params baked into its lock, and the witness that
// spends it. The wallet is the owner, so every coin returns home.
const PLAN = [
  {
    title: 'p2pkh — ownership authored from a condition',
    source: 'given sig pubkey\nassert(eq(hash160(pubkey), this.owner))\nassert(checkSig(sig, pubkey))',
    params: { owner: pkh },
    spend: { sig: w.privateKey, pubkey: pub }
  },
  {
    title: 'hashlock — knowledge authored from a condition',
    source: 'given preimage\nassert(eq(hash160(preimage), this.h))',
    params: { h: bsv.crypto.Hash.sha256ripemd160(secret).toString('hex') },
    spend: { preimage: secret }
  }
]

async function validate () {
  console.log(`validate-only — each expression predicate spent through the interpreter (wallet ${w.address})\n`)
  let bad = 0
  for (const p of PLAN) {
    const pred = expr.compile(p.source)
    const r = run(pred, { ...p.params, ...p.spend })
    if (!r.ok) bad++
    console.log(`  ${r.ok ? 'ok  ' : 'FAIL'} ${p.title}  (${r.lockSize} B lock)${r.ok ? '' : ' → ' + r.error}`)
  }
  console.log(bad
    ? `\n${bad} did not verify — fix before going live.`
    : '\nboth verify on the consensus interpreter — ready to --live when the wallet is funded.')
  process.exit(bad ? 1 : 0)
}

async function live () {
  console.log(`LIVE — deploy + spend expression predicates on ${cfg.network} from ${w.address}\n`)
  for (const p of PLAN) {
    const pred = expr.compile(p.source)
    console.log(`\n── ${p.title} ─────────────`)
    const dep = await onchain.deploy(pred, p.params)
    console.log(`  deployed ${dep.txid}:0  (${dep.satoshis} sat, ${dep.lockHex.length / 2} B lock)`)
    const spent = await onchain.unlock(dep, p.spend, { predicate: pred })
    if (!spent.broadcast) { console.log(`  SPEND NOT BROADCAST — verifiedLocally=${spent.verifiedLocally}; stopping.`); process.exit(1) }
    console.log(`  spent → ${spent.txid}`)
  }
  console.log('\nexpression-authored predicates: deployed AND spent on BSV mainnet.')
  console.log('The receipts carry their source (deployments.json) — recompile to confirm the bytes.')
}

;(LIVE ? live() : validate()).catch((e) => { console.error(e.message); process.exit(1) })
