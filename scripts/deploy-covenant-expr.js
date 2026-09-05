'use strict'

// Deploy a COVENANT authored from an expression to BSV mainnet, and — for the stateful one —
// advance its state on chain. This is the covenant frontier meeting the bench's thesis: a
// stateful covenant written as `state count; recreate` is not merely interpreter-valid, its
// counter provably increments 0 → 1 → 2 through real, spent UTXOs, each recorded with its
// source so anyone can recompile and confirm the bytes on chain.
//
//   node scripts/deploy-covenant-expr.js          VALIDATE only (interpreter, no coins)
//   node scripts/deploy-covenant-expr.js --live    deploy + advance on mainnet (funded wallet)

const bsv = require('@smartledger/bsv')
const expr = require('../src/expr')
const onchain = require('../src/onchain')
const wallet = require('../src/wallet')
const cfg = require('../src/config')

const LIVE = process.argv.includes('--live')
const w = wallet.load()
const HOPS = 2
const COUNTER = 'state count: u32\nrecreate(this.hopFee)'
const params = { count: 0, hopFee: 150 }

function synthetic (pred, p) {
  const lock = pred.lock(p)
  return {
    network: cfg.network, predicate: 'expr', source: pred.source, params: p,
    txid: bsv.crypto.Hash.sha256sha256(lock.toBuffer()).toString('hex'),
    vout: 0, satoshis: 5000, lockAsm: lock.toASM(), lockHex: lock.toHex()
  }
}

async function validate () {
  console.log(`validate-only — the counter covenant, spent through the interpreter (wallet ${w.address})\n`)
  const p = expr.compile(COUNTER)
  const res = await onchain.unlock(synthetic(p, params), {}, { predicate: p, dryRun: true })
  const cont = p.continuation({ ...params, lockingScript: p.lock(params), satoshis: 5000 })
  const ok = res.verifiedLocally === true && cont.params.count === 1
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} state count:u32; recreate — count 0 → ${cont.params.count}, spend verified: ${res.verifiedLocally}  (${p.lock(params).toBuffer().length} B)`)
  console.log(ok
    ? '\nready to --live when the wallet is funded: deploy count=0, then advance it on chain.'
    : '\ndid not verify — do not go live.')
  process.exit(ok ? 0 : 1)
}

async function live () {
  console.log(`LIVE — deploy the counter covenant and advance its state on ${cfg.network} from ${w.address}\n`)
  const p = expr.compile(COUNTER)
  let dep = await onchain.deploy(p, params)
  console.log(`  deployed count=0  ${dep.txid}:0  (${dep.satoshis} sat, ${dep.lockHex.length / 2} B)`)
  for (let hop = 1; hop <= HOPS; hop++) {
    const spent = await onchain.unlock(dep, {}, { predicate: p })
    if (!spent.broadcast || !spent.recreated || !spent.recreated.length) {
      console.log(`  hop ${hop} did not recreate — verifiedLocally=${spent.verifiedLocally}; stopping.`); process.exit(1)
    }
    dep = spent.recreated[0]
    console.log(`  advanced → count=${dep.params.count}  ${spent.txid} → ${dep.txid}:${dep.vout}  (${dep.satoshis} sat)`)
  }
  console.log(`\na stateful covenant authored from an expression: deployed and advanced 0 → ${HOPS} on BSV mainnet.`)
  console.log('The recreated coins carry their source and the counter in params — recompile to confirm.')
}

;(LIVE ? live() : validate()).catch((e) => { console.error(e.message); process.exit(1) })
