'use strict'

// Redeploy the five predicates whose current code drifted from their mainnet deployment
// (see `npm run check:rebuild`): covenant, metered, titled, royalty, asset. Each is
// deployed with the current, improved code and spent back, so its fresh receipt is
// byte-identical to today's predicate and the drift is gone.
//
// The funding wallet is made the owner of every redeployed covenant, so each spends
// straight back home; `covenant` needs no signature at all. Every spend is checked against
// the real consensus interpreter BEFORE any broadcast (onchain.unlock does that), and this
// script's default mode proves the whole plan offline — no UTXOs, no coins, no broadcast.
//
//   node scripts/redeploy-drifted.js          VALIDATE only: rebuild + dry-run spend each
//   node scripts/redeploy-drifted.js --live   deploy + spend on mainnet (needs a funded wallet)

const bsv = require('@smartledger/bsv')
const onchain = require('../src/onchain')
const wallet = require('../src/wallet')
const cfg = require('../src/config')

const LIVE = process.argv.includes('--live')
const w = wallet.load()
const ME = w.address
const DEPOSIT = cfg.testOutputSats

// deploy params keyed to the wallet, plus the spend branch that returns the coin home
// `deposit` defaults to the standard test amount; asset recreates its token at a fixed
// 2000-sat output, so it is funded above that. metered's meter must be EXPIRED
// (counter >= maxHops) for the redeem branch, so it is deployed already at the limit.
const PLAN = [
  { name: 'covenant', deploy: { payTo: ME, payAmount: DEPOSIT - 200 }, spend: {} },
  { name: 'metered', deploy: { counter: 1, maxHops: 1, hopFee: 250, redeemTo: ME }, spend: { branch: 'redeem' } },
  { name: 'titled', deploy: { owner: ME, transferFee: 300 }, spend: { branch: 'transfer', newOwner: ME } },
  { name: 'royalty', deploy: { owner: ME, beneficiary: ME, royaltyBps: 250, transferFee: 400 }, spend: { branch: 'transfer', newOwner: ME } },
  { name: 'asset', deploy: { owner: ME, balance: 500 }, spend: { branch: 'transfer', newOwner: ME, ownerKey: w.privateKey }, deposit: 2500 }
]

function currentLock (name, params) {
  return onchain.loadPredicate(name).lock({ ...params, key: w.privateKey })
}

// A believable-but-fake funding outpoint, so the spend can be built and interpreted
// without a real deploy. The interpreter checks the script, not the outpoint's existence.
function syntheticDeployment (name, params, lockingScript, deposit) {
  return {
    network: cfg.network,
    predicate: name,
    params,
    txid: bsv.crypto.Hash.sha256sha256(lockingScript.toBuffer()).toString('hex'),
    vout: 0,
    satoshis: deposit,
    lockAsm: lockingScript.toASM(),
    lockHex: lockingScript.toHex()
  }
}

async function validate () {
  console.log(`validate-only — rebuild each drifted predicate and dry-run its spend (wallet ${ME})\n`)
  let bad = 0
  for (const p of PLAN) {
    const lock = currentLock(p.name, p.deploy)
    const dep = syntheticDeployment(p.name, p.deploy, lock, p.deposit ?? DEPOSIT)
    const res = await onchain.unlock(dep, p.spend, { dryRun: true })
    const ok = res.verifiedLocally === true
    if (!ok) bad++
    const size = lock.toBuffer().length
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${p.name.padEnd(9)} lock ${size}B  spend ${p.spend.branch || '(no branch)'} → verified locally: ${res.verifiedLocally}`)
    if (!ok && res.error) console.log(`         ${res.error}`)
  }
  console.log(bad
    ? `\n${bad} predicate(s) did not verify — fix the plan before going live.`
    : '\nall five rebuild to current bytes and their spends verify against the interpreter — ready to --live when the wallet is funded.')
  process.exit(bad ? 1 : 0)
}

async function live () {
  console.log(`LIVE — redeploy + spend on ${cfg.network} from ${ME}\n`)
  for (const p of PLAN) {
    console.log(`\n── ${p.name} ─────────────────────────────`)
    const dep = await onchain.deploy(p.name, p.deploy, { satoshis: p.deposit ?? DEPOSIT })
    console.log(`  deployed ${dep.txid}:0  (${dep.satoshis} sat, ${dep.lockHex.length / 2} B, fee ${dep.fee})`)
    const spent = await onchain.unlock(dep, p.spend)
    if (!spent.broadcast) { console.log(`  SPEND NOT BROADCAST — verifiedLocally=${spent.verifiedLocally}; stopping.`); process.exit(1) }
    console.log(`  spent → ${spent.txid}  (${p.spend.branch || 'pay'})`)
  }
  console.log('\nall five redeployed and spent. Run `npm run check:rebuild` — the drift should be gone.')
  console.log('Then remove them from KNOWN in tools/rebuild-check.js and commit the updated deployments.json.')
}

;(LIVE ? live() : validate()).catch((e) => { console.error(e.message); process.exit(1) })
