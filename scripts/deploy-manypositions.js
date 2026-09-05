'use strict'

// Deploy the many-positions family to BSV mainnet, and prove each covenant by spending it.
// Every spend is run through the REAL consensus Interpreter locally BEFORE it is broadcast,
// so a construction bug is a local failure — never a lost coin. Run a dry run first (it
// constructs and verifies everything against the chain's real UTXOs, broadcasts nothing):
//
//     DRY_RUN=1 node scripts/deploy-manypositions.js
//
// then, to actually broadcast, run it in your own session (the agent's classifier blocks it):
//
//     ! node scripts/deploy-manypositions.js
//
// The chain is: fund → spend, spend, … each tx referencing the previous, broadcast in order.

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { policyFlags } = require('../src/clauses')
const wallet = require('../src/wallet')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const R = require('../src/rabin')
const bulletin = require('../src/predicates/bulletin')
const descentbulletin = require('../src/predicates/descentbulletin')
const descentmarket = require('../src/predicates/descentmarket')
const positionv2 = require('../src/predicates/positionv2')
const Interpreter = bsv.Script.Interpreter
const Opcode = bsv.Opcode
const SIGHASH = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
const PANEL_KEYS = require('../src/predicates/oracle-panel.json').keys.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))
const DRY = !!process.env.DRY_RUN
const sha2 = bsv.crypto.Hash.sha256sha256

const w = wallet.load()
const FUNDER_PKH = bsv.crypto.Hash.sha256ripemd160(w.publicKey.toBuffer())
const DUST = 2000
let failed = 0
const log = (...a) => console.log(...a)

// verify one input against the real Interpreter under relay policy
function verify (unlock, lock, tx, i, sats) {
  const it = new Interpreter()
  const ok = it.verify(unlock, lock, tx, i, policyFlags(), new bsv.crypto.BN(sats))
  if (!ok) { failed++; log(`    LOCAL VERIFY FAILED (input ${i}): ${it.errstr}`) }
  return ok
}
const cfg = require('../src/config')
function record (predicate, tx, vout, script, params) {
  if (DRY) return
  onchain.appendLedger({ network: cfg.network, predicate, params: params || {}, txid: tx.id, vout, satoshis: tx.outputs[vout].satoshis, lockAsm: script.toASM(), lockHex: script.toHex(), at: new Date().toISOString() })
}
const broadcasts = []
async function submit (label, tx) {
  const raw = tx.serialize({ disableIsFullySigned: true, disableDustOutputs: true, disableLargeFees: true })
  if (DRY) { log(`    [dry] ${label} constructed & locally verified — ${tx.id} (${raw.length / 2} B)`); return tx.id }
  const txid = await woc.broadcast(raw)
  const id = typeof txid === 'string' ? txid.replace(/"/g, '') : tx.id
  log(`    broadcast ${label} → ${id}`)
  broadcasts.push({ label, txid: id })
  return id
}

// grind one input's OP_PUSH_TX preimage clean at a shared nLockTime
function grind (tx, i, lock, sats) {
  for (let t = 0; t < 100000; t++) { tx.nLockTime = t; const p = helpers.rawPreimage(tx, i, lock, sats, SIGHASH); if (PushTx.sFromPreimage(p)) return p }
  throw new Error('grind failed')
}
function p2pkhOut (pkh, sats) { return new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(pkh)), satoshis: sats }) }
function outpoint36 (txidHex, vout) { const t = Buffer.from(txidHex, 'hex').reverse(); const v = Buffer.alloc(4); v.writeUInt32LE(vout, 0); return Buffer.concat([t, v]) }

async function main () {
  const bal = await wallet.balance()
  log(`funding ${w.address} — ${bal.total} sat\n`)
  let utxos = (await wallet.utxos()).sort((a, b) => b.satoshis - a.satoshis)
  let fund = utxos[0]                       // the working UTXO the whole chain descends from
  const fundKey = w.privateKey

  // helper: build a funding tx that spends `fund`, emits `outs`, returns change to `fund`
  function fundTx (outs, feeSats = 500) {
    const tx = new bsv.Transaction().from([fund])
    outs.forEach((o) => tx.addOutput(o))
    const spent = outs.reduce((s, o) => s + o.satoshis, 0)
    tx.addOutput(p2pkhOut(FUNDER_PKH, fund.satoshis - spent - feeSats))
    tx.sign(fundKey)
    // advance the working UTXO to the change output for the next funding
    const changeVout = outs.length
    fund = { txId: tx.id, outputIndex: changeVout, satoshis: fund.satoshis - spent - feeSats, script: bsv.Script.buildPublicKeyHashOut(w.address).toHex() }
    return tx
  }

  // ── 1. bulletin: deploy OPEN → resolve (quorum) → read (recreate) ──────────────
  log('bulletin — a reusable outcome fact:')
  {
    const question = bsv.crypto.Hash.sha256(Buffer.from('bench: a reusable bulletin, read many times, on mainnet', 'utf8'))
    const openScript = bulletin.buildScript({ question })
    const deploy = fundTx([new bsv.Transaction.Output({ script: openScript, satoshis: DUST })])
    await submit('bulletin deploy (OPEN)', deploy); record('bulletin', deploy, 0, openScript, { question: question.toString('hex') })

    // resolve
    const rTx = new bsv.Transaction()
    rTx.addInput(new bsv.Transaction.Input({ prevTxId: deploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), openScript, DUST)
    bulletin.outputs({ branch: 'resolve', attestOutcome: 1, question, satoshis: DUST }).forEach((o) => rTx.addOutput(o))
    rTx.setScript && 0
    rTx.inputs[0].setScript(bulletin.unlock({ tx: rTx, inputIndex: 0, lockingScript: openScript, satoshis: DUST, branch: 'resolve', signers: [0, 1], attestOutcome: 1, question }))
    const resolvedScript = bulletin.buildScript({ question, status: bulletin.RESOLVED, outcome: 1 })
    if (verify(rTx.inputs[0].script, openScript, rTx, 0, DUST)) await submit('bulletin resolve (→RESOLVED)', rTx)

    // read (recreate)
    const rdTx = new bsv.Transaction()
    rdTx.addInput(new bsv.Transaction.Input({ prevTxId: rTx.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), resolvedScript, DUST - bulletin.DEFAULT_FEE)
    bulletin.outputs({ branch: 'read', outcome: 1, question, satoshis: DUST - bulletin.DEFAULT_FEE }).forEach((o) => rdTx.addOutput(o))
    rdTx.inputs[0].setScript(bulletin.unlock({ tx: rdTx, inputIndex: 0, lockingScript: resolvedScript, satoshis: DUST - bulletin.DEFAULT_FEE, branch: 'read', outcome: 1, question }))
    if (verify(rdTx.inputs[0].script, resolvedScript, rdTx, 0, DUST - bulletin.DEFAULT_FEE)) await submit('bulletin read (recreate)', rdTx)
  }

  const chunkOf = (script, varintFn) => { const b = script.toBuffer(); return Buffer.concat([varintFn(b.length), b]) }

  // ── 2. descentbulletin: deploy OPEN (genesis = the funding UTXO) → resolve (mint path) ──────
  // The genesis is the very outpoint the deploy spends, so the resolve proves descent by the
  // mint branch (parent == G). The OPEN coin is over-funded so the resolve pays its fee from
  // the one input while recreating at dust.
  log('\ndescentbulletin — a counterfeit-proof reusable fact:')
  {
    const genesis = descentbulletin.genesisOutpoint(fund.txId, fund.outputIndex)   // = the UTXO the deploy will spend
    const openScript = descentbulletin.buildScript({ genesis, m: 2 })
    const deploy = fundTx([new bsv.Transaction.Output({ script: openScript, satoshis: 3000 })])   // spends `fund` (= genesis)
    await submit('descentbulletin deploy (OPEN, genesis=funding outpoint)', deploy); record('descentbulletin', deploy, 0, openScript, { genesis: genesis.toString('hex') })

    const rTx = new bsv.Transaction()
    rTx.addInput(new bsv.Transaction.Input({ prevTxId: deploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), openScript, 3000)
    descentbulletin.outputs({ genesis, attestOutcome: 1, m: 2 }).forEach((o) => rTx.addOutput(o))   // RESOLVED @ dust; fee = 3000 − 2000
    const tc = { tx: rTx, inputIndex: 0, lockingScript: openScript, satoshis: 3000, branch: 'resolve', signers: [0, 1], attestOutcome: 1, genesis, m: 2,
      _scn: { raw1: deploy.toBuffer(), iblob2: Buffer.alloc(41), lt2: Buffer.alloc(4), parentChunk: chunkOf(openScript, descentbulletin.varint), coinScript: openScript, coinTxidInternal: sha2(deploy.toBuffer()), coinVout: 0 } }
    rTx.inputs[0].setScript(descentbulletin.unlock(tc))
    if (verify(rTx.inputs[0].script, openScript, rTx, 0, 3000)) await submit('descentbulletin resolve (mint path, descent from G)', rTx)
  }

  // ── 3. descentmarket: deploy OPEN → resolve (mint path); the unified descent+pTail coin ──────
  log('\ndescentmarket — descent ∧ the position-payout tail, unified:')
  {
    const genesis = descentmarket.genesisOutpoint(fund.txId, fund.outputIndex)
    const openScript = descentmarket.buildScript({ genesis, m: 2 })
    const deploy = fundTx([new bsv.Transaction.Output({ script: openScript, satoshis: 3000 })])
    await submit('descentmarket deploy (OPEN, genesis=funding outpoint)', deploy); record('descentmarket', deploy, 0, openScript, { genesis: genesis.toString('hex') })

    const rTx = new bsv.Transaction()
    rTx.addInput(new bsv.Transaction.Input({ prevTxId: deploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), openScript, 3000)
    descentmarket.outputs({ genesis, attestOutcome: 1, m: 2 }).forEach((o) => rTx.addOutput(o))    // RESOLVED @ dust (empty pTail here)
    const tc = { tx: rTx, inputIndex: 0, lockingScript: openScript, satoshis: 3000, branch: 'resolve', kind: 'resolve', signers: [0, 1], attestOutcome: 1, genesis, m: 2,
      _scn: { raw1: deploy.toBuffer(), iblob2: Buffer.alloc(41), lt2: Buffer.alloc(4), parentChunk: chunkOf(openScript, descentmarket.varint), parentPTail: Buffer.alloc(0), myPTail: Buffer.alloc(0), coinScript: openScript, coinTxidInternal: sha2(deploy.toBuffer()), coinVout: 0 } }
    rTx.inputs[0].setScript(descentmarket.unlock(tc))
    if (verify(rTx.inputs[0].script, openScript, rTx, 0, 3000)) await submit('descentmarket resolve (mint path, descent from G)', rTx)
  }

  log(failed ? `\n${failed} step(s) failed local verification — nothing further will be trusted` : `\n${DRY ? 'DRY RUN' : 'DONE'}: bulletin, descentbulletin, descentmarket proven on chain${DRY ? ' (locally verified)' : ''}`)
  if (!DRY && broadcasts.length) { broadcasts.forEach((b) => log(`  ${b.label}: ${b.txid}`)) }
  log('\nNote: position and positionv2 (the settlers that read these coins) are interpreter-verified in the suite; their on-chain co-spend deploy is a follow-up.')
}

main().catch((e) => { console.error('FAILED:', e.message); process.exit(1) })
