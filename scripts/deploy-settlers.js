'use strict'

// Deploy the two position SETTLERS to mainnet — the coins that READ a market and pay whoever
// was right. Each settles in a two-input co-spend: the position and the coin it reads are spent
// together, the coin recreated in the same transaction while the position's collateral goes to
// the winner. Both inputs use OP_PUSH_TX, so we grind one shared nLockTime clean for both, then
// verify each input against the real Interpreter locally before broadcasting.
//
//     DRY_RUN=1 node scripts/deploy-settlers.js      # construct + verify, broadcast nothing
//     ! node scripts/deploy-settlers.js              # broadcast (run in your own session)

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { policyFlags } = require('../src/clauses')
const wallet = require('../src/wallet')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const cfg = require('../src/config')
const bulletin = require('../src/predicates/bulletin')
const position = require('../src/predicates/position')
const descentmarket = require('../src/predicates/descentmarket')
const positionv2 = require('../src/predicates/positionv2')
const witness = require('../src/predicates/witness')
const Interpreter = bsv.Script.Interpreter
const Opcode = bsv.Opcode
const SIGHASH = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
const DRY = !!process.env.DRY_RUN
const sha2 = bsv.crypto.Hash.sha256sha256

const w = wallet.load()
const FUNDER_PKH = bsv.crypto.Hash.sha256ripemd160(w.publicKey.toBuffer())
let failed = 0
const log = (...a) => console.log(...a)
const broadcasts = []

function verify (unlock, lock, tx, i, sats) {
  const it = new Interpreter()
  const ok = it.verify(unlock, lock, tx, i, policyFlags(), new bsv.crypto.BN(sats))
  if (!ok) { failed++; log(`    LOCAL VERIFY FAILED (input ${i}): ${it.errstr}`) }
  return ok
}
async function submit (label, tx) {
  const raw = tx.serialize({ disableIsFullySigned: true, disableDustOutputs: true, disableLargeFees: true })
  if (DRY) { log(`    [dry] ${label} — ${tx.id} (${raw.length / 2} B)`); return tx.id }
  const id = (await woc.broadcast(raw)).toString().replace(/"/g, '')
  log(`    broadcast ${label} → ${id}`); broadcasts.push({ label, txid: id }); return id
}
function record (predicate, tx, vout, script, params) {
  if (DRY) return
  onchain.appendLedger({ network: cfg.network, predicate, params: params || {}, txid: tx.id, vout, satoshis: tx.outputs[vout].satoshis, lockAsm: script.toASM(), lockHex: script.toHex(), at: new Date().toISOString() })
}
function p2pkhOut (pkh, sats) { return new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(pkh)), satoshis: sats }) }
// grind ONE shared nLockTime under which every listed input has a clean OP_PUSH_TX preimage
function grindShared (tx, inputs) {
  for (let t = 0; t < 400000; t++) {
    tx.nLockTime = t
    if (inputs.every(({ lock, sats }, i) => PushTx.sFromPreimage(helpers.rawPreimage(tx, i, lock, sats, SIGHASH)))) return t
  }
  throw new Error('shared grind failed')
}
function surrounding (tx, outpoint) {
  const vector = Buffer.concat(tx.inputs.map((i) => witness.outpoint36(i.prevTxId, i.outputIndex)))
  let at = -1; for (let i = 0; i + 36 <= vector.length; i += 36) if (vector.slice(i, i + 36).equals(outpoint)) at = i
  return { prefix: at >= 0 ? vector.slice(0, at) : vector.slice(0, 36), suffix: at >= 0 ? vector.slice(at + 36) : vector.slice(36) }
}

async function main () {
  const bal = await wallet.balance()
  log(`funding ${w.address} — ${bal.total} sat\n`)
  // fetch the REAL current UTXOs from the chain (the local wallet cache can be stale after
  // a custom deploy that did not record its spends), and take the largest spendable one.
  const chainUtxos = (await woc.getUtxos(w.address)).map((u) => ({ txId: u.txId, outputIndex: u.outputIndex, satoshis: u.satoshis, script: bsv.Script.buildPublicKeyHashOut(w.address).toHex() }))
  let fund = chainUtxos.sort((a, b) => b.satoshis - a.satoshis)[0]
  if (!fund) throw new Error('no spendable UTXO found on chain')
  log(`working UTXO: ${fund.txId.slice(0, 16)}…:${fund.outputIndex} (${fund.satoshis} sat)\n`)
  function fundTx (outs, feeSats = 500) {
    const tx = new bsv.Transaction().from([fund])
    outs.forEach((o) => tx.addOutput(o))
    const spent = outs.reduce((s, o) => s + o.satoshis, 0)
    tx.addOutput(p2pkhOut(FUNDER_PKH, fund.satoshis - spent - feeSats)); tx.sign(w.privateKey)
    fund = { txId: tx.id, outputIndex: outs.length, satoshis: fund.satoshis - spent - feeSats, script: bsv.Script.buildPublicKeyHashOut(w.address).toHex() }
    return tx
  }

  // ── position + bulletin: deploy a bulletin, resolve it, then co-spend it with a position ──
  log('position — a binary option settled by co-spending a bulletin:')
  {
    const question = bsv.crypto.Hash.sha256(Buffer.from('bench: a settled position, co-spending a bulletin, on mainnet', 'utf8'))
    const owner = w.privateKey; const cp = bsv.PrivateKey.fromRandom()   // owner = the funding wallet, so its winnings return home
    const oPKH = FUNDER_PKH
    const cPKH = bsv.crypto.Hash.sha256ripemd160(cp.publicKey.toBuffer())

    // bulletin: OPEN(3000) → resolve → RESOLVED(2750). The resolve tx is the position's source.
    const openScript = bulletin.buildScript({ question })
    const bDeploy = fundTx([new bsv.Transaction.Output({ script: openScript, satoshis: 3000 })])
    await submit('bulletin deploy (OPEN)', bDeploy)
    const resolvedScript = bulletin.buildScript({ question, status: bulletin.RESOLVED, outcome: 1 })
    const bResolve = new bsv.Transaction()
    bResolve.addInput(new bsv.Transaction.Input({ prevTxId: bDeploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), openScript, 3000)
    bResolve.addOutput(new bsv.Transaction.Output({ script: resolvedScript, satoshis: 2750 }))
    bResolve.inputs[0].setScript(bulletin.unlock({ tx: bResolve, inputIndex: 0, lockingScript: openScript, satoshis: 3000, branch: 'resolve', signers: [0, 1], attestOutcome: 1, question, fee: 250 }))
    if (!verify(bResolve.inputs[0].script, openScript, bResolve, 0, 3000)) return finish()
    await submit('bulletin resolve (→RESOLVED, the source)', bResolve)

    // position: bakes the RESOLVED bulletin's outpoint (bResolve:0); side YES, so with outcome YES the owner wins
    const posScript = position.buildScript({ question, side: 1, owner: oPKH, counterparty: cPKH, bulletinOutpoint: witness.outpoint36(bResolve.id, 0) })
    const pDeploy = fundTx([new bsv.Transaction.Output({ script: posScript, satoshis: 2000 })])
    await submit('position deploy', pDeploy); record('position', pDeploy, 0, posScript, { question: question.toString('hex'), side: 1 })

    // settle: co-spend [position(0) + RESOLVED bulletin(1)] → [recreated bulletin(0) + owner payout(1)]
    const src = { tx: bResolve, ...witness.decomposeSource(bResolve.toBuffer()) }
    const settle = new bsv.Transaction()
    settle.addInput(new bsv.Transaction.Input({ prevTxId: pDeploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), posScript, 2000)
    settle.addInput(new bsv.Transaction.Input({ prevTxId: bResolve.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), resolvedScript, 2750)
    settle.addOutput(new bsv.Transaction.Output({ script: resolvedScript, satoshis: 2500 }))     // output 0: bulletin recreated (2750 − 250)
    const ownerPayout = p2pkhOut(oPKH, 1250)   // fee = 2000+2750-2500-1250 = 1000, covers the ~6KB tx
    settle.addOutput(ownerPayout)                                                                // output 1: the winner's collateral
    const pTail = ownerPayout.toBufferWriter().toBuffer()
    grindShared(settle, [{ lock: posScript, sats: 2000 }, { lock: resolvedScript, sats: 2750 }])

    // input 1 — the bulletin's read branch, pTail = the owner payout
    const pre1 = helpers.rawPreimage(settle, 1, resolvedScript, 2750, SIGHASH)
    settle.inputs[1].setScript(new bsv.Script().add(pTail).add(Opcode.OP_0).add(pre1))
    // input 0 — the position reads the co-spent bulletin and the owner (winner) signs
    const { prefix, suffix } = surrounding(settle, witness.outpoint36(bResolve.id, 0))
    const pre0 = helpers.rawPreimage(settle, 0, posScript, 2000, SIGHASH)
    const sig = bsv.Transaction.Sighash.sign(settle, owner, SIGHASH, 0, posScript, new bsv.crypto.BN(2000)).toTxFormat()
    settle.inputs[0].setScript(new bsv.Script().add(owner.publicKey.toBuffer()).add(sig)
      .add(prefix.length ? prefix : Opcode.OP_0).add(suffix.length ? suffix : Opcode.OP_0)
      .add(src.preOuts).add(src.outsBlob).add(src.lt4).add(pre0))

    const okB = verify(settle.inputs[1].script, resolvedScript, settle, 1, 2750)
    const okP = verify(settle.inputs[0].script, posScript, settle, 0, 2000)
    if (okB && okP) await submit('position settle (co-spend: owner claims the YES outcome)', settle)
  }

  // ── positionv2 + descentmarket: same, but the position identifies its market by covenant hash ──
  log('\npositionv2 — a position settled by market identity, against a descentmarket:')
  {
    const genesis = descentmarket.genesisOutpoint(fund.txId, fund.outputIndex)   // the funding outpoint the deploy spends
    const owner = w.privateKey; const cp = bsv.PrivateKey.fromRandom()   // owner = the funding wallet, so its winnings return home
    const oPKH = FUNDER_PKH
    const cPKH = bsv.crypto.Hash.sha256ripemd160(cp.publicKey.toBuffer())

    // descentmarket: OPEN must be DUST (the descent rebuild reconstructs a dust-valued parent),
    // so the resolve pays its fee from a SECOND input. The deploy emits the OPEN coin AND a fee UTXO.
    const openScript = descentmarket.buildScript({ genesis, m: 2 })
    const dDeploy = fundTx([
      new bsv.Transaction.Output({ script: openScript, satoshis: 2000 }),    // OPEN @ dust
      p2pkhOut(FUNDER_PKH, 2000)                                             // a fee UTXO for the resolve
    ])
    await submit('descentmarket deploy (OPEN @ dust + a fee UTXO)', dDeploy)
    const resolvedScript = descentmarket.buildScript({ genesis, status: descentmarket.RESOLVED, outcome: 1, m: 2 })
    const varintOf = (len) => (len < 253 ? Buffer.from([len]) : Buffer.concat([Buffer.from([0xfd]), (() => { const b = Buffer.alloc(2); b.writeUInt16LE(len, 0); return b })()]))
    const chunkOf = (s) => { const b = s.toBuffer(); return Buffer.concat([varintOf(b.length), b]) }
    const dResolve = new bsv.Transaction()
    dResolve.addInput(new bsv.Transaction.Input({ prevTxId: dDeploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), openScript, 2000)         // OPEN (input 0)
    dResolve.addInput(new bsv.Transaction.Input({ prevTxId: dDeploy.id, outputIndex: 1, script: new bsv.Script(), sequenceNumber: 0xffffffff }), bsv.Script.buildPublicKeyHashOut(w.address), 2000)   // fee (input 1)
    dResolve.addOutput(new bsv.Transaction.Output({ script: resolvedScript, satoshis: 2000 }))     // RESOLVED @ dust; fee = the 2000 fee input
    dResolve.inputs[0].setScript(descentmarket.unlock({ tx: dResolve, inputIndex: 0, lockingScript: openScript, satoshis: 2000, branch: 'resolve', kind: 'resolve', signers: [0, 1], attestOutcome: 1, genesis, m: 2,
      _scn: { raw1: dDeploy.toBuffer(), iblob2: Buffer.alloc(41), lt2: Buffer.alloc(4), parentChunk: chunkOf(openScript), parentPTail: Buffer.alloc(0), myPTail: Buffer.alloc(0), coinScript: openScript, coinTxidInternal: sha2(dDeploy.toBuffer()), coinVout: 0 } }))
    // sign the fee input (input 1) at the nLockTime the covenant grind fixed
    const feeSig = bsv.Transaction.Sighash.sign(dResolve, w.privateKey, SIGHASH, 1, bsv.Script.buildPublicKeyHashOut(w.address), new bsv.crypto.BN(2000)).toTxFormat()
    dResolve.inputs[1].setScript(new bsv.Script().add(feeSig).add(w.publicKey.toBuffer()))
    if (!verify(dResolve.inputs[0].script, openScript, dResolve, 0, 2000)) return finish()
    if (!verify(dResolve.inputs[1].script, bsv.Script.buildPublicKeyHashOut(w.address), dResolve, 1, 2000)) return finish()
    await submit('descentmarket resolve (mint, the source)', dResolve)

    // positionv2: bakes the market IDENTITY (covenant hash committing to genesis)
    const posScript = positionv2.buildScript({ market: positionv2.marketId(genesis), side: 1, owner: oPKH, counterparty: cPKH })
    const pDeploy = fundTx([new bsv.Transaction.Output({ script: posScript, satoshis: 4000 })])   // larger collateral: the identity co-spend is a big tx
    await submit('positionv2 deploy', pDeploy); record('positionv2', pDeploy, 0, posScript, { genesis: genesis.toString('hex'), side: 1 })

    // settle: co-spend [positionv2(0) + RESOLVED descentmarket(1)] → [recreated descentmarket(0) + owner payout(1)]
    const src = { tx: dResolve, ...witness.decomposeSource(dResolve.toBuffer()) }
    const settle = new bsv.Transaction()
    settle.addInput(new bsv.Transaction.Input({ prevTxId: pDeploy.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), posScript, 4000)
    settle.addInput(new bsv.Transaction.Input({ prevTxId: dResolve.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), resolvedScript, 2000)
    settle.addOutput(new bsv.Transaction.Output({ script: resolvedScript, satoshis: 2000 }))       // output 0: descentmarket recreated (value kept)
    const ownerPayout = p2pkhOut(oPKH, 1500)   // fee = 4000+2000-2000-1500 = 2500, covers the ~18KB tx
    settle.addOutput(ownerPayout)                                                                  // output 1: the winner's collateral (− fee)
    const myPTail = ownerPayout.toBufferWriter().toBuffer()
    grindShared(settle, [{ lock: posScript, sats: 4000 }, { lock: resolvedScript, sats: 2000 }])

    // input 1 — the descentmarket read branch: descent (raw1 = the resolve tx) + recreate + pTail
    const dpd = decomposeGeneric(dResolve.toBuffer())   // the descentmarket coin's funding = dResolve; its parent is the OPEN coin
    const pre1 = helpers.rawPreimage(settle, 1, resolvedScript, 2000, SIGHASH)
    // parent of the RESOLVED coin = OPEN coin (input 0 of dResolve); parent's funding = dDeploy
    const parentPd = decomposeGeneric(dDeploy.toBuffer())
    settle.inputs[1].setScript(new bsv.Script()
      .add(dResolve.toBuffer())                       // raw1: the RESOLVED coin's funding
      .add(parentPd.iblob).add(parentPd.lt4).add(chunkOf(openScript))   // iblob2, lt2, parentChunk (the OPEN coin)
      .add(parentPd.pTail.length ? parentPd.pTail : Opcode.OP_0)        // parentPTail
      .add(myPTail).add(Opcode.OP_0).add(pre1))
    // input 0 — positionv2 reads the co-spent descentmarket by identity, owner signs
    const { prefix, suffix } = surrounding(settle, witness.outpoint36(dResolve.id, 0))
    const pre0 = helpers.rawPreimage(settle, 0, posScript, 4000, SIGHASH)
    const sig = bsv.Transaction.Sighash.sign(settle, owner, SIGHASH, 0, posScript, new bsv.crypto.BN(4000)).toTxFormat()
    settle.inputs[0].setScript(new bsv.Script().add(owner.publicKey.toBuffer()).add(sig)
      .add(prefix.length ? prefix : Opcode.OP_0).add(suffix.length ? suffix : Opcode.OP_0)
      .add(src.preOuts).add(src.outsBlob).add(src.lt4).add(pre0))

    const okD = verify(settle.inputs[1].script, resolvedScript, settle, 1, 2000)
    const okP = verify(settle.inputs[0].script, posScript, settle, 0, 4000)
    if (okD && okP) await submit('positionv2 settle (co-spend by identity: owner claims)', settle)
  }

  finish()
  function finish () {
    log(failed ? `\n${failed} step(s) failed local verification — broadcast stopped` : `\n${DRY ? 'DRY RUN' : 'DONE'}: position and positionv2 settled by two-input co-spend${DRY ? ' (locally verified)' : ''}`)
    if (!DRY && broadcasts.length) broadcasts.forEach((b) => log(`  ${b.label}: ${b.txid}`))
  }
}

// split any tx into { iblob(inputCount‖inputs‖outCount), out0chunk, pTail(outputs 1..), lt4 }
function decomposeGeneric (raw) {
  const reader = new bsv.encoding.BufferReader(raw)
  reader.read(4); const inC = reader.readVarintNum()
  for (let i = 0; i < inC; i++) { reader.read(32); reader.read(4); const sl = reader.readVarintNum(); reader.read(sl); reader.read(4) }
  const outC = reader.readVarintNum(); const iblob = raw.slice(4, reader.pos)
  reader.read(8); const sl0 = reader.readVarintNum(); reader.read(sl0)
  const pTailStart = reader.pos
  for (let i = 1; i < outC; i++) { reader.read(8); const sl = reader.readVarintNum(); reader.read(sl) }
  return { iblob, pTail: raw.slice(pTailStart, reader.pos), lt4: raw.slice(reader.pos) }
}

main().catch((e) => { console.error('FAILED:', e.message); process.exit(1) })
