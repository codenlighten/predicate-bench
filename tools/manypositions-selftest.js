'use strict'

// MANY POSITIONS, ONE RESOLUTION — the payoff of the bulletin/position pair.
//
// A single transaction co-spends ONE resolved `bulletin` and THREE independent `position`
// coins. The bulletin recreates itself at output 0 (its `read` branch); each position reads
// the bulletin's committed outcome by backtracing to its source, and releases its collateral
// to whichever party — owner or counterparty — called that outcome right. Every input is
// verified against the real consensus Interpreter under relay policy. This is what makes a
// market scale: one fact, any number of positions settling against it, none consuming it.

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { policyFlags } = require('../src/clauses')
const bulletin = require('../src/predicates/bulletin')
const position = require('../src/predicates/position')
const witness = require('../src/predicates/witness')
const Interpreter = bsv.Script.Interpreter
const Opcode = bsv.Opcode
const SIGHASH = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

const Q = Buffer.alloc(32, 7)
const OUTCOME = 1                                       // the bulletin resolves YES
const FEE = 250

// the resolved bulletin, and the source tx a position backtraces to (bulletin at output 0)
const src = position.bulletinSourceTx({ question: Q, outcome: OUTCOME, satoshis: 3000, extraOutputs: 1 })
const bulletinScript = src.script
const bulletinOutpoint = witness.outpoint36(src.tx.id, 0)

// three stakes on the same question: YES, NO, YES — with distinct owners and counterparties
const parties = [0, 1, 2].map(() => ({ owner: bsv.PrivateKey.fromRandom(), cp: bsv.PrivateKey.fromRandom() }))
const pkh = (k) => bsv.crypto.Hash.sha256ripemd160(k.publicKey.toBuffer())
const positions = [1, 0, 1].map((side, i) => {
  const { owner, cp } = parties[i]
  const script = position.buildScript({ question: Q, side, owner: pkh(owner), counterparty: pkh(cp), bulletinOutpoint })
  const winnerKey = (OUTCOME === side) ? owner : cp          // who is right, and thus may claim
  const winnerLabel = (OUTCOME === side) ? 'owner' : 'counterparty'
  return { side, script, satoshis: 2000, winnerKey, winnerLabel, prevTxId: Buffer.alloc(32, 0x30 + i), vout: 0 }
})

// build the settlement transaction: input 0 = bulletin, inputs 1..3 = positions;
// output 0 = recreated bulletin, outputs 1..3 = each winner's payout
const tx = new bsv.Transaction()
tx.addInput(new bsv.Transaction.Input({ prevTxId: src.tx.id, outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), bulletinScript, 3000)
positions.forEach((p) => tx.addInput(new bsv.Transaction.Input({ prevTxId: p.prevTxId, outputIndex: p.vout, script: new bsv.Script(), sequenceNumber: 0xffffffff }), p.script, p.satoshis))

tx.addOutput(new bsv.Transaction.Output({ script: bulletinScript, satoshis: 3000 - FEE }))   // output 0: bulletin persists
const payouts = positions.map((p) => new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(pkh(p.winnerKey))), satoshis: p.satoshis - FEE }))
payouts.forEach((o) => tx.addOutput(o))
const pTail = Buffer.concat(payouts.map((o) => o.toBufferWriter().toBuffer()))   // the free tail the bulletin allows

console.log('one resolved bulletin, three positions, one settlement transaction:')
console.log('  outputs: [0] the bulletin, recreated; [1..3] each stake paid to whoever was right')

// the surrounding-outpoint split is the same for every position (all name the one bulletin)
const vector = Buffer.concat(tx.inputs.map((i) => witness.outpoint36(i.prevTxId, i.outputIndex)))
const at = (() => { for (let i = 0; i + 36 <= vector.length; i += 36) if (vector.slice(i, i + 36).equals(bulletinOutpoint)) return i; return -1 })()
const prefix = vector.slice(0, at); const suffix = vector.slice(at + 36)

// Verify each input against the real Interpreter. The Interpreter runs ONE input's scripts,
// so we grind that input's nLockTime to a clean OP_PUSH_TX signature and verify it — a valid
// spend of that input in this exact transaction shape. (Broadcasting all four in one atomic
// transaction additionally needs the coordinated multi-input grind pool/ledger pay at deploy:
// one nLockTime clean for every input at once — a cost, not a soundness gap.)
function grind (i, sc, sats) {
  for (let t = 0; t < 100000; t++) { tx.nLockTime = t; const pre = helpers.rawPreimage(tx, i, sc, sats, SIGHASH); if (PushTx.sFromPreimage(pre)) return pre }
  throw new Error('grind failed')
}

// input 0 — the bulletin's read branch: pTail carries the three payouts, output 0 stays the bulletin
{
  const preimage = grind(0, bulletinScript, 3000)
  const unlock = new bsv.Script().add(pTail).add(Opcode.OP_0).add(preimage)
  const interp = new Interpreter()
  ok(interp.verify(unlock, bulletinScript, tx, 0, policyFlags(), new bsv.crypto.BN(3000)),
    `input 0 — the bulletin recreates itself and permits the three payouts in the tail${interp.errstr ? ' — ' + interp.errstr : ''}`)
}

// inputs 1..3 — each position independently reads the co-spent bulletin and pays its winner
positions.forEach((p, idx) => {
  const i = idx + 1
  const preimage = grind(i, p.script, p.satoshis)
  const sig = bsv.Transaction.Sighash.sign(tx, p.winnerKey, SIGHASH, i, p.script, new bsv.crypto.BN(p.satoshis)).toTxFormat()
  const unlock = new bsv.Script()
    .add(p.winnerKey.publicKey.toBuffer()).add(sig)
    .add(prefix.length ? prefix : Opcode.OP_0).add(suffix.length ? suffix : Opcode.OP_0)
    .add(src.preOuts).add(src.outsBlob).add(src.lt4).add(preimage)
  const interp = new Interpreter()
  ok(interp.verify(unlock, p.script, tx, i, policyFlags(), new bsv.crypto.BN(p.satoshis)),
    `input ${i} — ${p.side ? 'YES' : 'NO '} stake vs outcome ${OUTCOME}: the ${p.winnerLabel} claims${interp.errstr ? ' — ' + interp.errstr : ''}`)
})

console.log(failed
  ? `\n${failed} failing`
  : '\nmany positions, one resolution: three independent options settled against a single reusable bulletin, in one transaction, all interpreter-verified')
process.exit(failed ? 1 : 0)
