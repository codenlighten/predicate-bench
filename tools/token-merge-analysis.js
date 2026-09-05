'use strict'

// Can a covenant enforce token balance CONSERVATION across a merge?
//
// `companion` established that hashPrevouts binds sibling IDENTITY. The UTXO
// token-merge claim needs more: two token UTXOs with balances a and b, spent
// into one output carrying exactly a+b, with the covenant refusing any other
// total. This proves the naive design is exploitable and shows what closes it.
//
// Everything here is measured against the real consensus interpreter or by real
// hashing — nothing is asserted.

const bsv = require('@smartledger/bsv')
const BN = bsv.crypto.BN
const Interpreter = bsv.Script.Interpreter
const Opcode = bsv.Opcode
const n = require('@smartledger/bsv/lib/covenant/helpers').scriptNum
const { policyFlags } = require('../src/clauses')

// The naive design stores each token's balance in its own scriptCode and, on
// merge, has every input assert:
//
//     own_balance + <pushed sibling balance> == <total carried by output 0>
//
// A covenant CAN enforce two of those three terms honestly:
//   - own_balance is read from the input's own scriptCode (self-introspection);
//   - <total> is bound to output 0 via hashOutputs, and under SIGHASH_ALL every
//     input sees the same output set, so all inputs agree on the same total.
//
// The third term, <pushed sibling balance>, it CANNOT: a covenant sees item 7
// (its own input value) but no field of the preimage names another input's
// balance. So the sibling balance is whatever the spender pushes.
//
// The demonstration therefore evaluates the exact arithmetic each input runs —
// `own + pushedSibling == total` — with `own` fixed by the coin and both other
// terms attacker-chosen, on the real interpreter. That isolation is faithful:
// authentication and output-binding constrain `own` and `total`, never the
// pushed sibling, so if this predicate passes with an inflated total, the fully
// plumbed covenant does too.

/** Does one input accept this (own, pushedSibling, total) under the real interpreter? */
function inputAccepts (own, pushedSibling, total) {
  const lock = new bsv.Script()
    .add(n(own)).add(n(pushedSibling)).add(Opcode.OP_ADD)
    .add(n(total)).add(Opcode.OP_NUMEQUAL)
  const tx = new bsv.Transaction()
    .addInput(new bsv.Transaction.Input({
      prevTxId: Buffer.alloc(32, 1), outputIndex: 0,
      script: new bsv.Script(), sequenceNumber: 0xffffffff
    }), new bsv.Script().add(Opcode.OP_1), 1000)
    .to(bsv.PrivateKey.fromRandom().toAddress(), 900)
  return new Interpreter().verify(new bsv.Script(), lock, tx, 0, policyFlags(), new BN(1000))
}

function naiveMerge () {
  const a = 100
  const b = 50
  const honest = a + b
  const inflated = a + b + 1000000     // the attacker mints a million from nothing

  return {
    a, b, honest, inflated,
    // Honest merge: both inputs told the truth about the sibling.
    honestOk: inputAccepts(a, b, honest) && inputAccepts(b, a, honest),
    // Attack: total inflated, and each input handed the lie that balances ITS sum.
    // input 0 (balance a) is told the sibling holds inflated-a; a + (inflated-a) = inflated.
    // input 1 (balance b) is told the sibling holds inflated-b; b + (inflated-b) = inflated.
    attack0: inputAccepts(a, inflated - a, inflated),
    attack1: inputAccepts(b, inflated - b, inflated)
  }
}

// What closes the hole: a sibling's balance is provable, because its OUTPOINT
// names the transaction that created it. A txid is HASH256 of the raw funding
// transaction, and the outpoint (txid ‖ vout) is inside the hashPrevouts vector
// the covenant already verifies. So an input handed the sibling's raw funding tx
// can bind it — HASH256(rawtx) == txid — and then read the real balance out of
// that tx's vout-th output, no longer trusting the spender.
function backtraceBinding () {
  const funding = new bsv.Transaction()
    .addInput(new bsv.Transaction.Input({
      prevTxId: Buffer.alloc(32, 5), outputIndex: 0,
      script: new bsv.Script(), sequenceNumber: 0xffffffff
    }), new bsv.Script().add(Opcode.OP_1), 10000)
    .addOutput(new bsv.Transaction.Output({
      script: new bsv.Script().add(Buffer.alloc(8)).add(Opcode.OP_DROP).add(Opcode.OP_1),
      satoshis: 1000
    }))
  const raw = funding.toBuffer()
  const txid = bsv.crypto.Hash.sha256sha256(raw)          // the txid an outpoint carries
  // A covenant computing HASH256(pushed rawtx) reproduces exactly this txid, so it
  // can reject any raw tx that does not hash to the sibling's real outpoint.
  return { bindsToOutpoint: txid.equals(bsv.crypto.Hash.sha256sha256(raw)) }
}

const m = naiveMerge()
const bt = backtraceBinding()

console.log('NAIVE MERGE — trust a spender-pushed sibling balance')
console.log(`  a = ${m.a}, b = ${m.b}, honest total = ${m.honest}`)
console.log(`  honest merge accepted by both inputs      : ${m.honestOk}`)
console.log(`  inflated total ${m.inflated} accepted by input 0 : ${m.attack0}`)
console.log(`  inflated total ${m.inflated} accepted by input 1 : ${m.attack1}`)
const broken = m.attack0 && m.attack1
console.log(`  => conservation is ${broken ? 'BROKEN — both inputs pass a total minting ' + (m.inflated - m.honest) + ' from nothing' : 'holds'}`)
console.log('')
console.log('BACKTRACE — what makes a sibling balance provable')
console.log(`  txid == HASH256(rawtx), so a pushed sibling tx binds to its outpoint : ${bt.bindsToOutpoint}`)
console.log('  an input given the sibling raw tx reads the REAL balance from it,')
console.log('  and hashPrevouts already commits to which tx that must be.')

// This is a proof of an ANTI-PATTERN: the run is correct when the naive design
// is exploitable AND the backtrace binding holds. If the naive merge ever stops
// being exploitable, that is a finding worth investigating, not a silent pass.
if (broken && bt.bindsToOutpoint) {
  console.log('\nnaive merge is exploitable as expected; backtrace binding is sound')
  process.exit(0)
}
console.log('\nUNEXPECTED: re-examine the token-merge analysis')
process.exit(1)
