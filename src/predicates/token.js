'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const covsteps = require('../covsteps')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A fungible token whose balance is CONSERVED, in both directions:
//
//   merge   two token UTXOs (balances a, b) -> one carrying exactly a+b
//   split   one token (balance c) -> two carrying x and y, with x+y = c
//
// The interesting half is merge, and the reason it is hard is that a covenant
// cannot read a sibling's balance from its own preimage. It authenticates it by
// BACKTRACE: the sibling's outpoint names its funding tx, a txid is
// HASH256(rawtx), so the covenant rebuilds the funding tx with the CLAIMED
// balance spliced into the sibling's own script and requires the rebuild to hash
// to the real txid. A lie changes the bytes and misses the hash. See
// docs/cross-input.md and docs/predicates.md#token.
//
// Split is the easy direction: one input, so there is no sibling to prove. The
// covenant reads its own balance and requires the two outputs it builds to sum to
// it, bound through hashOutputs.
//
// Constraints that keep the backtrace sound: a token holds a fixed DUST value in
// satoshis (balance lives in the scriptCode, decoupled), and a token transaction
// is single-output (a merge or a mint) or exactly two token outputs (a split).
// The merge backtrace reconstructs whichever of those two shapes the sibling came
// from — fully, from the claimed balances — so nothing is left opaque to slide.
//
// Proves CONSERVATION, not AUTHENTICITY (that inputs descend from a real
// issuance) — the unbounded back-to-genesis problem, out of scope by design.

const BAL_BYTES = 8
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1    // chunk = varint ‖ 0x08 push-op ‖ balance ‖ tail
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')

function balanceLE (v) { const b = Buffer.alloc(BAL_BYTES); b.writeUIntLE(v, 0, 6); return b }
function dustLE () { const b = Buffer.alloc(8); b.writeUIntLE(DUST, 0, 6); return b }

function buildScript ({ balance }) {
  const s = new Script()
  s.add(balanceLE(balance)).add(Opcode.OP_DROP)     // state: our balance

  // Both branch bodies live in src/covsteps.js (tokEmitMerge / tokEmitSplit),
  // shared with the compiler so the spec and the predicate cannot drift.
  C.authenticateThenBranch(s)                        // authenticates preimage, consumes the flag, opens OP_IF
  covsteps.tokEmitMerge(new StackAsm(s).given(['lt4', 'iblob', 'outsBlob', 'sibBal8', 'sibling', 'preimage']))
  s.add(Opcode.OP_ELSE)
  covsteps.tokEmitSplit(new StackAsm(s).given(['balA8', 'balB8', 'preimage']))
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- funding decomposition, shared by tests and the deploy path ----

function varint (len) {
  if (len < 253) return Buffer.from([len])
  const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b
}

/** The output section (concatenated TxOuts) for token outputs of these balances. */
function outsBlobFor (balances) {
  return Buffer.concat(balances.map(bal => {
    const scriptBuf = buildScript({ balance: bal }).toBuffer()
    return Buffer.concat([dustLE(), varint(scriptBuf.length), scriptBuf])
  }))
}

/**
 * Decompose a token funding tx (1 or 2 token outputs) for the backtrace, asserting
 * the shape by round-tripping the reassembly.
 */
function decomposeFunding (raw, balances) {
  const outsBlob = outsBlobFor(balances)
  const lt4 = raw.slice(raw.length - 4)
  const iblob = raw.slice(4, raw.length - (1 + outsBlob.length + 4))
  const reassembled = Buffer.concat([raw.slice(0, 4), iblob, Buffer.from([balances.length]), outsBlob, lt4])
  if (!reassembled.equals(raw)) {
    throw new Error('funding is not a token funding tx of this shape (reassembly mismatch)')
  }
  return { iblob, lt4, outsBlob, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}

/** Build a dummy token funding tx (1 or 2 outputs) and decompose it. */
function tokenFunding (balances) {
  const f = new bsv.Transaction()
  f.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.alloc(32, 3), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), 5000)
  for (const bal of balances) {
    f.addOutput(new bsv.Transaction.Output({ script: buildScript({ balance: bal }), satoshis: DUST }))
  }
  const raw = f.toBuffer()
  return { raw, ...decomposeFunding(raw, balances) }
}

/** The sibling's real balance, whether it came from a mint/merge or a split. */
function effectiveSibBalance ({ sibBalance, sibSplit, sibB0, sibB1, sibVout = 0 }) {
  return sibSplit ? [sibB0, sibB1][sibVout] : sibBalance
}

/** The sibling of a merge: which funding tx created it, its vout, and its balance. */
function mergeSibling ({ sibBalance, sibSplit, sibB0, sibB1, sibVout = 0, wrongSibTxid }) {
  const balances = sibSplit ? [sibB0, sibB1] : [sibBalance]
  const f = tokenFunding(balances)
  return { f, vout: sibVout, sibBalance: balances[sibVout], wrongSibTxid }
}

const MERGE = Opcode.OP_1
const SPLIT = Opcode.OP_0

module.exports = {
  name: 'token',
  describe: 'a fungible token conserved across merge and split, the merge verified by backtrace',
  example: () => ({ balance: 300, sibBalance: 200, branch: 'merge' }),
  BAL_BYTES,
  DUST,
  balanceLE,
  buildScript,
  tokenFunding,
  decomposeFunding,
  outsBlobFor,
  varint,

  lock ({ balance }) {
    if (!Number.isInteger(balance) || balance <= 0) throw new Error('balance must be a positive integer')
    return buildScript({ balance })
  },

  siblings (tc) {
    if ((tc.branch || 'merge') !== 'merge') return undefined
    const { f, vout, wrongSibTxid } = mergeSibling(tc)
    const display = Buffer.from(f.txidInternal); display.reverse()
    return [{ prevTxId: wrongSibTxid ? Buffer.alloc(32, 0xab) : display, outputIndex: vout, satoshis: DUST }]
  },

  outputs ({ branch = 'merge', balance, sibBalance, splitA, splitB,
    actualOutBalance, actualSplitA, actualSplitB }) {
    if (branch === 'split') {
      const a = actualSplitA ?? splitA
      const b = actualSplitB ?? splitB
      return [a, b].map(bal => new bsv.Transaction.Output({
        script: buildScript({ balance: bal }), satoshis: DUST
      }))
    }
    const outBal = actualOutBalance ?? (balance + effectiveSibBalance(arguments[0]))
    return [new bsv.Transaction.Output({ script: buildScript({ balance: outBal }), satoshis: DUST })]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType, branch = 'merge',
      claimSibBalance, splitA, splitB } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)

    // merge witness is shape-independent of the grind, so build it once
    let merge
    if (branch === 'merge') {
      const { f, vout, sibBalance } = mergeSibling(tc)
      const voutLE = Buffer.alloc(4); voutLE.writeUInt32LE(vout, 0)
      const sibling36 = Buffer.concat([f.txidInternal, voutLE])
      const sibBal8 = balanceLE(claimSibBalance ?? sibBalance)
      merge = { lt4: f.lt4, iblob: f.iblob, outsBlob: f.outsBlob, sibBal8, sibling36 }
    }

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue

      if (branch === 'split') {
        // [balA8, balB8, SPLIT, preimage]
        return new Script()
          .add(balanceLE(splitA)).add(balanceLE(splitB)).add(SPLIT).add(preimage)
      }
      // merge: [lt4, iblob, outsBlob, sibBal8, sibling, MERGE, preimage]
      return new Script()
        .add(merge.lt4).add(merge.iblob).add(merge.outsBlob).add(merge.sibBal8)
        .add(merge.sibling36).add(MERGE).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
