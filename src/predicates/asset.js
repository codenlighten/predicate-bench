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

// A fungible token that is also OWNED — the composition of two primitives this
// bench already has: the balance conservation of `token` and the spender-chosen,
// signature-gated ownership of `titled`. Every asset carries `owner ‖ balance` in
// its own scriptCode, and every operation requires the current owner's signature:
//
//   transfer   1 -> 1, same balance, a new owner the current owner chooses
//   split      1 -> 2, balance divided, an owner for each half
//   merge      2 -> 1, balances summed; EACH input's owner must sign, so a merge
//              happens only when both holders consent
//   swap       two assets change hands in one transaction, each output pinned by
//              its own owner — an atomic peer-to-peer trade, all-or-nothing
//
// The conservation machinery is `token`'s: split checks x+y == balance in-script,
// and merge proves the sibling's balance by BACKTRACE (rebuild its funding tx with
// the claimed owner+balance spliced in, require it to hash to the real txid). The
// ownership machinery is `titled`'s: read the owner out of our own scriptCode,
// require HASH160(pubkey) to equal it, and OP_CHECKSIGVERIFY the owner's signature
// over this spend. Neither primitive needed changing to compose — that is the
// point. See docs/predicates.md#asset.
//
// Proves CONSERVATION and AUTHORISATION. Still not AUTHENTICITY (that inputs
// descend from a real issuance) — the back-to-genesis problem, out of scope.

const OWNER_BYTES = 20
const BAL_BYTES = 8
const STATE_BYTES = OWNER_BYTES + BAL_BYTES        // owner ‖ balance, one push
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1                // varint ‖ push-op(0x1c) ‖ state ‖ tail
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')
const TRANSFER = 0
const SPLIT = 1
const MERGE = 2
const SWAP = 3

function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function balanceLE (v) { const b = Buffer.alloc(BAL_BYTES); b.writeUIntLE(v, 0, 6); return b }
function dustLE () { const b = Buffer.alloc(8); b.writeUIntLE(DUST, 0, 6); return b }
function state (owner, balance) { return Buffer.concat([hash160Of(owner), balanceLE(balance)]) }
function varint (len) {
  if (len < 253) return Buffer.from([len])
  const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b
}

function buildScript ({ owner, balance }) {
  const s = new Script()
  s.add(state(owner, balance)).add(Opcode.OP_DROP)        // state: owner ‖ balance

  C.authenticate(s)                                        // preimage proven, on top
  s.add(Opcode.OP_TOALTSTACK)                              // park preimage; [.., selector]

  // 4-way dispatch on the selector, preimage safe on the altstack
  s.add(Opcode.OP_DUP).add(n(SWAP)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  covsteps.assetEmitSwap(new StackAsm(s)
    .given(['outsBlob', 'myIndex', 'newOwner', 'sig', 'pubkey']).seedAlt(['preimage']))
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DUP).add(n(MERGE)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  covsteps.assetEmitMerge(new StackAsm(s)
    .given(['lt4', 'iblob', 'outsBlob', 'sibOwner', 'sibBal8', 'sibling', 'newOwner', 'sig', 'pubkey'])
    .seedAlt(['preimage']))
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DUP).add(n(SPLIT)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  covsteps.assetEmitSplit(new StackAsm(s)
    .given(['ownerA', 'ownerB', 'balA8', 'balB8', 'sig', 'pubkey']).seedAlt(['preimage']))
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DROP)
  covsteps.assetEmitTransfer(new StackAsm(s)
    .given(['newOwner', 'sig', 'pubkey']).seedAlt(['preimage']))
  s.add(Opcode.OP_ENDIF)
  s.add(Opcode.OP_ENDIF)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- funding decomposition for the merge backtrace ----

function outsBlobFor (records) {                            // records: [{owner, balance}]
  return Buffer.concat(records.map(r => {
    const scriptBuf = buildScript({ owner: r.owner, balance: r.balance }).toBuffer()
    return Buffer.concat([dustLE(), varint(scriptBuf.length), scriptBuf])
  }))
}
function decomposeFunding (raw, records) {
  const outsBlob = outsBlobFor(records)
  const lt4 = raw.slice(raw.length - 4)
  const iblob = raw.slice(4, raw.length - (1 + outsBlob.length + 4))
  const reassembled = Buffer.concat([raw.slice(0, 4), iblob, Buffer.from([records.length]), outsBlob, lt4])
  if (!reassembled.equals(raw)) throw new Error('funding shape mismatch (reassembly)')
  return { iblob, lt4, outsBlob, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}
function tokenFunding (records) {
  const f = new bsv.Transaction()
  f.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.alloc(32, 3), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), 5000)
  for (const r of records) f.addOutput(new bsv.Transaction.Output({ script: buildScript(r), satoshis: DUST }))
  const raw = f.toBuffer()
  return { raw, ...decomposeFunding(raw, records) }
}
function mergeSibling ({ sibOwner, sibBalance, sibSplit, sibR0, sibR1, sibVout = 0, wrongSibTxid }) {
  const records = sibSplit ? [sibR0, sibR1] : [{ owner: sibOwner, balance: sibBalance }]
  const f = tokenFunding(records)
  return { f, vout: sibVout, record: records[sibVout], wrongSibTxid }
}

const A = bsv.PrivateKey.fromRandom()
const B = bsv.PrivateKey.fromRandom()

module.exports = {
  name: 'asset',
  describe: 'an owned fungible token: transfer, split, merge and atomic swap, each owner-signed',
  example: () => ({ owner: A.toAddress().toString(), balance: 300, branch: 'transfer', ownerKey: A, newOwner: B.toAddress().toString() }),
  OWNER_BYTES,
  BAL_BYTES,
  DUST,
  balanceLE,
  hash160Of,
  buildScript,
  tokenFunding,
  decomposeFunding,

  lock ({ owner, balance }) {
    if (!owner) throw new Error('owner is required')
    if (!Number.isInteger(balance) || balance <= 0) throw new Error('balance must be a positive integer')
    return buildScript({ owner, balance })
  },

  siblings (tc) {
    if ((tc.branch || 'transfer') !== 'merge') return undefined
    const { f, vout, wrongSibTxid } = mergeSibling(tc)
    const display = Buffer.from(f.txidInternal); display.reverse()
    return [{ prevTxId: wrongSibTxid ? Buffer.alloc(32, 0xab) : display, outputIndex: vout, satoshis: DUST }]
  },

  outputs (tc) {
    const branch = tc.branch || 'transfer'
    if (branch === 'swap') {
      // my outgoing asset (to newOwner, same balance) at myIndex, the counterparty's at the other
      const myIndex = tc.myIndex ?? 0
      const mine = { owner: tc.actualNewOwner ?? tc.newOwner, balance: tc.actualBalance ?? tc.balance }
      const other = { owner: tc.swapOtherOwner, balance: tc.swapOtherBalance }
      const recs = myIndex === 0 ? [mine, other] : [other, mine]
      return recs.map(r => new bsv.Transaction.Output({ script: buildScript(r), satoshis: DUST }))
    }
    if (branch === 'split') {
      return [
        { owner: tc.actualOwnerA ?? tc.ownerA, balance: tc.actualBalA ?? tc.splitA },
        { owner: tc.ownerB, balance: tc.splitB }
      ].map(r => new bsv.Transaction.Output({ script: buildScript(r), satoshis: DUST }))
    }
    if (branch === 'merge') {
      const sib = mergeSibling(tc).record.balance
      const outBal = tc.actualOutBalance ?? (tc.balance + sib)
      return [new bsv.Transaction.Output({ script: buildScript({ owner: tc.actualMergeOwner ?? tc.newOwner, balance: outBal }), satoshis: DUST })]
    }
    // transfer
    return [new bsv.Transaction.Output({
      script: buildScript({ owner: tc.actualNewOwner ?? tc.newOwner, balance: tc.actualBalance ?? tc.balance }),
      satoshis: DUST
    })]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType, branch = 'transfer',
      ownerKey, ownerWif, newOwner, ownerA, ownerB, splitA, splitB, claimSibBalance,
      claimSibOwner, wrongPubkey } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const signer = ownerKey || (ownerWif ? bsv.PrivateKey.fromWIF(ownerWif) : null)
    if (!signer) throw new Error('no owner key: pass ownerKey or ownerWif')
    const pub = (wrongPubkey || signer).publicKey.toBuffer()

    let merge
    if (branch === 'merge') {
      const { f, vout, record } = mergeSibling(tc)
      const voutLE = Buffer.alloc(4); voutLE.writeUInt32LE(vout, 0)
      merge = {
        lt4: f.lt4, iblob: f.iblob, outsBlob: f.outsBlob,
        sibOwner: hash160Of(claimSibOwner ?? record.owner),
        sibBal8: balanceLE(claimSibBalance ?? record.balance),
        sibling36: Buffer.concat([f.txidInternal, voutLE])
      }
    }

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, signer, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()

      if (branch === 'transfer') {
        return new Script().add(hash160Of(newOwner)).add(sig).add(pub).add(n(TRANSFER)).add(preimage)
      }
      if (branch === 'split') {
        return new Script().add(hash160Of(ownerA)).add(hash160Of(ownerB))
          .add(balanceLE(splitA)).add(balanceLE(splitB)).add(sig).add(pub).add(n(SPLIT)).add(preimage)
      }
      if (branch === 'swap') {
        // outsBlob = the transaction's real output section; the covenant pins
        // only its own slice and checks the whole set against hashOutputs.
        const outsBlob = Buffer.concat(tx.outputs.map(o => o.toBufferWriter().toBuffer()))
        return new Script().add(outsBlob).add(n(tc.myIndex ?? 0))
          .add(hash160Of(newOwner)).add(sig).add(pub).add(n(SWAP)).add(preimage)
      }
      return new Script().add(merge.lt4).add(merge.iblob).add(merge.outsBlob)
        .add(merge.sibOwner).add(merge.sibBal8).add(merge.sibling36)
        .add(hash160Of(newOwner)).add(sig).add(pub).add(n(MERGE)).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
