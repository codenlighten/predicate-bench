'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const witness = require('./witness')
const bulletin = require('./bulletin')
const Script = bsv.Script
const Opcode = bsv.Opcode

// POSITION — a fully-collateralised binary OPTION on a market outcome, settled by READING a
// shared [`bulletin`](bulletin) rather than by consuming it. This is what makes markets of
// MANY positions possible: any number of position coins can co-spend the SAME bulletin in the
// same transaction, each read the committed outcome out of it, and each release its own
// collateral to the party that was right — the bulletin recreates itself (its `read` branch),
// so it is never used up, and no position depends on any other.
//
// A position stakes a side of a yes/no question. When the bulletin for that question is
// RESOLVED, the position pays out:
//
//     outcome == side   →  the OWNER (they called it right) may take the collateral
//     outcome != side   →  the COUNTERPARTY takes it
//
// Soundness is the [`witness`](witness) cross-coin mechanism, unchanged: the position bakes
// the bulletin's OUTPOINT, checks (via hashPrevouts) that this exact coin is co-spent NOW,
// rebuilds its source transaction and requires it to hash to the baked txid, and reads the
// outcome straight out of the bulletin's committed state at output 0 — a fact the bulletin's
// own covenant, running on the co-spent input, guarantees is genuine and unchanged. The
// question in that state must equal the position's own, so a position cannot be settled
// against a different market's bulletin. The winner then signs to take the coin; no signature
// but the winner's will do, and which of the two is the winner is not the spender's to choose.
//
// Honest scope: the position references the bulletin by a specific outpoint (as `witness`
// does its sibling), so a batch of positions settles against a live resolved bulletin. Writing
// a position BEFORE the outcome is known, against a bulletin that has been read many times,
// needs the bulletin to carry a descent proof back to its genesis resolve — the next increment.

const OUTPOINT_BYTES = 36
const TX_VERSION = Buffer.from('01000000', 'hex')
const F_HASHPREVOUTS = C.hashPrevoutsFromFront

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string' && /^[0-9a-fA-F]{40}$/.test(a)) return Buffer.from(a, 'hex')
  return bsv.Address.fromString(a).hashBuffer
}
function sideByte (v) { return Buffer.from([v & 0xff]) }

function readField (asm, fn, name) {
  asm.fromAlt(); asm.clause(fn, 0, [name]); asm.swap(); asm.toAlt()
}
function finishBranch (asm) {
  while (asm.main.length) asm.drop()
  asm.fromAlt(); asm.drop()
  asm.raw(Opcode.OP_1, 0, ['true'])
}

function buildScript ({ question, side, owner, counterparty, bulletinOutpoint }) {
  const q = buf(question)
  const own = pkhOf(owner); const cp = pkhOf(counterparty)
  const outpoint = Buffer.isBuffer(bulletinOutpoint) ? bulletinOutpoint : witness.outpoint36(bulletinOutpoint.prevTxId, bulletinOutpoint.outputIndex ?? bulletinOutpoint.vout)
  if (q.length !== 32) throw new Error('question must be 32 bytes')
  if (own.length !== 20 || cp.length !== 20) throw new Error('owner and counterparty must be 20-byte pkhs')
  if (outpoint.length !== OUTPOINT_BYTES) throw new Error('bulletinOutpoint must be 36 bytes')
  if (side !== 0 && side !== 1) throw new Error('side must be 0 or 1')
  const txidB = outpoint.slice(0, 32)

  const s = new Script()
  C.authenticate(s)                                        // preimage proven, on top
  s.add(Opcode.OP_TOALTSTACK)                              // park it
  const a = new StackAsm(s).given(['pubkey', 'sig', 'prefix', 'suffix', 'preOuts', 'outsBlob', 'lt4']).seedAlt(['preimage'])

  // 1. companion: the baked bulletin outpoint is genuinely one of THIS tx's inputs (co-spent now)
  a.pick('prefix'); a.data(outpoint, 'sibOutpoint'); a.cat('pfx1'); a.pick('suffix'); a.cat('prevoutsGuess')
  a.hash256('pvHash'); readField(a, F_HASHPREVOUTS, 'hashPrevouts'); a.equalVerify()

  // 2. backtrace: rebuild the bulletin's SOURCE tx, hash it, require it == the baked txid.
  a.data(TX_VERSION, 'ver'); a.pick('preOuts'); a.cat('vi'); a.pick('outsBlob'); a.cat('vico')
  a.pick('lt4'); a.size('ltsz'); a.num(4, 'four'); a.equalVerify(); a.cat('sourceTx')
  a.hash256('sourceTxid'); a.data(txidB, 'txidB'); a.equalVerify()

  // 3. read the bulletin's committed state out of output 0 (value ‖ varint ‖ script):
  //    the question must be OURS, the status RESOLVED, and the outcome is the byte we settle on.
  a.pick('outsBlob'); a.splitAt(bulletin.QUESTION_OFFSET, 'qskip', 'qafter'); a.nip()
  a.splitAt(32, 'bq', 'qrest'); a.drop(); a.data(q, 'ourQ'); a.equalVerify()
  a.pick('outsBlob'); a.splitAt(bulletin.OUTCOME_OFFSET - 1, 'sskip', 'safter'); a.nip()
  a.splitAt(1, 'st', 'srest'); a.drop(); a.bin2num('stN'); a.num(bulletin.RESOLVED, 'R'); a.numEqualVerify()
  a.pick('outsBlob'); a.splitAt(bulletin.OUTCOME_OFFSET, 'oskip', 'oafter'); a.nip()
  a.splitAt(1, 'oc', 'orest'); a.drop(); a.bin2num('ocN')

  // 4. winner = outcome == side ? owner : counterparty
  a.num(side, 'sideN'); a.numEqual('win')
  a.pick('win'); a.beginIf()
  a.data(own, 'winnerPkh')
  a.elseBranch()
  a.data(cp, 'winnerPkh')
  a.endIf()

  // 5. the winner authorises taking the collateral
  a.pick('pubkey'); a.hash160('pkh'); a.pick('winnerPkh'); a.equalVerify()
  a.pick('sig'); a.pick('pubkey'); a.checkSigVerify()

  finishBranch(a)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- source-tx fixture: a RESOLVED bulletin at output 0, decomposed for the backtrace ----
function bulletinSourceTx ({ question, outcome, satoshis = 3000, extraOutputs = 1 }) {
  const script = bulletin.buildScript({ question, status: bulletin.RESOLVED, outcome })
  const f = new bsv.Transaction()
  f.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.alloc(32, 9), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), satoshis + 5000)
  f.addOutput(new bsv.Transaction.Output({ script, satoshis }))
  for (let i = 0; i < extraOutputs; i++) {
    f.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(Buffer.alloc(20, 6))), satoshis: 1000 }))
  }
  const raw = f.toBuffer()
  return { raw, tx: f, script, ...witness.decomposeSource(raw) }
}

function indexOfAligned (haystack, needle, stride) {
  for (let i = 0; i + needle.length <= haystack.length; i += stride) {
    if (haystack.slice(i, i + needle.length).equals(needle)) return i
  }
  return -1
}

module.exports = {
  name: 'position',
  describe: 'a fully-collateralised binary option on a market outcome: co-spend the shared bulletin, read the committed outcome, and release the collateral to the owner if they called it right, else to the counterparty',
  example: () => ({ question: Buffer.alloc(32, 7), side: 1, owner: Buffer.alloc(20, 1), counterparty: Buffer.alloc(20, 2), bulletinOutpoint: Buffer.alloc(36, 3) }),

  buildScript,
  bulletinSourceTx,
  pkhOf,

  lock (tc) {
    if (tc.side === undefined || !tc.owner || !tc.counterparty) throw new Error('side, owner, counterparty are required')
    const src = tc._src
    const outpoint = tc.bulletinOutpoint || (src ? witness.outpoint36(src.tx.id, 0) : null)
    if (!outpoint) throw new Error('position test needs tc._src (from bulletinSourceTx) or a bulletinOutpoint')
    return buildScript({ question: tc.question, side: tc.side, owner: tc.owner, counterparty: tc.counterparty, bulletinOutpoint: outpoint })
  },

  // the bulletin this position reads, added as a real co-input so hashPrevouts covers it
  siblings (tc) {
    const src = tc._src
    if (!src) throw new Error('position test must supply tc._src (from bulletinSourceTx)')
    const out = src.tx.outputs[0]
    return [{ prevTxId: src.tx.id, outputIndex: 0, script: out.script, satoshis: out.satoshis }, ...(tc.extraSiblings || [])]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const src = tc._src
    if (!src) throw new Error('position unlock needs tc._src (from bulletinSourceTx)')

    // which party is signing — the winner, unless the test forces the wrong one
    const winnerKey = tc.claimantKey || tc.key
    const pub = (tc.wrongPubkey || winnerKey).publicKey.toBuffer()

    const outpoint = witness.outpoint36(src.tx.id, 0)
    const vector = Buffer.concat(tx.inputs.map((i) => witness.outpoint36(i.prevTxId, i.outputIndex)))
    let prefix, suffix
    const at = indexOfAligned(vector, outpoint, OUTPOINT_BYTES)
    if (at >= 0) { prefix = vector.slice(0, at); suffix = vector.slice(at + OUTPOINT_BYTES) } else { prefix = vector.slice(0, OUTPOINT_BYTES); suffix = vector.slice(OUTPOINT_BYTES) }

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, winnerKey, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const s = new Script()
      s.add(pub).add(sig)
      s.add(prefix.length ? prefix : Opcode.OP_0)
      s.add(suffix.length ? suffix : Opcode.OP_0)
      s.add(src.preOuts).add(src.outsBlob).add(src.lt4)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
