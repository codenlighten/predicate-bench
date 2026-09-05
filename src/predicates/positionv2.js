'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const witness = require('./witness')
const descentmarket = require('./descentmarket')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// POSITION v2 — a fully-collateralised binary option that identifies its market by IDENTITY, not
// by an outpoint. Where [`position`](position) bakes the specific bulletin coin it settles against
// (so a position must be written after that coin exists), this bakes the market's covenant-SCRIPT
// hash — the [`descentmarket`](descentmarket) script with the mutable status and outcome blanked,
// which commits to the genesis G, the panel, and the logic but not the state. So a position can be
// written BEFORE the outcome is known, and later settle against ANY genuine descentmarket of that
// market it co-spends: it rebuilds the co-spent coin's source, checks the coin at output 0 hashes
// (blanked) to the baked market id, reads the committed outcome, and releases the collateral to the
// owner if they called it right, else the counterparty.
//
// Soundness rests on descentmarket's guarantee: the co-spent coin is a genuine descentmarket (its
// blanked script matches the baked id), and — because it is co-spent — its OWN covenant runs and
// enforces descent from G. A counterfeit carrying G's bytes with a forged outcome either fails the
// script-id check or, if it wears the real covenant, cannot be spent at all (descentmarket refuses
// it). So the outcome this position reads is one the chain, not the spender, guarantees.

const OUTPOINT_BYTES = 36
const TX_VERSION = Buffer.from('01000000', 'hex')
const F_HASHPREVOUTS = C.hashPrevoutsFromFront

// the descentmarket coin's output layout, and where status/outcome sit in its script
const MARKET_SCRIPT_LEN = descentmarket.buildScript({ genesis: Buffer.alloc(36, 0) }).toBuffer().length
const SCRIPT_STATUS_OFF = 1 + descentmarket.G_BYTES               // push-op(1) ‖ genesis(36) → status at 37
const OUT0_SCRIPT_OFF = 8 + 3                                     // value(8) ‖ scriptlen varint(3) → script begins here

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string' && /^[0-9a-fA-F]{40}$/.test(a)) return Buffer.from(a, 'hex')
  return bsv.Address.fromString(a).hashBuffer
}
/** The market's identity: HASH256 of the descentmarket script with status+outcome blanked. */
function marketId (genesis) {
  const s = descentmarket.buildScript({ genesis }).toBuffer()
  const blanked = Buffer.concat([s.slice(0, SCRIPT_STATUS_OFF), Buffer.from([0, 0]), s.slice(SCRIPT_STATUS_OFF + 2)])
  return bsv.crypto.Hash.sha256sha256(blanked)
}

function readField (asm, fn, name) { asm.fromAlt(); asm.clause(fn, 0, [name]); asm.swap(); asm.toAlt() }
function finishBranch (asm) { while (asm.main.length) asm.drop(); asm.fromAlt(); asm.drop(); asm.raw(Opcode.OP_1, 0, ['true']) }

function buildScript ({ market, side, owner, counterparty }) {
  const mid = buf(market)
  const own = pkhOf(owner); const cp = pkhOf(counterparty)
  if (mid.length !== 32) throw new Error('market id must be a 32-byte hash')
  if (own.length !== 20 || cp.length !== 20) throw new Error('owner and counterparty must be 20-byte pkhs')
  if (side !== 0 && side !== 1) throw new Error('side must be 0 or 1')

  const s = new Script()
  C.authenticate(s)
  s.add(Opcode.OP_TOALTSTACK)
  const a = new StackAsm(s).given(['pubkey', 'sig', 'prefix', 'suffix', 'preOuts', 'outsBlob', 'lt4']).seedAlt(['preimage'])

  // 1. rebuild the co-spent market's SOURCE tx and take its txid; the market is output 0, so the
  //    co-spent outpoint is (sourceTxid ‖ 0). Require that outpoint is genuinely one of this tx's inputs.
  a.data(TX_VERSION, 'ver'); a.pick('preOuts'); a.cat('vi'); a.pick('outsBlob'); a.cat('vico')
  a.pick('lt4'); a.size('ltsz'); a.num(4, 'four'); a.equalVerify(); a.cat('sourceTx')
  a.hash256('sourceTxid')
  a.pick('sourceTxid'); a.data(Buffer.from([0, 0, 0, 0]), 'vout0'); a.cat('marketOutpoint')
  a.pick('prefix'); a.pick('marketOutpoint'); a.cat('pfx1'); a.pick('suffix'); a.cat('prevoutsGuess')
  a.hash256('pvHash'); readField(a, F_HASHPREVOUTS, 'hashPrevouts'); a.equalVerify()

  // 2. read the market coin out of output 0 (value ‖ varint ‖ script), and verify its IDENTITY:
  //    the script with status+outcome blanked must hash to the baked market id.
  a.pick('outsBlob'); a.splitAt(OUT0_SCRIPT_OFF, 'o0head', 'o0rest'); a.nip()
  a.splitAt(MARKET_SCRIPT_LEN, 'mscript', 'o0tail'); a.drop()
  a.pick('mscript'); a.splitAt(SCRIPT_STATUS_OFF, 'sPre', 'sMid')
  a.splitAt(2, 'sSO', 'sPost')                                       // sSO = status(1) ‖ outcome(1)
  a.pick('sPre'); a.data(Buffer.from([0, 0]), 'blank'); a.cat('bl1'); a.pick('sPost'); a.cat('blanked')
  a.hash256('idHash'); a.data(marketIdFrom(mid), 'wantId'); a.equalVerify()

  // 3. the coin must be RESOLVED, and its outcome decides the winner
  a.pick('sSO'); a.splitAt(1, 'stB', 'ocB')
  a.pick('stB'); a.bin2num('st#'); a.num(descentmarket.RESOLVED, 'R'); a.numEqualVerify()
  a.pick('ocB'); a.bin2num('ocN')
  a.num(side, 'sideN'); a.numEqual('win')
  a.pick('win'); a.beginIf()
  a.data(own, 'winnerPkh')
  a.elseBranch()
  a.data(cp, 'winnerPkh')
  a.endIf()

  // 4. the winner authorises taking the collateral
  a.pick('pubkey'); a.hash160('pkh'); a.pick('winnerPkh'); a.equalVerify()
  a.pick('sig'); a.pick('pubkey'); a.checkSigVerify()

  finishBranch(a)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) throw new Error(`script is ${size} bytes; needs 253..65535`)
  return s
}
// the baked id is already a 32-byte hash — just pass it through (kept as a hook for clarity)
function marketIdFrom (mid) { return mid }

/** A source tx with a RESOLVED descentmarket at output 0, decomposed for the backtrace. */
function marketSourceTx ({ genesis, outcome, satoshis = 2000 }) {
  const script = descentmarket.buildScript({ genesis, status: descentmarket.RESOLVED, outcome })
  const f = new bsv.Transaction()
  f.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.alloc(32, 9), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), new bsv.Script().add(Opcode.OP_1), satoshis + 6000)
  f.addOutput(new bsv.Transaction.Output({ script, satoshis }))
  f.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(Buffer.alloc(20, 6))), satoshis: 1000 }))
  const raw = f.toBuffer()
  return { tx: f, script, ...witness.decomposeSource(raw) }
}
function indexOfAligned (h, needle, stride) { for (let i = 0; i + needle.length <= h.length; i += stride) if (h.slice(i, i + needle.length).equals(needle)) return i; return -1 }

module.exports = {
  name: 'positionv2',
  describe: 'a binary option that identifies its market by the descentmarket covenant-script hash (so it can be written before resolution): co-spend any genuine descentmarket of the market, verify its identity, read the outcome, and pay whoever was right',
  example: () => ({ genesis: Buffer.alloc(36, 3), side: 1, owner: Buffer.alloc(20, 1), counterparty: Buffer.alloc(20, 2), outcome: 1 }),
  MARKET_SCRIPT_LEN,
  buildScript,
  marketId,
  marketSourceTx,
  pkhOf,

  lock (tc) {
    if (tc.side === undefined || !tc.owner || !tc.counterparty) throw new Error('side, owner, counterparty are required')
    return buildScript({ market: tc.market || marketId(tc.genesis), side: tc.side, owner: tc.owner, counterparty: tc.counterparty })
  },

  siblings (tc) {
    const src = tc._src || (tc._src = marketSourceTx({ genesis: tc.srcGenesis || tc.genesis, outcome: tc.outcome ?? 1 }))
    const out = src.tx.outputs[0]
    return [{ prevTxId: src.tx.id, outputIndex: 0, script: out.script, satoshis: out.satoshis }]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const src = tc._src || (tc._src = marketSourceTx({ genesis: tc.srcGenesis || tc.genesis, outcome: tc.outcome ?? 1 }))
    const claimKey = tc.claimantKey || tc.key
    const pub = (tc.wrongPubkey || claimKey).publicKey.toBuffer()
    const outpoint = witness.outpoint36(src.tx.id, 0)
    const vector = Buffer.concat(tx.inputs.map((i) => witness.outpoint36(i.prevTxId, i.outputIndex)))
    const at = indexOfAligned(vector, outpoint, OUTPOINT_BYTES)
    const prefix = at >= 0 ? vector.slice(0, at) : vector.slice(0, OUTPOINT_BYTES)
    const suffix = at >= 0 ? vector.slice(at + OUTPOINT_BYTES) : vector.slice(OUTPOINT_BYTES)

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, claimKey, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const us = new Script().add(pub).add(sig)
        .add(prefix.length ? prefix : Opcode.OP_0).add(suffix.length ? suffix : Opcode.OP_0)
        .add(src.preOuts).add(src.outsBlob).add(src.lt4).add(preimage)
      return us
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
