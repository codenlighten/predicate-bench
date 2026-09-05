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

// AUTHENTICITY — the one hard problem the bench had scoped but not solved.
//
// The token covenants conserve balance and gate ownership, but a counterfeiter
// can still create a raw output whose bytes are the covenant with any state —
// the covenant proves conservation, not that the coin descends from a real
// issuance. `lineage` closes that, without a SNARK, for a self-recreating token.
//
// The idea: every token carries its GENESIS outpoint G in its scriptCode, and on
// every spend it proves — by a bounded backtrace — that its IMMEDIATE parent was
// a genuine `lineage` token with the same G. It does NOT re-verify the whole
// ancestry; it verifies one hop and relies on induction:
//
//   To spend token T, the covenant requires EITHER
//     (a) T's funding transaction spent the outpoint G directly  — the genesis
//         mint, which can happen exactly once because G is a UTXO; or
//     (b) T's parent P (the token T's funding tx spent) was a `lineage` token
//         with the same G — proven by rebuilding P's single-output funding tx
//         and hashing it to P's txid.
//
//   A counterfeit — a raw output with the lineage bytes, created by spending a
//   plain UTXO — fails both: its funding tx did not spend G, and its "parent"
//   output is a plain script, not `lineage`+G. So it can be created but never
//   SPENT, and an unspendable coin can never enter circulation.
//
//   Soundness is inductive. T is spendable only if raw1 (its funding tx) is a
//   real, network-validated transaction. If raw1 spent P, then P's covenant ran
//   and enforced P's OWN descent check when raw1 was mined. So P is authentic,
//   and by descent so is its parent, back to the one genesis spend of G. The
//   witness is two parent transactions per spend — bounded, not O(N).
//
// Constraints, both load-bearing: a token transaction is single-output (the
// token self-recreates, unchanged), and the token is always input 0 of its
// spend. The first keeps the parent backtrace free of sliding (as in `token`);
// the second puts the parent outpoint at a fixed offset in the funding tx.
//
// Proves AUTHENTICITY (unbroken descent from a unique genesis). Access control
// and balance are out of scope here — compose with `asset` for those; this
// isolates the lineage mechanism.

const G_BYTES = 36                       // genesis outpoint: txid(32, internal) ‖ vout(4 LE)
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1      // varint ‖ push-op(0x24) ‖ G(36) ‖ tail
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')

function dustLE () { const b = Buffer.alloc(8); b.writeUIntLE(DUST, 0, 6); return b }
function varint (len) {
  if (len < 253) return Buffer.from([len])
  const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b
}
/** A genesis outpoint from a display txid + vout, in the internal ‖ LE form the
 *  serialised transaction uses. */
function genesisOutpoint (displayTxid, vout) {
  const txid = Buffer.from(displayTxid, 'hex'); txid.reverse()   // display -> internal
  const v = Buffer.alloc(4); v.writeUInt32LE(vout, 0)
  return Buffer.concat([txid, v])
}

function buildScript ({ genesis }) {
  const g = Buffer.isBuffer(genesis) ? genesis : Buffer.from(genesis, 'hex')
  if (g.length !== G_BYTES) throw new Error('genesis must be a 36-byte outpoint')

  const s = new Script()
  s.add(g).add(Opcode.OP_DROP)                          // state: the genesis outpoint

  // The descent proof lives in src/covsteps.js (linEmit), shared with the compiler
  // so the spec and the predicate cannot drift: read self + genesis, bind the
  // successor to my exact self, recover my parent's outpoint, and require it to be
  // the genesis mint or a genuine parent of the same genesis.
  C.authenticate(s)                                      // preimage proven, on top
  covsteps.linEmit(new StackAsm(s).given(['raw1', 'iblob2', 'lt2', 'preimage']))

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- scenario construction: build a real lineage chain and a counterfeit ----

/** The single-output funding-tx decomposition the backtrace needs. */
function decomposeFunding (raw, genesis) {
  const scriptBuf = buildScript({ genesis }).toBuffer()
  const chunk = Buffer.concat([varint(scriptBuf.length), scriptBuf])
  const txout = Buffer.concat([dustLE(), chunk])
  const lt4 = raw.slice(raw.length - 4)
  const iblob = raw.slice(4, raw.length - (1 + txout.length + 4))
  const reassembled = Buffer.concat([raw.slice(0, 4), iblob, Buffer.from([1]), txout, lt4])
  if (!reassembled.equals(raw)) throw new Error('lineage funding is not single-output (reassembly)')
  return { iblob, lt4, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}

/** A one-input, one-output tx spending `prevInternal:vout` into `outScript`@DUST. */
function oneToOne (prevInternal, vout, outScript) {
  const display = Buffer.from(prevInternal); display.reverse()
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: display, outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), 5000)
  tx.addOutput(new bsv.Transaction.Output({ script: outScript, satoshis: DUST }))
  return tx
}

/**
 * Build one of three spends of a lineage token and return everything the harness
 * and unlock need: the funding tx of the token being spent (raw1), the parent's
 * funding decomposition (iblob2, lt2), and the token's own outpoint.
 *
 *   'genesis'     — spend the token the mint created (mint spent G)
 *   'child'       — spend a token whose parent is a genuine lineage token
 *   'counterfeit' — spend a raw lineage-bytes output created from a plain UTXO
 */
function scenario (kind, genesis) {
  const tokenScript = buildScript({ genesis })
  const gTxidInternal = genesis.slice(0, 32)
  const gVout = genesis.readUInt32LE(32)

  // GEN: the mint — spends the genesis outpoint, creates the first token
  const gen = oneToOne(gTxidInternal, gVout, tokenScript)
  const genRaw = gen.toBuffer()
  const genId = bsv.crypto.Hash.sha256sha256(genRaw)

  if (kind === 'genesis') {
    // spending the mint's token; parent is G, so raw2 is unused (dummy)
    const dummy = decomposeFunding(genRaw, genesis)   // any valid single-output funding
    return { raw1: genRaw, iblob2: dummy.iblob, lt2: dummy.lt4, tokenTxidInternal: genId, tokenVout: 0 }
  }

  if (kind === 'child') {
    // SPEND0 spends the mint token; the token we now spend is SPEND0's output 0,
    // whose parent is the mint token, whose funding tx is GEN.
    const spend0 = oneToOne(genId, 0, tokenScript)
    const spend0Raw = spend0.toBuffer()
    const spend0Id = bsv.crypto.Hash.sha256sha256(spend0Raw)
    const parent = decomposeFunding(genRaw, genesis)   // GEN is the parent's funding tx
    return { raw1: spend0Raw, iblob2: parent.iblob, lt2: parent.lt4, tokenTxidInternal: spend0Id, tokenVout: 0 }
  }

  if (kind === 'grandchild') {
    // GEN -> SPEND0 (child) -> SPEND1 (grandchild). Spending the grandchild: its
    // parent is the child, whose funding tx is SPEND0. Induction over three hops.
    const spend0 = oneToOne(genId, 0, tokenScript)
    const spend0Raw = spend0.toBuffer()
    const spend0Id = bsv.crypto.Hash.sha256sha256(spend0Raw)
    const spend1 = oneToOne(spend0Id, 0, tokenScript)
    const spend1Raw = spend1.toBuffer()
    const spend1Id = bsv.crypto.Hash.sha256sha256(spend1Raw)
    const parent = decomposeFunding(spend0Raw, genesis)   // SPEND0 is the parent's funding tx
    return { raw1: spend1Raw, iblob2: parent.iblob, lt2: parent.lt4, tokenTxidInternal: spend1Id, tokenVout: 0 }
  }

  // counterfeit: a plain P2PKH-funded tx mints lineage bytes out of thin air
  const plainFundingTx = oneToOne(Buffer.alloc(32, 7), 0,
    bsv.Script.buildPublicKeyHashOut(bsv.PrivateKey.fromRandom().toAddress()))
  const plainRaw = plainFundingTx.toBuffer()
  const plainId = bsv.crypto.Hash.sha256sha256(plainRaw)
  const count = oneToOne(plainId, 0, tokenScript)      // spends the plain output, makes lineage bytes
  const countRaw = count.toBuffer()
  const countId = bsv.crypto.Hash.sha256sha256(countRaw)
  // best forgery the counterfeiter can offer for the parent backtrace: the plain
  // funding tx — but its output is P2PKH, not lineage+G, so the rebuild misses.
  const lt2 = plainRaw.slice(plainRaw.length - 4)
  const iblob2 = plainRaw.slice(4, plainRaw.length - (1 + (8 + plainFundingTx.outputs[0].script.toBuffer().length + 1) + 4))
  return { raw1: countRaw, iblob2, lt2, tokenTxidInternal: countId, tokenVout: 0 }
}

const EXAMPLE_GENESIS = genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)

module.exports = {
  name: 'lineage',
  describe: 'a token that proves unbroken descent from its genesis on every spend',
  example: () => ({ genesis: EXAMPLE_GENESIS, kind: 'genesis' }),
  G_BYTES,
  DUST,
  buildScript,
  genesisOutpoint,
  decomposeFunding,
  scenario,

  lock ({ genesis }) {
    if (!genesis) throw new Error('genesis outpoint is required')
    return buildScript({ genesis })
  },

  /** input 0's real outpoint: (funding txid, vout) of the token being spent. */
  spendOutpoint (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc.kind || 'genesis', tc.genesis))
    const display = Buffer.from(sc.tokenTxidInternal); display.reverse()
    return { prevTxId: display, prevVout: sc.tokenVout }
  },

  /** the successor: the same token, self-recreated */
  outputs (tc) {
    return [new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis }), satoshis: DUST })]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sc = tc._scn || (tc._scn = scenario(tc.kind || 'genesis', tc.genesis))

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      // [raw1, iblob2, lt2, preimage]
      return new Script().add(sc.raw1).add(sc.iblob2).add(sc.lt2).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
