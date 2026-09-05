'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const witness = require('./witness')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// GUARDED — the composition the constraint graph specified: conserve ∧ witness.
//
// A conserved two-body pair (conserve.js) whose rebalance is ALSO gated on a named
// oracle coin's committed state (witness.js). To move the pair, you must conserve the
// sum AND prove descent AND co-spend the partner — and, on top of all of it, co-spend
// a specific oracle coin that carries a required flag. One covenant, both cross-object
// relationships, exactly the obligation union relgraph.js printed for an object that
// `conservesWith B` and `dependsOn O`.
//
// The oracle outpoint and required flag are baked into the logic (side-agnostic, so
// both coins carry the same gate and every successor keeps it). Everything below is
// conserve, with the oracle gate spliced into the rebalance.

const ORACLE_BYTES = 36
const FLAG_BYTES4 = 4
const FLAG_OFFSET = 8 + 1 + 1                   // value(8) ‖ scriptVarint(1) ‖ push4(1) ‖ flag

// CONSERVE — the capstone: a CONSERVED TWO-BODY PAIR, uncounterfeitable.
//
// Two covenant coins, side 0 and side 1, born together from one genesis. A
// rebalance spends BOTH and recreates BOTH, moving quantity between them while
// keeping side0.balance + side1.balance invariant — and no counterfeit pair can
// ever spend, so the conserved total is real, not a number anyone can mint.
//
// It fuses three mechanisms the bench proved separately:
//   - token's backtrace   — to read a sibling's balance soundly;
//   - companion           — to pin the sibling as a genuine co-input;
//   - lineage's descent    — so only coins descending from the genesis can spend.
//
// The unlock of every hop: one backtrace of the SHARED PARENT transaction — the
// genesis or rebalance that created BOTH current coins. That single rebuild
// yields everything at once:
//   * the parent's txid == this coin's own outpoint txid (so it is my real parent);
//   * the parent's two outputs are the side-0 and side-1 coins — their balances a,
//     b, read straight out (no trust), and my own script is one of them;
//   * the sibling's outpoint is (parentTxid, other side) — pinned, co-spent
//     (companion), so the canonical partner is consumed, not a fake;
//   * the parent descends from genesis — it spent the genesis outpoint G directly,
//     or its own parent was a genuine pair coin (lineage induction).
// Then a + b == a' + b' (conservation) and the two successors, carrying G forward
// with the new balances, are bound to hashOutputs.
//
//   state = G(36) ‖ side(1) ‖ balance(4) ‖ owner(20)
//
// The script is SIDE-AGNOSTIC — both coins run identical logic, differing only in
// state — so neither has to embed the other's bytes (no circular self-reference);
// each reads the other's script from the shared parent and splices the new balance.
//
// Convention, load-bearing: a genesis/rebalance tx puts side 0 at output 0 and
// side 1 at output 1, and a rebalance spends the pair as its first two inputs.

const G_BYTES = 36
const SIDE_BYTES = 1
const BAL_BYTES = 4
const OWNER_BYTES = 20
const STATE_BYTES = G_BYTES + SIDE_BYTES + BAL_BYTES + OWNER_BYTES   // 61
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')
// field offsets inside a coin's scriptCode chunk (varint ‖ pushop ‖ state ‖ logic)
const OFF_G = HEAD_BYTES                       // 4
const OFF_SIDE = OFF_G + G_BYTES               // 40
const OFF_BAL = OFF_SIDE + SIDE_BYTES          // 41
const OFF_OWNER = OFF_BAL + BAL_BYTES          // 45
const OFF_TAIL = OFF_OWNER + OWNER_BYTES       // 65
// same offsets inside a TxOut (value(8) ‖ chunk)
const T = 8

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string') return /^[0-9a-f]{40}$/i.test(a) ? Buffer.from(a, 'hex') : bsv.Address.fromString(a).hashBuffer
  if (a instanceof bsv.PrivateKey) return bsv.crypto.Hash.sha256ripemd160(a.publicKey.toBuffer())
  if (a instanceof bsv.PublicKey) return bsv.crypto.Hash.sha256ripemd160(a.toBuffer())
  if (a && a.hashBuffer) return a.hashBuffer
  return hash160Of(a)
}
function balLE (v) { const b = Buffer.alloc(BAL_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function dustLE () { const b = Buffer.alloc(8); b.writeUIntLE(DUST, 0, 6); return b }
function varint (len) {
  if (len < 253) return Buffer.from([len])
  const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b
}
function genesisOutpoint (displayTxid, vout) {
  const txid = Buffer.from(displayTxid, 'hex'); txid.reverse()
  const v = Buffer.alloc(4); v.writeUInt32LE(vout, 0)
  return Buffer.concat([txid, v])
}
function state (G, side, balance, owner) {
  return Buffer.concat([buf(G), Buffer.from([side]), balLE(balance), pkhOf(owner)])
}

const F_HASHPREVOUTS = C.hashPrevoutsFromFront
const F_HASHOUTPUTS = (x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32)
const F_OWNOUTPOINT = (x) => x.add(Opcode.OP_DUP).add(n(68)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
  .add(n(36)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
function readField (asm, fn, name) { asm.fromAlt(); asm.clause(fn, 0, [name]); asm.swap(); asm.toAlt() }
function finishBranch (asm) { while (asm.main.length) asm.drop(); asm.fromAlt(); asm.drop(); asm.raw(Opcode.OP_1, 0, ['true']) }

/** From a coin's chunk on the named stack slot, copy the field [off, off+len). */
function fieldFromChunk (asm, chunkName, off, len, out) {
  asm.pick(chunkName); asm.splitAt(off, 'pre_' + out, 'r_' + out); asm.nip()
  asm.splitAt(len, out, 't_' + out); asm.drop()
}
/** Splice a new balance into a coin chunk: chunk[0:OFF_BAL] ‖ newBal ‖ chunk[OFF_BAL+4:]. */
function spliceBalance (asm, chunkName, newBalName, out) {
  asm.pick(chunkName); asm.splitAt(OFF_BAL, 'lo_' + out, 'hi_' + out)                 // lo = head‖G‖side ; hi = bal‖owner‖tail
  asm.pick('hi_' + out); asm.splitAt(BAL_BYTES, 'oldbal_' + out, 'ownertail_' + out); asm.nip()  // ownertail = owner‖tail
  asm.pick('lo_' + out); asm.pick(newBalName); asm.cat('lonb_' + out)                 // lo ‖ newBal
  asm.pick('ownertail_' + out); asm.cat(out)                                          // lo ‖ newBal ‖ owner‖tail
}

// The witness gate, baked: a specific oracle coin must be co-spent at input 2 carrying
// the required flag. Reuses the pair's already-verified `suffix` (the outpoints after
// the pair) and a token-style backtrace of the oracle's source transaction.
function emitOracleGate (asm, { oracle, requiredFlag }) {
  const oTxid = buf(oracle).slice(0, 32)
  const wantFlag = witness.flagLE(requiredFlag)
  // O is co-spent at input 2: suffix's first outpoint is the baked oracle outpoint
  asm.pick('suffix'); asm.splitAt(ORACLE_BYTES, 'oCand', 'oSuffRest'); asm.drop()
  asm.data(buf(oracle), 'oOut'); asm.equalVerify()
  // backtrace O's source tx (version ‖ oPreOuts ‖ oOutsBlob ‖ oLt4), hash == the oracle txid
  asm.data(VERSION, 'ov'); asm.pick('oPreOuts'); asm.cat('ovi'); asm.pick('oOutsBlob'); asm.cat('ovio')
  asm.pick('oLt4'); asm.size('olsz'); asm.num(4, 'of4'); asm.equalVerify(); asm.cat('oSource')
  asm.hash256('oTxidGot'); asm.data(oTxid, 'oTxidWant'); asm.equalVerify()
  // O's committed flag (its output 0 is the tagged coin) equals the required value
  asm.pick('oOutsBlob'); asm.splitAt(FLAG_OFFSET, 'oskip', 'oafter'); asm.nip()
  asm.splitAt(FLAG_BYTES4, 'oflag', 'orest'); asm.drop()
  asm.data(wantFlag, 'oflagWant'); asm.equalVerify()
}

function emitRebalance (asm, { G, oracle, requiredFlag }) {
  // self
  readField(asm, C.selfChunk, 'myChunk')
  fieldFromChunk(asm, 'myChunk', OFF_OWNER, OWNER_BYTES, 'myOwner')
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('myOwner'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()

  // parentTxid = my funding outpoint's txid
  readField(asm, F_OWNOUTPOINT, 'myOutpoint')
  asm.pick('myOutpoint'); asm.splitAt(32, 'parentTxid', 'myVout'); asm.drop()

  // rebuild the parent tx (version ‖ iblobP ‖ pOut0 ‖ pOut1 ‖ pTailP ‖ ltP), hash == parentTxid.
  // iblobP folds the output count in, and pTailP carries any outputs past the pair (a fee-
  // change output), so the parent need not be exactly two outputs.
  asm.data(VERSION, 've'); asm.pick('iblobP'); asm.cat('vi')
  asm.pick('pOut0'); asm.cat('vico'); asm.pick('pOut1'); asm.cat('vicoo'); asm.pick('pTailP'); asm.cat('vicot')
  asm.pick('ltP'); asm.size('lsz'); asm.num(4, 'f4'); asm.equalVerify(); asm.cat('parentTx')
  asm.hash256('ptid'); asm.pick('parentTxid'); asm.equalVerify()

  // read the two coins the parent created: chunk (drop 8-byte value), G, side, balance
  fieldFromChunk(asm, 'pOut0', T + OFF_G, G_BYTES, 'g0'); asm.data(buf(G), 'G0'); asm.pick('g0'); asm.equalVerify()
  fieldFromChunk(asm, 'pOut1', T + OFF_G, G_BYTES, 'g1'); asm.data(buf(G), 'G1'); asm.pick('g1'); asm.equalVerify()
  fieldFromChunk(asm, 'pOut0', T + OFF_SIDE, SIDE_BYTES, 's0'); asm.pick('s0'); asm.bin2num('s0n'); asm.num(0, 'zeroS'); asm.numEqualVerify()
  fieldFromChunk(asm, 'pOut1', T + OFF_SIDE, SIDE_BYTES, 's1'); asm.pick('s1'); asm.bin2num('s1n'); asm.num(1, 'oneS'); asm.numEqualVerify()
  fieldFromChunk(asm, 'pOut0', T + OFF_BAL, BAL_BYTES, 'a4'); asm.pick('a4'); asm.bin2num('a')
  fieldFromChunk(asm, 'pOut1', T + OFF_BAL, BAL_BYTES, 'b4'); asm.pick('b4'); asm.bin2num('b')

  // chunk0 = pOut0 minus its 8-byte value; likewise chunk1. My own chunk is one of them.
  asm.pick('pOut0'); asm.splitAt(T, 'v0', 'chunk0'); asm.nip()
  asm.pick('pOut1'); asm.splitAt(T, 'v1', 'chunk1'); asm.nip()
  asm.pick('myChunk'); asm.pick('chunk0'); asm.equal('is0')
  asm.pick('myChunk'); asm.pick('chunk1'); asm.equal('is1')
  asm.raw(Opcode.OP_BOOLOR, 2, ['mine']); asm.verify()

  // the pair is co-spent: inputs 0,1 are (parentTxid,0) and (parentTxid,1), either order
  asm.pick('parentTxid'); asm.raw(Opcode.OP_0, 0, ['zv']); asm.num2bin(4, 'v0le'); asm.cat('op0')
  asm.pick('parentTxid'); asm.num(1, 'onev'); asm.num2bin(4, 'v1le'); asm.cat('op1')
  asm.pick('op0'); asm.pick('op1'); asm.cat('ab'); asm.pick('suffix'); asm.cat('pvA'); asm.hash256('hA')
  readField(asm, F_HASHPREVOUTS, 'hp1'); asm.equal('okA')
  asm.pick('op1'); asm.pick('op0'); asm.cat('ba'); asm.pick('suffix'); asm.cat('pvB'); asm.hash256('hB')
  readField(asm, F_HASHPREVOUTS, 'hp2'); asm.equal('okB')
  asm.raw(Opcode.OP_BOOLOR, 2, ['pairOk']); asm.verify()

  // descent: the parent spent G directly (genesis), OR its parent was a genuine pair coin
  asm.pick('iblobP'); asm.splitAt(1, 'inc', 'afterInc'); asm.nip()        // drop input count byte
  asm.splitAt(G_BYTES, 'parentSpent', 'restIn'); asm.drop()
  asm.pick('parentSpent'); asm.data(buf(G), 'Gd'); asm.equal('isGenesis')
  // The grandparent's side-0 output must be a GENUINE pair coin — same G, same logic
  // tail as me. EQUALVERIFY (not a boolean): a plain-funded counterfeit's grandparent
  // output is a P2PKH, not a coin, so this bites before the hash is even considered.
  fieldFromChunk(asm, 'gOut0', T + OFF_G, G_BYTES, 'gg'); asm.pick('gg'); asm.data(buf(G), 'Gg'); asm.equalVerify()
  asm.pick('gOut0'); asm.splitAt(T + OFF_TAIL, 'ghead', 'gtail'); asm.nip()
  asm.pick('myChunk'); asm.splitAt(OFF_TAIL, 'mhead', 'mtail'); asm.nip()
  asm.pick('gtail'); asm.pick('mtail'); asm.equalVerify()
  // gpHashOk: the grandparent tx, rebuilt from its parts, hashes to what the parent spent
  asm.pick('parentSpent'); asm.splitAt(32, 'gpTxid', 'gpVout'); asm.drop()
  asm.data(VERSION, 've2'); asm.pick('iblobG'); asm.cat('gi')
  asm.pick('gOut0'); asm.cat('gico'); asm.pick('gOut1'); asm.cat('gicoo'); asm.pick('pTailG'); asm.cat('gicot')
  asm.pick('ltG'); asm.size('lsz2'); asm.num(4, 'f42'); asm.equalVerify(); asm.cat('grandTx')
  asm.hash256('gtid'); asm.pick('gpTxid'); asm.equal('gpHashOk')
  // descent: the parent spent G directly (genesis mint), OR its parent was genuine
  asm.pick('isGenesis'); asm.pick('gpHashOk'); asm.raw(Opcode.OP_BOOLOR, 2, ['descentOk']); asm.verify()

  // conservation: a + b == a' + b'
  asm.pick('newA4'); asm.size('na'); asm.num(BAL_BYTES, 'nb'); asm.equalVerify()
  asm.pick('newB4'); asm.size('nb2'); asm.num(BAL_BYTES, 'nb3'); asm.equalVerify()
  asm.pick('newA4'); asm.bin2num('na#'); asm.pick('newB4'); asm.bin2num('nb#'); asm.add('newSum')
  asm.pick('a'); asm.pick('b'); asm.add('oldSum'); asm.pick('newSum'); asm.numEqualVerify()

  // the witness gate — a named oracle coin must be co-spent carrying the required flag
  emitOracleGate(asm, { oracle, requiredFlag })

  // successors: splice the new balances into the two coins, bind [A' ‖ B'] to hashOutputs
  spliceBalance(asm, 'chunk0', 'newA4', 'newChunk0')
  spliceBalance(asm, 'chunk1', 'newB4', 'newChunk1')
  asm.data(dustLE(), 'd0'); asm.pick('newChunk0'); asm.cat('out0')
  asm.data(dustLE(), 'd1'); asm.pick('newChunk1'); asm.cat('out1')
  // the pair is outputs 0 and 1; outTail (owner-signed, so it is the owner's own change)
  // may follow, so a rebalance can carry a fee-change output without a change-exact input.
  asm.pick('out0'); asm.pick('out1'); asm.cat('outs'); asm.pick('outTail'); asm.cat('outsAll')
  asm.hash256('oh'); readField(asm, F_HASHOUTPUTS, 'ho'); asm.equalVerify()

  finishBranch(asm)
}

function oracleOutpoint (o) {
  if (Buffer.isBuffer(o)) return o
  return witness.outpoint36(o.prevTxId, o.outputIndex ?? o.vout)
}

function buildScript ({ genesis, side, balance, owner, oracle, requiredFlag }) {
  const G = buf(genesis)
  if (G.length !== G_BYTES) throw new Error('genesis must be a 36-byte outpoint')
  const oracleOp = oracleOutpoint(oracle)
  if (oracleOp.length !== ORACLE_BYTES) throw new Error('oracle must be a 36-byte outpoint')
  const s = new Script()
  s.add(state(G, side, balance, owner)).add(Opcode.OP_DROP)
  C.authenticate(s)
  s.add(Opcode.OP_TOALTSTACK)
  const a = new StackAsm(s).given(['pubkey', 'sig', 'newA4', 'newB4', 'iblobP', 'pOut0', 'pOut1', 'pTailP', 'ltP', 'iblobG', 'gOut0', 'gOut1', 'pTailG', 'ltG', 'oPreOuts', 'oOutsBlob', 'oLt4', 'suffix', 'outTail']).seedAlt(['preimage'])
  emitRebalance(a, { G, oracle: oracleOp, requiredFlag })
  const size = s.toBuffer().length
  if (size < 253 || size > 65535) throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  return s
}

// ---- scenario construction ----
function coinTxout (params) {
  const scriptBuf = buildScript(params).toBuffer()
  return Buffer.concat([dustLE(), varint(scriptBuf.length), scriptBuf])
}
/** A tx spending `spendOutpoints` and creating the side-0/side-1 pair at outputs 0,1. */
function pairTx (spendOutpoints, side0, side1) {
  const tx = new bsv.Transaction()
  for (const op of spendOutpoints) {
    const display = Buffer.from(op.internal); display.reverse()
    tx.addInput(new bsv.Transaction.Input({ prevTxId: display, outputIndex: op.vout, script: new bsv.Script(), sequenceNumber: 0xffffffff }), new bsv.Script().add(Opcode.OP_1), 5000)
  }
  tx.addOutput(new bsv.Transaction.Output({ script: buildScript(side0), satoshis: DUST }))
  tx.addOutput(new bsv.Transaction.Output({ script: buildScript(side1), satoshis: DUST }))
  const raw = tx.toBuffer()
  return { tx, raw, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}
/** Split a pair tx (side 0, side 1, then any change) into iblob (inputs ‖ outCount) ‖
 *  [pOut0, pOut1] ‖ pTail (outputs past the pair) ‖ lt4. */
function decomposePair (raw) {
  const r = buf(raw)
  const reader = new bsv.encoding.BufferReader(r); reader.read(4)
  const inCount = reader.readVarintNum()
  for (let i = 0; i < inCount; i++) { reader.read(32); reader.read(4); const sl = reader.readVarintNum(); reader.read(sl); reader.read(4) }
  const outCount = reader.readVarintNum()
  if (outCount < 2) throw new Error('a pair tx needs at least 2 outputs')
  const outsStart = reader.pos
  const iblob = r.slice(4, outsStart)                       // inputCount ‖ inputs ‖ outCount
  const outs = []
  for (let i = 0; i < 2; i++) { const s0 = reader.pos; reader.read(8); const sl = reader.readVarintNum(); reader.read(sl); outs.push(r.slice(s0, reader.pos)) }
  const pairEnd = reader.pos
  for (let i = 2; i < outCount; i++) { reader.read(8); const sl = reader.readVarintNum(); reader.read(sl) }
  const pTail = r.slice(pairEnd, reader.pos)
  const lt4 = r.slice(reader.pos)
  const rebuilt = Buffer.concat([r.slice(0, 4), iblob, outs[0], outs[1], pTail, lt4])
  if (!rebuilt.equals(r)) throw new Error('pair decomposition mismatch')
  return { iblob, pOut0: outs[0], pOut1: outs[1], pTail, lt4, txidInternal: bsv.crypto.Hash.sha256sha256(r) }
}

const OA = bsv.PrivateKey.fromRandom()
const OB = bsv.PrivateKey.fromRandom()
const DUMMY = Buffer.alloc(4)

/**
 * Build a rebalance spend of one member and everything the backtrace needs.
 *  kind 'genesis' — the pair was minted by the genesis tx (spent G); grandparent unused.
 *  kind 'child'   — the pair came from a rebalance whose parent was the genesis.
 */
function scenario (tc) {
  const G = buf(tc.genesis)
  const gTxid = G.slice(0, 32); const gVout = G.readUInt32LE(32)
  const oa = pkhOf(tc.ownerA || OA); const ob = pkhOf(tc.ownerB || OB)
  const kind = tc.kind || 'genesis'
  const requiredFlag = tc.requiredFlag ?? 1

  // the oracle coin: a tagged coin whose source tx and outpoint the gate backtraces.
  // `presentOracleFlag` lets a test co-spend an oracle carrying the WRONG flag.
  const oracleOwner = pkhOf(tc.oracleOwner || OA)
  const oSrc = witness.taggedCoinTx({ flag: tc.presentOracleFlag ?? requiredFlag, ownerPKH: oracleOwner })
  const oracle = witness.outpoint36(oSrc.tx.id, 0)
  const co = { oracle, requiredFlag }                        // baked into every coin

  const gen = pairTx([tc.counterfeit ? { internal: Buffer.alloc(32, 7), vout: 0 } : { internal: gTxid, vout: gVout }],
    { genesis: G, side: 0, balance: tc.a0 ?? 60, owner: oa, ...co }, { genesis: G, side: 1, balance: tc.b0 ?? 40, owner: ob, ...co })

  if (kind === 'genesis') {
    const parent = decomposePair(gen.raw)
    return { parent, coinTxid: gen.txidInternal, spendSide: tc.spendSide ?? 0, grand: parent, oSrc, oracle, requiredFlag, co }
  }
  const reb = pairTx([{ internal: gen.txidInternal, vout: 0 }, { internal: gen.txidInternal, vout: 1 }],
    { genesis: G, side: 0, balance: tc.a1 ?? 50, owner: oa, ...co }, { genesis: G, side: 1, balance: tc.b1 ?? 50, owner: ob, ...co })
  return { parent: decomposePair(reb.raw), coinTxid: reb.txidInternal, spendSide: tc.spendSide ?? 0, grand: decomposePair(gen.raw), oSrc, oracle, requiredFlag, co }
}

module.exports = {
  name: 'guarded',
  describe: 'conserve ∧ witness: a conserved pair whose rebalance is gated on a named oracle coin’s flag',
  example: () => ({ genesis: genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0), kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, requiredFlag: 1, ownerKey: OA, ownerA: OA, ownerB: OB }),

  G_BYTES,
  DUST,
  buildScript,
  genesisOutpoint,
  state,
  pkhOf,
  balLE,
  scenario,
  decomposePair,
  pairTx,
  coinTxout,

  lock (tc) {
    if (!tc.genesis) throw new Error('genesis is required')
    const sc = tc._scn || (tc._scn = scenario(tc))
    const side = sc.spendSide
    const owner = pkhOf(side === 0 ? (tc.ownerA || OA) : (tc.ownerB || OB))
    const bal = (tc.kind || 'genesis') === 'child'
      ? (side === 0 ? (tc.a1 ?? 50) : (tc.b1 ?? 50))
      : (side === 0 ? (tc.a0 ?? 60) : (tc.b0 ?? 40))
    return buildScript({ genesis: tc.genesis, side, balance: bal, owner, ...sc.co })
  },

  spendOutpoint (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc))
    const display = Buffer.from(sc.coinTxid); display.reverse()
    return { prevTxId: display, prevVout: sc.spendSide }
  },

  // the pair partner (input 1), the oracle coin (input 2), then a fee input (input 3)
  siblings (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc))
    const sibSide = 1 - sc.spendSide
    const display = Buffer.from(sc.coinTxid); display.reverse()
    const one = new bsv.Script().add(Opcode.OP_1)
    const oracle = { prevTxId: sc.oSrc.tx.id, outputIndex: 0, script: sc.oSrc.tx.outputs[0].script, satoshis: sc.oSrc.tx.outputs[0].satoshis }
    const fee = { prevTxId: Buffer.alloc(32, 9), outputIndex: 0, script: one, satoshis: 3000 }
    const partner = { prevTxId: display, outputIndex: sibSide, script: one, satoshis: DUST }
    if (tc.omitSibling) return [oracle, fee]                   // the pair partner is NOT co-spent
    if (tc.omitOracle) return [partner, fee]                   // the oracle is NOT co-spent
    return [partner, oracle, fee]
  },

  // the two successors, in order: side-0 then side-1, with the new balances
  outputs (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc))
    const oa = pkhOf(tc.ownerA || OA); const ob = pkhOf(tc.ownerB || OB)
    if (tc.actualOutputs) return tc.actualOutputs({ oa, ob, co: sc.co })
    return [
      new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis, side: 0, balance: tc.newA, owner: oa, ...sc.co }), satoshis: DUST }),
      new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis, side: 1, balance: tc.newB, owner: ob, ...sc.co }), satoshis: DUST })
    ]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sc = tc._scn || (tc._scn = scenario(tc))
    const priv = tc.ownerKey || (sc.spendSide === 0 ? OA : OB)
    const pub = (tc.wrongPubkey || priv).publicKey.toBuffer()

    // suffix of hashPrevouts after the pair's two outpoints (the fee input, etc.)
    const vector = Buffer.concat(tx.inputs.map(i => {
      const t = Buffer.from(i.prevTxId); t.reverse(); const v = Buffer.alloc(4); v.writeUInt32LE(i.outputIndex, 0); return Buffer.concat([t, v])
    }))
    const suffix = vector.slice(72)   // after inputs 0 and 1 (the pair)

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const s = new Script()
      s.add(pub).add(sig)
      s.add(balLE(tc.newA)).add(balLE(tc.newB))
      s.add(sc.parent.iblob).add(sc.parent.pOut0).add(sc.parent.pOut1).add(sc.parent.pTail.length ? sc.parent.pTail : Opcode.OP_0).add(sc.parent.lt4)
      s.add(sc.grand.iblob).add(sc.grand.pOut0).add(sc.grand.pOut1).add(sc.grand.pTail.length ? sc.grand.pTail : Opcode.OP_0).add(sc.grand.lt4)
      s.add(sc.oSrc.preOuts).add(sc.oSrc.outsBlob).add(sc.oSrc.lt4)
      s.add(suffix.length ? suffix : Opcode.OP_0)
      const outTail = Buffer.concat(tx.outputs.slice(2).map(o => o.toBufferWriter().toBuffer()))
      s.add(outTail.length ? outTail : Opcode.OP_0)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
