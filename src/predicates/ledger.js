'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// LEDGER — pool ∧ journal: an N-body conserved state system that is ALSO auditable.
//
// `conserve` fixed a total across TWO coins. `pool` fixes it across N: a group of
// coins whose balances always sum to the same constant, rebalanced by a transaction
// that spends ALL of them and recreates ALL of them. A treasury split into buckets
// (Treasury, Operations, Research, …) that may move quantity between buckets but can
// never change the total, and cannot be counterfeited into existence.
//
//   state = G(36) ‖ index(1) ‖ balance(4) ‖ owner(20)
//
//   rebalance   spend the N members (inputs 0..N−1, in index order), recreate the N
//               members, Σ balanceᵢ preserved, G and owners carried forward, every
//               owner signs, every member descends from the genesis.
//
// It is `conserve`'s machinery with 2 replaced by a baked N: each member backtraces
// the single SHARED PARENT that created all N (reading every balance at once), proves
// the whole group is co-spent in order, checks Σ, and binds the N successors. The
// script is index-agnostic — all members run identical logic, differing only in state.

const G_BYTES = 36
const IDX_BYTES = 1
const BAL_BYTES = 4
const OWNER_BYTES = 20
const SEQ_BYTES = 4
const HEADH_BYTES = 32
const STATE_BYTES = G_BYTES + IDX_BYTES + BAL_BYTES + OWNER_BYTES + SEQ_BYTES + HEADH_BYTES  // 97
const VARINT_BYTES = 3
// state is 97 bytes (> 75): pushed with OP_PUSHDATA1, a TWO-byte push-op. Header = varint(3) ‖ pushop(2).
const HEAD_BYTES = VARINT_BYTES + 2
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')
const GENESIS_HEAD = Buffer.alloc(HEADH_BYTES)
const OFF_G = HEAD_BYTES
const OFF_IDX = OFF_G + G_BYTES
const OFF_BAL = OFF_IDX + IDX_BYTES
const OFF_OWNER = OFF_BAL + BAL_BYTES
const OFF_SEQ = OFF_OWNER + OWNER_BYTES
const OFF_HEAD = OFF_SEQ + SEQ_BYTES
const OFF_TAIL = OFF_HEAD + HEADH_BYTES
const T = 8

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function hash160Of (a) { return Buffer.isBuffer(a) ? a : (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer }
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
function varint (len) { if (len < 253) return Buffer.from([len]); const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b }
function genesisOutpoint (displayTxid, vout) {
  const txid = Buffer.from(displayTxid, 'hex'); txid.reverse()
  const v = Buffer.alloc(4); v.writeUInt32LE(vout, 0); return Buffer.concat([txid, v])
}
function seqLE (v) { const b = Buffer.alloc(SEQ_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function headBuf (h) { const b = h ? buf(h) : GENESIS_HEAD; if (b.length !== HEADH_BYTES) throw new Error('head must be 32 bytes'); return b }
function state (G, index, balance, owner, seq, head) {
  return Buffer.concat([buf(G), Buffer.from([index]), balLE(balance), pkhOf(owner), seqLE(seq || 0), headBuf(head)])
}
function chain (oldHead, recordHash) { return bsv.crypto.Hash.sha256sha256(Buffer.concat([headBuf(oldHead), buf(recordHash)])) }

const F_HASHPREVOUTS = C.hashPrevoutsFromFront
const F_HASHOUTPUTS = (x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32)
const F_OWNOUTPOINT = (x) => x.add(Opcode.OP_DUP).add(n(68)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP).add(n(36)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
function readField (asm, fn, name) { asm.fromAlt(); asm.clause(fn, 0, [name]); asm.swap(); asm.toAlt() }
function finishBranch (asm) { while (asm.main.length) asm.drop(); asm.fromAlt(); asm.drop(); asm.raw(Opcode.OP_1, 0, ['true']) }
function fieldFromChunk (asm, chunkName, off, len, out) {
  asm.pick(chunkName); asm.splitAt(off, 'pre_' + out, 'r_' + out); asm.nip()
  asm.splitAt(len, out, 't_' + out); asm.drop()
}
// splice new balance + seq + head into a member chunk, keeping G, index, owner and tail:
//   lo(HEAD‖G‖index) ‖ newBal ‖ owner ‖ newSeq ‖ newHead ‖ tail
function spliceState (asm, chunkName, newBalName, newSeqName, newHeadName, out) {
  asm.pick(chunkName); asm.splitAt(OFF_BAL, 'lo_' + out, 'lr_' + out); asm.drop()
  fieldFromChunk(asm, chunkName, OFF_OWNER, OWNER_BYTES, 'own_' + out)
  asm.pick(chunkName); asm.splitAt(OFF_TAIL, 'th_' + out, 'tail_' + out); asm.nip()
  asm.pick('lo_' + out); asm.pick(newBalName); asm.cat('sa_' + out)
  asm.pick('own_' + out); asm.cat('sb_' + out)
  asm.pick(newSeqName); asm.cat('sc_' + out)
  asm.pick(newHeadName); asm.cat('sd_' + out)
  asm.pick('tail_' + out); asm.cat(out)
}
function advanceSeq (asm, seqName, out) {
  asm.raw(Opcode.OP_0, 0, ['z_' + out]); asm.pick(seqName); asm.cat('sp_' + out)
  asm.bin2num('sn_' + out); asm.raw(Opcode.OP_1ADD, 1, ['si_' + out]); asm.num2bin(SEQ_BYTES, out)
}
function advanceHead (asm, oldHeadName, recordName, out) {
  asm.pick(oldHeadName); asm.pick(recordName); asm.cat('hc_' + out); asm.hash256(out)
}

function emitRebalance (asm, { G, N }) {
  // self + owner sig
  readField(asm, C.selfChunk, 'myChunk')
  fieldFromChunk(asm, 'myChunk', OFF_OWNER, OWNER_BYTES, 'myOwner')
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('myOwner'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()

  // parentTxid
  readField(asm, F_OWNOUTPOINT, 'myOutpoint')
  asm.pick('myOutpoint'); asm.splitAt(32, 'parentTxid', 'myVout'); asm.drop()

  // rebuild the parent tx: version ‖ iblobP ‖ pOut0..pOut(N-1) ‖ pTailP ‖ ltP, hash == parentTxid
  asm.data(VERSION, 've'); asm.pick('iblobP'); asm.cat('vi')
  for (let i = 0; i < N; i++) { asm.pick('pOut' + i); asm.cat('vi' + i) }
  asm.pick('pTailP'); asm.cat('viT')
  asm.pick('ltP'); asm.size('lsz'); asm.num(4, 'f4'); asm.equalVerify(); asm.cat('parentTx')
  asm.hash256('ptid'); asm.pick('parentTxid'); asm.equalVerify()

  // read each member the parent created: its G == G, index == i, its balance and chunk
  for (let i = 0; i < N; i++) {
    fieldFromChunk(asm, 'pOut' + i, T + OFF_G, G_BYTES, 'g' + i); asm.data(buf(G), 'G' + i); asm.pick('g' + i); asm.equalVerify()
    fieldFromChunk(asm, 'pOut' + i, T + OFF_IDX, IDX_BYTES, 'idx' + i); asm.pick('idx' + i); asm.bin2num('idxn' + i); asm.num(i, 'iw' + i); asm.numEqualVerify()
    fieldFromChunk(asm, 'pOut' + i, T + OFF_BAL, BAL_BYTES, 'b' + i); asm.pick('b' + i); asm.bin2num('bn' + i)
    fieldFromChunk(asm, 'pOut' + i, T + OFF_SEQ, SEQ_BYTES, 'seq' + i)
    fieldFromChunk(asm, 'pOut' + i, T + OFF_HEAD, HEADH_BYTES, 'head' + i)
    asm.pick('pOut' + i); asm.splitAt(T, 'pv' + i, 'chunk' + i); asm.nip()
  }

  // I am one of the parent's members
  asm.pick('myChunk'); asm.pick('chunk0'); asm.equal('mine')
  for (let i = 1; i < N; i++) { asm.pick('myChunk'); asm.pick('chunk' + i); asm.equal('m' + i); asm.raw(Opcode.OP_BOOLOR, 2, ['mine']) }
  asm.verify()

  // the whole group is co-spent: inputs 0..N-1 are (parentTxid, 0..N-1) in index order
  asm.pick('parentTxid'); asm.raw(Opcode.OP_0, 0, ['z0']); asm.num2bin(4, 'v0le'); asm.cat('grp')
  for (let i = 1; i < N; i++) { asm.pick('parentTxid'); asm.num(i, 'iv' + i); asm.num2bin(4, 'vle' + i); asm.cat('opi' + i); asm.cat('grp') }
  asm.pick('suffix'); asm.cat('prevoutsGuess')
  asm.hash256('hpGot'); readField(asm, F_HASHPREVOUTS, 'hpWant'); asm.equalVerify()

  // descent: parent spent G directly (genesis), OR its parent was a genuine member
  asm.pick('iblobP'); asm.splitAt(1, 'inc', 'afterInc'); asm.nip()
  asm.splitAt(G_BYTES, 'parentSpent', 'restIn'); asm.drop()
  asm.pick('parentSpent'); asm.data(buf(G), 'Gd'); asm.equal('isGenesis')
  fieldFromChunk(asm, 'gOut0', T + OFF_G, G_BYTES, 'gg'); asm.pick('gg'); asm.data(buf(G), 'Gg'); asm.equalVerify()
  asm.pick('gOut0'); asm.splitAt(T + OFF_TAIL, 'ghead', 'gtail'); asm.nip()
  asm.pick('myChunk'); asm.splitAt(OFF_TAIL, 'mhead', 'mtail'); asm.nip()
  asm.pick('gtail'); asm.pick('mtail'); asm.equalVerify()
  asm.pick('parentSpent'); asm.splitAt(32, 'gpTxid', 'gpVout'); asm.drop()
  asm.data(VERSION, 've2'); asm.pick('iblobG'); asm.cat('gi')
  for (let i = 0; i < N; i++) { asm.pick('gOut' + i); asm.cat('gi' + i) }
  asm.pick('pTailG'); asm.cat('giT')
  asm.pick('ltG'); asm.size('lsz2'); asm.num(4, 'f42'); asm.equalVerify(); asm.cat('grandTx')
  asm.hash256('gtid'); asm.pick('gpTxid'); asm.equal('gpHashOk')
  asm.pick('isGenesis'); asm.pick('gpHashOk'); asm.raw(Opcode.OP_BOOLOR, 2, ['descentOk']); asm.verify()

  // conservation: Σ old balance == Σ new balance
  for (let i = 0; i < N; i++) { asm.pick('newBal' + i); asm.size('ns' + i); asm.num(BAL_BYTES, 'nb' + i); asm.equalVerify() }
  asm.pick('newBal0'); asm.bin2num('newSum')
  for (let i = 1; i < N; i++) { asm.pick('newBal' + i); asm.bin2num('nn' + i); asm.add('newSum') }
  asm.pick('bn0'); asm.rename('oldSum')
  for (let i = 1; i < N; i++) { asm.pick('bn' + i); asm.add('oldSum') }
  asm.pick('newSum'); asm.numEqualVerify()

  // the audit chain advances for every member: seq += 1, head = HASH256(oldHead ‖ record),
  // sharing one recordHash for this rebalance
  for (let i = 0; i < N; i++) { advanceSeq(asm, 'seq' + i, 'newSeq' + i); advanceHead(asm, 'head' + i, 'recordHash', 'newHead' + i) }

  // successors: splice new balance + seq + head into each member, bind the N outputs (+ outTail)
  for (let i = 0; i < N; i++) {
    spliceState(asm, 'chunk' + i, 'newBal' + i, 'newSeq' + i, 'newHead' + i, 'newChunk' + i)
    asm.data(dustLE(), 'd' + i); asm.pick('newChunk' + i); asm.cat('out' + i)
  }
  asm.pick('out0'); asm.rename('outs')
  for (let i = 1; i < N; i++) { asm.pick('out' + i); asm.cat('outs') }
  asm.pick('outTail'); asm.cat('outsAll')
  asm.hash256('oh'); readField(asm, F_HASHOUTPUTS, 'ho'); asm.equalVerify()

  finishBranch(asm)
}

function givenNames (N) {
  const g = ['pubkey', 'sig']
  for (let i = 0; i < N; i++) g.push('newBal' + i)
  g.push('recordHash', 'iblobP')
  for (let i = 0; i < N; i++) g.push('pOut' + i)
  g.push('pTailP', 'ltP', 'iblobG')
  for (let i = 0; i < N; i++) g.push('gOut' + i)
  g.push('pTailG', 'ltG', 'suffix', 'outTail')
  return g
}

function buildScript ({ genesis, index, balance, owner, seq = 0, head, N = 3 }) {
  const G = buf(genesis)
  if (G.length !== G_BYTES) throw new Error('genesis must be a 36-byte outpoint')
  if (N < 2 || N > 16) throw new Error('N must be 2..16')
  const s = new Script()
  s.add(state(G, index, balance, owner, seq, head)).add(Opcode.OP_DROP)
  C.authenticate(s)
  s.add(Opcode.OP_TOALTSTACK)
  const a = new StackAsm(s).given(givenNames(N)).seedAlt(['preimage'])
  emitRebalance(a, { G, N })
  const size = s.toBuffer().length
  if (size < 253 || size > 65535) throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  return s
}

// ---- scenario ----
function groupTx (spendOutpoints, members) {
  const tx = new bsv.Transaction()
  for (const op of spendOutpoints) {
    const display = Buffer.from(op.internal); display.reverse()
    tx.addInput(new bsv.Transaction.Input({ prevTxId: display, outputIndex: op.vout, script: new bsv.Script(), sequenceNumber: 0xffffffff }), new bsv.Script().add(Opcode.OP_1), 5000)
  }
  for (const m of members) tx.addOutput(new bsv.Transaction.Output({ script: buildScript(m), satoshis: DUST }))
  const raw = tx.toBuffer()
  return { tx, raw, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}
function decomposeGroup (raw, N) {
  const r = buf(raw)
  const reader = new bsv.encoding.BufferReader(r); reader.read(4)
  const inCount = reader.readVarintNum()
  for (let i = 0; i < inCount; i++) { reader.read(32); reader.read(4); const sl = reader.readVarintNum(); reader.read(sl); reader.read(4) }
  const outCount = reader.readVarintNum()
  if (outCount < N) throw new Error(`a group tx needs at least ${N} outputs`)
  const outsStart = reader.pos
  const iblob = r.slice(4, outsStart)
  const outs = []
  for (let i = 0; i < N; i++) { const s0 = reader.pos; reader.read(8); const sl = reader.readVarintNum(); reader.read(sl); outs.push(r.slice(s0, reader.pos)) }
  const groupEnd = reader.pos
  for (let i = N; i < outCount; i++) { reader.read(8); const sl = reader.readVarintNum(); reader.read(sl) }
  const pTail = r.slice(groupEnd, reader.pos)
  const lt4 = r.slice(reader.pos)
  const rebuilt = Buffer.concat([r.slice(0, 4), iblob, ...outs, pTail, lt4])
  if (!rebuilt.equals(r)) throw new Error('group decomposition mismatch')
  return { iblob, outs, pTail, lt4, txidInternal: bsv.crypto.Hash.sha256sha256(r) }
}

const KEYS = Array.from({ length: 16 }, () => bsv.PrivateKey.fromRandom())

function scenario (tc) {
  const G = buf(tc.genesis)
  const N = tc.N ?? 3
  const owners = (tc.owners || KEYS.slice(0, N)).map(pkhOf)
  const gTxid = G.slice(0, 32); const gVout = G.readUInt32LE(32)
  const record = tc.recordHash || Buffer.alloc(32, 0xaa)
  const rec0 = tc.parentRecord || Buffer.alloc(32, 0xbb)
  const mk = (bals, seq, head) => bals.map((b, i) => ({ genesis: G, index: i, balance: b, owner: owners[i], seq, head, N }))
  const gen = groupTx([tc.counterfeit ? { internal: Buffer.alloc(32, 7), vout: 0 } : { internal: gTxid, vout: gVout }], mk(tc.start, 0, GENESIS_HEAD))
  if ((tc.kind || 'genesis') === 'genesis') {
    const parent = decomposeGroup(gen.raw, N)
    return { parent, grand: parent, coinTxid: gen.txidInternal, spendIndex: tc.spendIndex ?? 0, N, owners, startSeq: 0, startHead: GENESIS_HEAD, record }
  }
  const h1 = chain(GENESIS_HEAD, rec0)
  const reb = groupTx(tc.start.map((_, i) => ({ internal: gen.txidInternal, vout: i })), mk(tc.mid, 1, h1))
  return { parent: decomposeGroup(reb.raw, N), grand: decomposeGroup(gen.raw, N), coinTxid: reb.txidInternal, spendIndex: tc.spendIndex ?? 0, N, owners, startSeq: 1, startHead: h1, record }
}

module.exports = {
  name: 'ledger',
  describe: 'pool ∧ journal: an N-body conserved treasury whose every rebalance is appended to each bucket\u2019s audit chain',
  example: () => ({ genesis: genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0), N: 3, kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: KEYS[0], owners: KEYS.slice(0, 3) }),

  DUST,
  G_BYTES,
  GENESIS_HEAD,
  buildScript,
  genesisOutpoint,
  chain,
  balLE,
  pkhOf,
  scenario,
  decomposeGroup,
  groupTx,

  lock (tc) {
    if (!tc.genesis) throw new Error('genesis is required')
    const sc = tc._scn || (tc._scn = scenario(tc))
    const idx = sc.spendIndex
    const bal = ((tc.kind || 'genesis') === 'child' ? tc.mid : tc.start)[idx]
    return buildScript({ genesis: tc.genesis, index: idx, balance: bal, owner: sc.owners[idx], seq: sc.startSeq, head: sc.startHead, N: sc.N })
  },

  spendOutpoint (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc))
    const display = Buffer.from(sc.coinTxid); display.reverse()
    return { prevTxId: display, prevVout: sc.spendIndex }
  },

  // the other N-1 members (inputs 1..N-1, in index order after the coin under test) + a fee input.
  // The coin under test is index `spendIndex`; the harness places it at input 0, so the demo uses
  // spendIndex 0 and the members follow in order.
  siblings (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc))
    const display = Buffer.from(sc.coinTxid); display.reverse()
    const one = new bsv.Script().add(Opcode.OP_1)
    const sibs = []
    for (let i = 0; i < sc.N; i++) {
      if (i === sc.spendIndex) continue
      sibs.push({ prevTxId: display, outputIndex: i, script: one, satoshis: DUST })
    }
    if (tc.omitMember) sibs.pop()                               // drop one member — the group is not whole
    sibs.push({ prevTxId: Buffer.alloc(32, 9), outputIndex: 0, script: one, satoshis: 4000 })
    return sibs
  },

  outputs (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc))
    const next = tc.next
    const nseq = sc.startSeq + 1; const nhead = chain(sc.startHead, sc.record)
    if (tc.actualOutputs) return tc.actualOutputs({ owners: sc.owners, nseq, nhead })
    return next.map((b, i) => new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis, index: i, balance: b, owner: sc.owners[i], seq: nseq, head: nhead, N: sc.N }), satoshis: DUST }))
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sc = tc._scn || (tc._scn = scenario(tc))
    const priv = tc.ownerKey || (tc.owners || KEYS)[sc.spendIndex]
    const pub = (tc.wrongPubkey || priv).publicKey.toBuffer()
    const N = sc.N
    const vector = Buffer.concat(tx.inputs.map((i) => { const t = Buffer.from(i.prevTxId); t.reverse(); const v = Buffer.alloc(4); v.writeUInt32LE(i.outputIndex, 0); return Buffer.concat([t, v]) }))
    const suffix = vector.slice(36 * N)
    const pT = (d) => (d.length ? d : Opcode.OP_0)

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const s = new Script().add(pub).add(sig)
      for (let i = 0; i < N; i++) s.add(balLE(tc.next[i]))
      s.add(sc.record)
      s.add(sc.parent.iblob); for (let i = 0; i < N; i++) s.add(sc.parent.outs[i]); s.add(pT(sc.parent.pTail)).add(sc.parent.lt4)
      s.add(sc.grand.iblob); for (let i = 0; i < N; i++) s.add(sc.grand.outs[i]); s.add(pT(sc.grand.pTail)).add(sc.grand.lt4)
      s.add(suffix.length ? suffix : Opcode.OP_0)
      const outTail = Buffer.concat(tx.outputs.slice(N).map((o) => o.toBufferWriter().toBuffer()))
      s.add(outTail.length ? outTail : Opcode.OP_0)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
