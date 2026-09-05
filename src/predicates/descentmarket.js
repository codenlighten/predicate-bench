'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const R = require('../rabin')
const rabinScript = require('../rabinscript')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// DESCENT MARKET — the unification: a COUNTERFEIT-PROOF ([`descentbulletin`](descentbulletin))
// reusable outcome fact that also carries a pTail of position payouts ([`bulletin`](bulletin)),
// so a whole batch of positions can settle against it in one transaction while it proves, on
// every hop, that it descends from the unique genesis. This is the single deployable coin a
// market of positions written BEFORE the outcome is known rests on: it recreates itself at
// output 0, pays any number of positions in the tail, and — because its OWN covenant runs on
// every spend — guarantees that a coin carrying the market's genesis G that did not descend from
// the one spend of G can be created but never spent.
//
//   state = genesis(36) ‖ status(1) ‖ outcome(1)   (always at output 0 of its tx, always input 0 of its spend)
//
//   resolve   OPEN → RESOLVED, quorum-gated, proving descent from G, recreated at output 0 (+ pTail)
//   read      RESOLVED → RESOLVED, recreated unchanged at output 0 (+ pTail), proving descent from G
//
// Two generalisations over `descentbulletin` make the tail possible:
//   - the RECREATE binds output 0 to the coin and lets a pTail of arbitrary trailing outputs
//     ride behind it (the position payouts), exactly as `bulletin`'s read does;
//   - the DESCENT backtrace rebuilds a MULTI-output parent — its `iblob2` folds the output
//     count in and it presents the parent's own trailing outputs (`parentPTail`), exactly as
//     `conserve`'s parent backtrace does (pitfall 26) — because a read that co-settled positions
//     is itself a multi-output parent for the next read.
//
// Soundness is inductive, as `lineage`/`descentbulletin` argue: a spend is valid only if its
// funding is network-validated; if that funding spent a parent bulletin, the parent's covenant
// enforced ITS OWN descent when mined. Authenticity chains back to the one spend of G, and the
// pTail is unverified because it is only the losers' and winners' payouts — value the network,
// not the bulletin, accounts for.

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map((k) => BigInt(k.n))
const PANEL_KEYS = PANEL.map((k) => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const G_BYTES = 36
const STATUS_BYTES = 1
const OUTCOME_BYTES = 1
const STATE_BYTES = G_BYTES + STATUS_BYTES + OUTCOME_BYTES   // 38, push-op 0x26
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const OUTCOME_MSG_BYTES = 4
const DUST = 2000
const DEFAULT_FEE = 250
const TX_VERSION = Buffer.from('01000000', 'hex')

const OPEN = 0
const RESOLVED = 1

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function dustLE () { const b = Buffer.alloc(8); b.writeUIntLE(DUST, 0, 6); return b }
function outcomeLE (o) { const b = Buffer.alloc(OUTCOME_MSG_BYTES); b.writeUInt32LE(o >>> 0, 0); return b }
function oracleMessage (genesis, o) { return Buffer.concat([buf(genesis), outcomeLE(o)]) }
function state (genesis, status, outcome) { return Buffer.concat([buf(genesis), Buffer.from([status]), Buffer.from([outcome])]) }
function varint (len) { if (len < 253) return Buffer.from([len]); const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b }

// read self out of the preimage: [.., preimage, header, genesis, status1, outcome1, tail]  (myChunk kept)
function readSelf (asm) {
  asm.clause(C.selfChunk, 0, ['myChunk'])
  asm.pick('myChunk'); asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(G_BYTES, 'genesis', 'r2')
  asm.splitAt(STATUS_BYTES, 'status1', 'r3')
  asm.splitAt(OUTCOME_BYTES, 'outcome1', 'tail')
}
function requireStatus (asm, want) {
  asm.pick('status1'); asm.bin2num('st#'); asm.num(want, 'want'); asm.numEqualVerify()
}

// Prove this coin descends from G: recover my funding txid, rebuild my parent's outpoint,
// and require it to be G (the mint) OR a same-covenant, same-G bulletin (any status/outcome).
// The spender presents raw1 (my funding tx), iblob2/lt2 (parent's funding inputs/locktime),
// and parentChunk (my parent's scriptlen‖script).
function proveDescent (asm) {
  // my own outpoint (preimage[68:104]) → my funding txid
  asm.pick('preimage'); asm.clause((x) => x.add(Opcode.OP_DUP).add(n(68)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP).add(n(36)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP), 0, ['myOutpoint'])
  asm.nip()
  asm.pick('myOutpoint'); asm.splitAt(32, 'myTxid', 'myVout'); asm.drop()
  asm.pick('raw1'); asm.hash256('r1h'); asm.pick('myTxid'); asm.equalVerify()   // raw1 is really my funding tx

  // my parent's outpoint = input 0 of raw1 (after version(4) ‖ inCount(1))
  asm.pick('raw1'); asm.splitAt(5, 'p5', 'r1rest'); asm.nip()
  asm.splitAt(G_BYTES, 'parentOutpoint', 'ptail'); asm.drop()

  // case (a): the mint — parent outpoint IS the genesis G
  asm.pick('parentOutpoint'); asm.pick('genesis'); asm.equal('isMint')

  // case (b): parent is a genuine same-G bulletin. EVERY check here is NON-ABORTING (a
  // boolean), so the mint path — where these are legitimately false and parentChunk is a
  // dummy — survives to the `isMint OR isChild` test. parentChunk must match myChunk except
  // the status+outcome bytes (same covenant + same genesis), and rebuild the parent's
  // single-output funding tx to the parent txid.
  asm.pick('parentOutpoint'); asm.splitAt(32, 'pTxid', 'pv'); asm.drop()
  const preLen = HEAD_BYTES + G_BYTES
  asm.pick('parentChunk'); asm.splitAt(preLen, 'pPre', 'pRest')
  asm.pick('myChunk'); asm.splitAt(preLen, 'mPre', 'mRest2')
  asm.pick('pPre'); asm.pick('mPre'); asm.equal('preEq')                      // header+genesis match?
  asm.pick('pRest'); asm.splitAt(STATUS_BYTES + OUTCOME_BYTES, 'pSO', 'pTailPart'); asm.nip()
  asm.pick('mRest2'); asm.splitAt(STATUS_BYTES + OUTCOME_BYTES, 'mSO', 'mTailPart'); asm.nip()
  asm.pick('pTailPart'); asm.pick('mTailPart'); asm.equal('tailEq')           // tail match?
  // rebuild parent funding: version ‖ iblob2(inputs ‖ outCount) ‖ (dust ‖ parentChunk) ‖ parentPTail ‖ lt2.
  // iblob2 folds the parent's output count in (no lone small-int push), and parentPTail carries the
  // parent's OWN trailing outputs — because a read that co-settled positions is a multi-output parent.
  asm.data(TX_VERSION, 'ver'); asm.pick('iblob2'); asm.cat('vi')
  asm.data(dustLE(), 'pd'); asm.pick('parentChunk'); asm.cat('pTxOut'); asm.cat('vio')
  asm.pick('parentPTail'); asm.cat('viot')
  asm.pick('lt2'); asm.cat('raw2'); asm.hash256('r2h'); asm.pick('pTxid'); asm.equal('hashEq')   // rebuilds to parent?
  // isChild = preEq ∧ tailEq ∧ hashEq
  asm.pick('preEq'); asm.pick('tailEq'); asm.raw(Opcode.OP_BOOLAND, 2, ['e1'])
  asm.pick('e1'); asm.pick('hashEq'); asm.raw(Opcode.OP_BOOLAND, 2, ['isChild'])
  asm.pick('isMint'); asm.pick('isChild'); asm.raw(Opcode.OP_BOOLOR, 2, ['authentic']); asm.verify()
}

// bind OUTPUT 0 to the recreated coin (dust ‖ newChunk) and let a pTail of position payouts ride
// behind it: HASH256(output0 ‖ myPTail) == the preimage's hashOutputs.
function bindSelfOutput (asm, chunkName) {
  asm.data(dustLE(), 'nd'); asm.pick(chunkName); asm.cat('output0')
  asm.pick('output0'); asm.pick('myPTail'); asm.cat('allOuts'); asm.hash256('oh')
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['hoField'])
  asm.nip(); asm.equalVerify()
}

// OPEN → RESOLVED, gated by the quorum and proving descent from G.
function resolveBody (asm, { moduli, m }) {
  const N = moduli.length
  readSelf(asm)
  requireStatus(asm, OPEN)

  asm.pick('outcome4'); asm.bin2num('o')
  asm.pick('o'); asm.num(OPEN, 'z'); asm.numEqual('is0')
  asm.pick('o'); asm.num(RESOLVED, 'one'); asm.numEqual('is1')
  asm.raw(Opcode.OP_BOOLOR, 2, ['inRange']); asm.verify()

  asm.pick('genesis'); asm.pick('outcome4'); asm.cat('omsg')
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'omsg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()

  proveDescent(asm)

  // successor: genesis UNCHANGED, status → RESOLVED, outcome → o
  asm.pick('outcome4'); asm.splitAt(1, 'ocLo', 'ocHi')
  asm.pick('header'); asm.pick('genesis'); asm.cat('hg')
  asm.num(RESOLVED, 'rb'); asm.cat('hgs'); asm.pick('ocLo'); asm.cat('hgso')
  asm.pick('tail'); asm.cat('newChunk')
  bindSelfOutput(asm, 'newChunk')
}

// RESOLVED → RESOLVED, recreated unchanged, proving descent from G.
function readBody (asm) {
  readSelf(asm)
  requireStatus(asm, RESOLVED)
  proveDescent(asm)
  asm.pick('myChunk', 'newChunk')            // recreate exactly (unchanged)
  bindSelfOutput(asm, 'newChunk')
}

function buildScript ({ genesis, status = OPEN, outcome = 0, m = 2, panelN }) {
  const g = buf(genesis)
  if (g.length !== G_BYTES) throw new Error('genesis must be a 36-byte outpoint')
  const moduli = (panelN || PANEL_N).map((x) => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)

  const s = new Script()
  s.add(state(g, status, outcome)).add(Opcode.OP_DROP)
  C.authenticateThenBranch(s)

  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)
  const rv = new StackAsm(s); rv.main = ['outcome4', ...slots, 'raw1', 'iblob2', 'lt2', 'parentChunk', 'parentPTail', 'myPTail', 'preimage']
  resolveBody(rv, { moduli, m })
  while (rv.main.length) rv.drop()
  rv.raw(Opcode.OP_1, 0, ['ok'])
  const d = rv.main.length

  s.add(Opcode.OP_ELSE)
  const rd = new StackAsm(s); rd.main = ['raw1', 'iblob2', 'lt2', 'parentChunk', 'parentPTail', 'myPTail', 'preimage']
  readBody(rd)
  while (rd.main.length) rd.drop()
  rd.raw(Opcode.OP_1, 0, ['ok'])
  if (rd.main.length !== d) throw new Error(`descentmarket: branches leave different depths (${d} vs ${rd.main.length})`)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) throw new Error(`script is ${size} bytes; needs 253..65535 for the 3-byte varint`)
  return s
}

module.exports = {
  name: 'descentmarket',
  describe: 'a counterfeit-proof reusable oracle fact: carries its genesis outpoint and proves, one hop at a time, that it descends from the unique genesis — resolve and read both refuse a coin that does not',
  example: () => ({ genesis: Buffer.alloc(36, 5), m: 2, signers: [0, 1], attestOutcome: 1, branch: 'resolve', scenario: 'genesis' }),
  G_BYTES, STATE_BYTES, HEAD_BYTES, DUST, DEFAULT_FEE, OPEN, RESOLVED, PANEL_N,
  buildScript, state, oracleMessage, varint,

  genesisOutpoint (displayTxid, vout) {
    const txid = Buffer.from(displayTxid, 'hex'); txid.reverse()
    const v = Buffer.alloc(4); v.writeUInt32LE(vout, 0)
    return Buffer.concat([txid, v])
  },

  scenario (tc) {
    if (tc._scn) return tc._scn
    const G = tc.genesis
    const m = tc.m
    const o = tc.attestOutcome ?? 1
    const openScript = buildScript({ genesis: G, status: OPEN, outcome: 0, m })
    const resolvedScript = buildScript({ genesis: G, status: RESOLVED, outcome: o, m })
    const kind = tc.kind || (tc.branch === 'read' ? 'read' : 'resolve')

    const EMPTY = Buffer.alloc(0)
    const myPTail = tc.myPTail || EMPTY

    if (kind === 'resolve') {
      const genTx = oneToOne(G.slice(0, 32), G.readUInt32LE(32), openScript)
      const raw1 = genTx.toBuffer()
      // parent is G (the mint), so iblob2/parentChunk/parentPTail are dummies (isMint wins)
      tc._scn = { raw1, iblob2: Buffer.alloc(41), lt2: Buffer.alloc(4), parentChunk: chunkOf(openScript), parentPTail: EMPTY, myPTail, coinScript: openScript, coinTxidInternal: sha2(raw1), coinVout: 0 }
    } else if (kind === 'read') {
      const genTx = oneToOne(G.slice(0, 32), G.readUInt32LE(32), openScript); const genRaw = genTx.toBuffer()
      const resTx = oneToOne(sha2(genRaw), 0, resolvedScript); const raw1 = resTx.toBuffer()
      const pd = decompose(genRaw)   // the OPEN parent's funding = the genesis mint (single output)
      tc._scn = { raw1, iblob2: pd.iblob, lt2: pd.lt4, parentChunk: pd.out0chunk, parentPTail: pd.pTail, myPTail, coinScript: resolvedScript, coinTxidInternal: sha2(raw1), coinVout: 0 }
    } else if (kind === 'read-of-read') {
      // the parent's FUNDING is a MULTI-output tx (a read that co-settled a position), so the
      // backtrace must rebuild it: G → OPEN → resolve → read0 (bulletin + a payout in the tail)
      // → read1. The coin we spend is read1's output 0; its parent is read0's output 0, whose
      // funding tx read0 has TWO outputs.
      const genTx = oneToOne(G.slice(0, 32), G.readUInt32LE(32), openScript); const genRaw = genTx.toBuffer()
      const resTx = oneToOne(sha2(genRaw), 0, resolvedScript); const resRaw = resTx.toBuffer()
      const payScript = bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(Buffer.alloc(20, 8)))
      const read0 = new bsv.Transaction()
      read0.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(sha2(resRaw)).reverse(), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff }), resolvedScript, DUST)
      read0.addOutput(new bsv.Transaction.Output({ script: resolvedScript, satoshis: DUST }))       // output 0: bulletin persists
      read0.addOutput(new bsv.Transaction.Output({ script: payScript, satoshis: 1500 }))            // pTail: a position payout
      const read0Raw = read0.toBuffer()
      const read1 = oneToOne(sha2(read0Raw), 0, resolvedScript); const raw1 = read1.toBuffer()      // read1 spends read0:0 → the coin we spend
      const pd = decompose(read0Raw)                                                                // parent's funding (read0) is MULTI-output
      tc._scn = { raw1, iblob2: pd.iblob, lt2: pd.lt4, parentChunk: pd.out0chunk, parentPTail: pd.pTail, myPTail, coinScript: resolvedScript, coinTxidInternal: sha2(raw1), coinVout: 0 }
    } else { // counterfeit: a RESOLVED bulletin minted from a plain (non-descent) UTXO
      const plainTx = oneToOne(Buffer.alloc(32, 7), 0, bsv.Script.buildPublicKeyHashOut(bsv.PrivateKey.fromRandom().toAddress()))
      const plainRaw = plainTx.toBuffer()
      const countTx = oneToOne(sha2(plainRaw), 0, resolvedScript); const raw1 = countTx.toBuffer()
      const pd = decompose(plainRaw)
      tc._scn = { raw1, iblob2: pd.iblob, lt2: pd.lt4, parentChunk: chunkOf(openScript), parentPTail: pd.pTail, myPTail, coinScript: resolvedScript, coinTxidInternal: sha2(raw1), coinVout: 0 }
    }
    return tc._scn
  },

  lock (tc) {
    if (!tc.genesis) throw new Error('genesis is required')
    return module.exports.scenario(tc).coinScript
  },

  spendOutpoint (tc) {
    const sc = module.exports.scenario(tc)
    const display = Buffer.from(sc.coinTxidInternal); display.reverse()
    return { prevTxId: display, prevVout: sc.coinVout }
  },

  outputs (tc) {
    const o = tc.attestOutcome ?? 1
    const script = buildScript({ genesis: tc.genesis, status: RESOLVED, outcome: o, m: tc.m })
    return [new bsv.Transaction.Output({ script, satoshis: DUST }), ...(tc.tailOutputs || [])]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sc = module.exports.scenario(tc)
    const branch = tc.branch || ((tc.kind && tc.kind !== 'resolve') ? 'read' : 'resolve')
    const N = (tc.panelN || PANEL_N).length

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const us = new Script()
      if (branch === 'resolve') {
        const signed = tc.attestOutcome ?? 1
        const presented = tc.forgeOutcome !== undefined ? tc.forgeOutcome : signed
        const attestG = tc.attestGenesis || tc.genesis
        const slotKeys = tc.slotKeys || (() => { const a = new Array(N).fill(null); (tc.signers || []).forEach((i) => { a[i] = i }); return a })()
        us.add(outcomeLE(presented))
        for (let i = 0; i < N; i++) {
          const k = slotKeys[i]
          if (k === null || k === undefined) { us.add(Buffer.from([0])).add(Buffer.from([0, 0])) } else {
            const msg = oracleMessage(attestG, signed); const { sig, padding } = R.sign(msg, PANEL_KEYS[k])
            us.add(sig).add(Buffer.from([padding & 0xff, (padding >> 8) & 0xff]))
          }
        }
      }
      const pT = (b) => (b && b.length ? b : Buffer.alloc(0))
      us.add(sc.raw1).add(sc.iblob2).add(sc.lt2).add(sc.parentChunk).add(pT(sc.parentPTail)).add(pT(sc.myPTail))
      us.add(branch === 'resolve' ? Opcode.OP_1 : Opcode.OP_0).add(preimage)
      return us
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}

function oneToOne (prevInternal, vout, outScript) {
  const disp = Buffer.from(prevInternal); disp.reverse()
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: disp, outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xffffffff }), new bsv.Script().add(Opcode.OP_1), 5000)
  tx.addOutput(new bsv.Transaction.Output({ script: outScript, satoshis: DUST }))
  return tx
}
// Split any tx (a bulletin at output 0, then any trailing outputs) into iblob (inputCount ‖
// inputs ‖ outCount), out0chunk (the output-0 script chunk, value stripped), pTail (outputs
// 1..end), and lt4 — so the descent backtrace can rebuild a multi-output parent.
function decompose (raw) {
  const reader = new bsv.encoding.BufferReader(raw)
  reader.read(4)
  const inCount = reader.readVarintNum()
  for (let i = 0; i < inCount; i++) { reader.read(32); reader.read(4); const sl = reader.readVarintNum(); reader.read(sl); reader.read(4) }
  const outsStart = reader.pos
  const outCount = reader.readVarintNum()
  const o0start = reader.pos
  const iblob = raw.slice(4, o0start)                 // inputCount ‖ inputs ‖ outCount
  reader.read(8); const sl0 = reader.readVarintNum(); reader.read(sl0)
  const out0chunk = raw.slice(o0start + 8, reader.pos)
  const pTailStart = reader.pos
  for (let i = 1; i < outCount; i++) { reader.read(8); const sl = reader.readVarintNum(); reader.read(sl) }
  const pTail = raw.slice(pTailStart, reader.pos)
  const lt4 = raw.slice(reader.pos)
  return { iblob, out0chunk, pTail, lt4 }
}
function chunkOf (script) { const b = script.toBuffer(); return Buffer.concat([varint(b.length), b]) }
const sha2 = bsv.crypto.Hash.sha256sha256
