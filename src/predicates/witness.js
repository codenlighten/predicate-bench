'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// WITNESS — a release gated on ANOTHER coin's on-chain state.
//
// Every cross-input covenant so far bound a sibling's IDENTITY ([`companion`](companion))
// or its VALUE ([`token`](token)). This binds a sibling's committed STATE: the witness
// pays its beneficiary only inside a transaction that also spends a SPECIFIC other coin,
// and only when that coin carries a required value in its script. A contract whose
// spendability is conditioned on a different contract's state — the two-body invariant,
// made sound.
//
// The sibling is a "tagged coin": <flag,4> OP_DROP <P2PKH>. Three checks, each honest:
//   1. companion — the sibling's outpoint is genuinely one of THIS transaction's inputs.
//      hashPrevouts is a hash the covenant cannot invert, but the spender can push the
//      surrounding outpoints and the covenant checks HASH256(prefix ‖ sibling ‖ suffix)
//      == hashPrevouts. The sibling's outpoint is BAKED, so it is canonical — not a
//      spender-chosen coin that merely happens to carry the flag.
//   2. backtrace — the sibling's SOURCE transaction, rebuilt from its parts and hashed,
//      equals the txid the baked outpoint names. Its output 0 is the tagged coin, so its
//      flag is read straight out of the reconstructed outputs and must equal the required
//      value. This is what [`token`](token)'s merge does to prove a sibling's balance,
//      turned to proving a sibling's state.
//   3. the beneficiary signs — so only they can trigger the release, wherever it points.
//
// Sound because the sibling is pinned by outpoint (1) and its state proven from the tx
// that created it (2), and CURRENT because that coin is being spent right now (1). What
// it does NOT claim — honestly, like [`companion`](companion) — is anything about coins
// the transaction does not spend: it reads the state of THIS co-spent sibling, no more.
//
// Uses: a payment released when a certificate is shown revoked; an escrow leg armed by
// a partner contract reaching a state; a dead-man's release keyed to another coin moving.

const OUTPOINT_BYTES = 36
const FLAG_BYTES = 4
const TX_VERSION = Buffer.from('01000000', 'hex')
// a tagged coin is <push4> <flag,4> OP_DROP ... at output 0 of its source tx, so its
// flag sits at: value(8) ‖ scriptVarint(1) ‖ pushop(1) ‖ flag(4)
const FLAG_OFFSET = 8 + 1 + 1

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  return /^[0-9a-f]{40}$/i.test(a) ? Buffer.from(a, 'hex') : hash160Of(a)
}
function flagLE (v) {
  if (Buffer.isBuffer(v)) return v
  const b = Buffer.alloc(FLAG_BYTES); b.writeUInt32LE(v >>> 0, 0); return b
}

/** An outpoint as hashPrevouts commits to it: internal (reversed) txid ‖ vout LE. */
function outpoint36 (prevTxId, vout) {
  const txid = Buffer.from(buf(prevTxId)); txid.reverse()
  const idx = Buffer.alloc(4); idx.writeUInt32LE(vout, 0)
  return Buffer.concat([txid, idx])
}

/** The locking script of a tagged coin: <flag> OP_DROP OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG. */
function taggedCoinScript (flag, ownerPKH) {
  return new Script().add(flagLE(flag)).add(Opcode.OP_DROP)
    .add(bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(pkhOf(ownerPKH))))
}

const F_HASHPREVOUTS = C.hashPrevoutsFromFront
function readField (asm, fn, name) {
  asm.fromAlt(); asm.clause(fn, 0, [name]); asm.swap(); asm.toAlt()
}
function finishBranch (asm) {
  while (asm.main.length) asm.drop()
  asm.fromAlt(); asm.drop()
  asm.raw(Opcode.OP_1, 0, ['true'])
}

function buildScript ({ beneficiary, sibling, requiredFlag }) {
  const bene = pkhOf(beneficiary)
  const outpoint = Buffer.isBuffer(sibling) ? sibling : outpoint36(sibling.prevTxId, sibling.outputIndex ?? sibling.vout)
  const flag = flagLE(requiredFlag)
  if (bene.length !== 20) throw new Error('beneficiary must be a 20-byte pkh')
  if (outpoint.length !== OUTPOINT_BYTES) throw new Error('sibling outpoint must be 36 bytes')
  const txidB = outpoint.slice(0, 32)

  const s = new Script()
  C.authenticate(s)                                        // preimage proven, on top
  s.add(Opcode.OP_TOALTSTACK)                              // park it
  const a = new StackAsm(s).given(['pubkey', 'sig', 'prefix', 'suffix', 'preOuts', 'outsBlob', 'lt4']).seedAlt(['preimage'])

  // 1. companion: the baked sibling outpoint is genuinely one of this tx's inputs
  a.pick('prefix'); a.data(outpoint, 'sibOutpoint'); a.cat('pfx1'); a.pick('suffix'); a.cat('prevoutsGuess')
  a.hash256('pvHash'); readField(a, F_HASHPREVOUTS, 'hashPrevouts'); a.equalVerify()

  // 2. backtrace: rebuild the sibling's SOURCE tx, hash it, require it == the baked txid.
  //    preOuts = inputCount ‖ inputs ‖ outputCount (folded together so no lone small-int
  //    push trips MINIMALDATA); the version is a constant and lt4 is the locktime.
  a.data(TX_VERSION, 'ver'); a.pick('preOuts'); a.cat('vi'); a.pick('outsBlob'); a.cat('vico')
  a.pick('lt4'); a.size('ltsz'); a.num(4, 'four'); a.equalVerify(); a.cat('sourceTx')
  a.hash256('sourceTxid'); a.data(txidB, 'txidB'); a.equalVerify()

  // 2b. its output 0 is the tagged coin — read the flag straight out and require the value
  a.pick('outsBlob'); a.splitAt(FLAG_OFFSET, 'skip', 'afterVal'); a.nip()   // drop the leading bytes
  a.splitAt(FLAG_BYTES, 'flag', 'rest'); a.drop()                           // keep flag, drop the tail
  a.data(flag, 'wantFlag'); a.equalVerify()

  // 3. the beneficiary authorises the release
  a.pick('pubkey'); a.hash160('pkh'); a.data(bene, 'bene'); a.equalVerify()
  a.pick('sig'); a.pick('pubkey'); a.checkSigVerify()

  finishBranch(a)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- source-tx fixture: a tagged coin at output 0, decomposed for the backtrace ----
function taggedCoinTx ({ flag, ownerPKH, satoshis = 2000, extraOutputs = 1 }) {
  const f = new bsv.Transaction()
  f.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.alloc(32, 5), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), satoshis + 5000)
  f.addOutput(new bsv.Transaction.Output({ script: taggedCoinScript(flag, ownerPKH), satoshis }))
  for (let i = 0; i < extraOutputs; i++) {
    f.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(Buffer.alloc(20, 6))), satoshis: 1000 }))
  }
  const raw = f.toBuffer()
  return { raw, tx: f, ...decomposeSource(raw) }
}

/** Split a raw tx into version ‖ [iblob] ‖ outCount ‖ [outsBlob] ‖ lt4 for the backtrace. */
function decomposeSource (raw) {
  const r = Buffer.isBuffer(raw) ? raw : buf(raw)
  const reader = new bsv.encoding.BufferReader(r)
  reader.read(4)                                           // version
  const inCount = reader.readVarintNum()
  const inStart = 4
  for (let i = 0; i < inCount; i++) {
    reader.read(32); reader.read(4)                        // outpoint
    const sl = reader.readVarintNum(); reader.read(sl)     // scriptSig
    reader.read(4)                                         // sequence
  }
  const outCountStart = reader.pos
  const outCount = reader.readVarintNum()
  const outsStart = reader.pos
  for (let i = 0; i < outCount; i++) {
    reader.read(8)                                         // value
    const sl = reader.readVarintNum(); reader.read(sl)     // script
  }
  const outsEnd = reader.pos
  const preOuts = r.slice(inStart, outsStart)              // inputCount ‖ inputs ‖ outputCount
  const outsBlob = r.slice(outsStart, outsEnd)
  const lt4 = r.slice(outsEnd)
  const rebuilt = Buffer.concat([r.slice(0, 4), preOuts, outsBlob, lt4])
  if (!rebuilt.equals(r)) throw new Error('source tx decomposition mismatch')
  return { preOuts, outsBlob, lt4, txidInternal: bsv.crypto.Hash.sha256sha256(r) }
}

const BENE = bsv.PrivateKey.fromRandom()

module.exports = {
  name: 'witness',
  describe: 'a release gated on a named sibling coin being co-spent while carrying a required flag',
  example: () => ({ beneficiary: BENE.toAddress().toString(), beneficiaryKey: BENE, requiredFlag: 1, sibling: { prevTxId: 'a'.repeat(64), outputIndex: 0 } }),

  FLAG_BYTES,
  buildScript,
  taggedCoinScript,
  taggedCoinTx,
  decomposeSource,
  outpoint36,
  flagLE,
  pkhOf,

  lock (tc) {
    if (!tc.beneficiary || !tc.sibling || tc.requiredFlag === undefined) {
      throw new Error('beneficiary, sibling and requiredFlag are required')
    }
    return buildScript(tc)
  },

  // the tagged coin this witness watches, added as a real co-input so hashPrevouts covers it.
  // The test builds the source fixture and passes it as tc._src (and its outpoint as tc.sibling).
  siblings (tc) {
    const src = tc._src
    if (!src) throw new Error('witness test must supply tc._src (from taggedCoinTx)')
    const out = src.tx.outputs[0]
    return [{ prevTxId: src.tx.id, outputIndex: 0, script: out.script, satoshis: out.satoshis }, ...(tc.extraSiblings || [])]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const priv = tc.beneficiaryKey || tc.key
    const pub = (tc.wrongPubkey || priv).publicKey.toBuffer()
    const src = tc._src
    if (!src) throw new Error('witness unlock needs tc._src (from taggedCoinTx)')

    // the sibling's real outpoint, and the surrounding outpoints of THIS tx
    const outpoint = Buffer.isBuffer(tc.sibling) ? tc.sibling : outpoint36(tc.sibling.prevTxId, tc.sibling.outputIndex ?? tc.sibling.vout)
    const vector = Buffer.concat(tx.inputs.map(i => outpoint36(i.prevTxId, i.outputIndex)))
    let prefix, suffix
    const at = indexOfAligned(vector, outpoint, OUTPOINT_BYTES)
    if (at >= 0) { prefix = vector.slice(0, at); suffix = vector.slice(at + OUTPOINT_BYTES) } else { prefix = vector.slice(0, OUTPOINT_BYTES); suffix = vector.slice(OUTPOINT_BYTES) }

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
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

function indexOfAligned (haystack, needle, stride) {
  for (let i = 0; i + needle.length <= haystack.length; i += stride) {
    if (haystack.slice(i, i + needle.length).equals(needle)) return i
  }
  return -1
}
