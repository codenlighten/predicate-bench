'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode

// JOURNAL — an append-only, hash-linked, authenticated data stream. Every state
// covenant so far (metered, ticker) carried a value and advanced it. This carries
// a HASH CHAIN: the successor must commit to `head = HASH256(oldHead ‖ record)`,
// so the log's head is a running commitment to its entire history. Reorder a past
// entry, delete one, or substitute one, and the head no longer matches — the chain
// is append-only and tamper-evident by construction, enforced on chain rather than
// by a server.
//
//   state (in scriptCode) = seq(4) ‖ head(32) ‖ publisher(20)
//
//   append  seq += 1 ; head = HASH256(head ‖ recordHash) ; recreate       (publisher signs)
//   close   sweep the remaining value to the publisher and stop           (publisher signs)
//
// The record itself lives OFF chain; only its hash enters the chain, so the ledger
// enforces the structure and provenance of a stream whose payload stays private —
// the chain guards the envelope, authorised parties read the contents. The publisher
// is fixed in the state and authorises every transition; the close branch is the
// exit a fee-draining self-recreating covenant must have (pitfall 18).

const SEQ_BYTES = 4
const HASH_BYTES = 32
const PUB_BYTES = 20
const STATE_BYTES = SEQ_BYTES + HASH_BYTES + PUB_BYTES   // 56, push-op 0x38
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1                       // varint ‖ push-op
const DUST = 2000
const DEFAULT_FEE = 250
const P2PKH_PRE = Buffer.from('1976a914', 'hex')          // varint(25) ‖ OP_DUP OP_HASH160 <20>
const P2PKH_POST = Buffer.from('88ac', 'hex')             // OP_EQUALVERIFY OP_CHECKSIG

function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function seqBuf (v) { const b = Buffer.alloc(SEQ_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function state (seq, head, publisher) {
  return Buffer.concat([seqBuf(seq), head, hash160Of(publisher)])
}
function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
/** the head after appending `recordHash` onto `head`. */
function chain (head, recordHash) {
  return bsv.crypto.Hash.sha256sha256(Buffer.concat([buf(head), buf(recordHash)]))
}
const GENESIS_HEAD = Buffer.alloc(HASH_BYTES)             // an empty log

// --- APPEND: seq+1, head = HASH256(head ‖ recordHash), recreate --------------
function appendBody (asm, { fee }) {
  // read my own state out of scriptCode
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(SEQ_BYTES, 'seq4', 'r2')
  asm.splitAt(HASH_BYTES, 'oldHead', 'r3')
  asm.splitAt(PUB_BYTES, 'publisher', 'tail')

  // the publisher, fixed in state, must sign this append
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('publisher'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()

  // newSeq = seq + 1
  asm.pick('seq4'); asm.data(Buffer.from([0]), 'zs'); asm.cat('seqP'); asm.bin2num('seqN')
  asm.raw(Opcode.OP_1ADD, 1, ['seqN1']); asm.num2bin(SEQ_BYTES, 'newSeq4')
  // newHead = HASH256(oldHead ‖ recordHash)
  asm.pick('oldHead'); asm.pick('recordHash'); asm.cat('hlink'); asm.hash256('newHead')
  // newState = newSeq ‖ newHead ‖ publisher   (publisher carried unchanged)
  asm.pick('newSeq4'); asm.pick('newHead'); asm.cat('ns1'); asm.pick('publisher'); asm.cat('newState')
  // newChunk = header ‖ newState ‖ tail ; the successor recreates me with it
  asm.pick('header'); asm.pick('newState'); asm.cat('hn'); asm.pick('tail'); asm.cat('newChunk')

  // output 0: (input value − fee) ‖ newChunk, bound to hashOutputs
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('nextOutput')
  asm.pick('nextOutput'); asm.hash256('oh')
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['hoField'])
  asm.nip(); asm.equalVerify()
}

// --- CLOSE: the publisher sweeps the remainder and stops ---------------------
function closeBody (asm, { fee }) {
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(SEQ_BYTES, 'seq4', 'r2')
  asm.splitAt(HASH_BYTES, 'oldHead', 'r3')
  asm.splitAt(PUB_BYTES, 'publisher', 'tail')

  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('publisher'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()

  // pay the publisher, whose PKH is in the state: build its P2PKH output at runtime
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.data(P2PKH_PRE, 'pre'); asm.pick('publisher'); asm.cat('pk1'); asm.data(P2PKH_POST, 'post'); asm.cat('pubChunk')
  asm.cat('closeOutput')                                   // newValue8 ‖ pubChunk (value first)
  asm.pick('closeOutput'); asm.hash256('oh')
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['hoField'])
  asm.nip(); asm.equalVerify()
}

function buildScript ({ seq = 0, head = GENESIS_HEAD, publisher, fee = DEFAULT_FEE }) {
  const p = Buffer.isBuffer(publisher) ? publisher
    : /^[0-9a-f]{40}$/i.test(publisher) ? Buffer.from(publisher, 'hex')   // a hex pkh (from the ledger)
      : hash160Of(publisher)                                             // an address / pubkey
  const h = Buffer.isBuffer(head) ? head : Buffer.from(head, 'hex')
  if (p.length !== PUB_BYTES) throw new Error('publisher must be a 20-byte pkh')
  if (h.length !== HASH_BYTES) throw new Error('head must be 32 bytes')

  const s = new Script()
  s.add(state(seq, h, p)).add(Opcode.OP_DROP)
  C.authenticateThenBranch(s)                              // one auth, SIGHASH_ALL, flag → OP_IF

  const ap = new StackAsm(s); ap.main = ['pubkey', 'sig', 'recordHash', 'preimage']
  appendBody(ap, { fee })
  while (ap.main.length) ap.drop()
  ap.raw(Opcode.OP_1, 0, ['ok'])
  const apDepth = ap.main.length

  s.add(Opcode.OP_ELSE)
  const cl = new StackAsm(s); cl.main = ['pubkey', 'sig', 'preimage']
  closeBody(cl, { fee })
  while (cl.main.length) cl.drop()
  cl.raw(Opcode.OP_1, 0, ['ok'])
  if (cl.main.length !== apDepth) throw new Error(`journal: branches leave different depths (${apDepth} vs ${cl.main.length})`)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

module.exports = {
  name: 'journal',
  describe: 'an append-only hash-linked authenticated log; the head commits to the whole history',
  example: () => ({ seq: 0, head: GENESIS_HEAD, publisher: Buffer.alloc(20, 2), fee: DEFAULT_FEE, recordHash: Buffer.alloc(32, 9), branch: 'append' }),

  SEQ_BYTES,
  HASH_BYTES,
  DUST,
  DEFAULT_FEE,
  GENESIS_HEAD,
  buildScript,
  state,
  chain,
  hash160Of,
  seqBuf,

  lock (tc) {
    if (!tc.publisher) throw new Error('publisher is required')
    return buildScript(tc)
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const p = buf(tc.publisher)
    if ((tc.branch || 'append') === 'close') {
      if (tc.actualOutputs) return tc.actualOutputs({ fee, p })
      return [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(p), tc.satoshis - fee)]
    }
    const newHead = chain(tc.head, tc.recordHash)
    const script = buildScript({ seq: tc.seq + 1, head: newHead, publisher: p, fee })
    if (tc.actualOutputs) return tc.actualOutputs({ fee, script, newHead })
    return [new bsv.Transaction.Output({ script, satoshis: tc.satoshis - fee })]
  },

  continuation (tc) {
    if ((tc.branch || 'append') === 'close') return null
    const newHead = chain(tc.head, tc.recordHash)
    const params = { seq: tc.seq + 1, head: newHead.toString("hex"), publisher: buf(tc.publisher).toString("hex"), fee: tc.fee ?? DEFAULT_FEE }
    return { script: buildScript(params), params }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const priv = tc.publisherKey || tc.key
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const pub = priv.publicKey.toBuffer()
      if ((tc.branch || 'append') === 'close') {
        return new Script().add(pub).add(sig).add(Opcode.OP_0).add(preimage)
      }
      const recordHash = buf(tc.presentRecordHash || tc.recordHash)
      return new Script().add(pub).add(sig).add(recordHash).add(Opcode.OP_1).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
