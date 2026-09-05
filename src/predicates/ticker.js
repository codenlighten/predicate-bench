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

// TICKER — oracle-driven STATE. Every oracle covenant before this consumed an
// attestation and then terminated. `ticker` consumes one and RECREATES itself,
// carrying the attested value forward in its own scriptCode — an on-chain mirror
// of a signed feed that anyone can advance with a fresh attestation, and that no
// single spend can revert.
//
// It composes two mechanisms already in the bench with one that only appears once
// state and an oracle meet:
//   - the Rabin verifier of [oracle] reads the external value;
//   - the self-recreation of [metered] carries state in scriptCode and rebuilds
//     itself with one field changed;
//   - a MONOTONICITY guard — the genuinely new part.
//
// Why monotonicity is not optional. An oracle attestation is public, reusable
// bytes. A stateful oracle covenant that accepted "any valid attestation" could be
// fed an OLD one to roll its state backwards — yesterday's price replayed over
// today's. So each attestation carries a ROUND, the covenant records the current
// round in its own state, and an update is refused unless the new round strictly
// exceeds it. Freshness, enforced by the script against its own past.
//
//   state (in scriptCode) = round(4) ‖ price(4)
//   oracle message        = TAG(8) ‖ round(4) ‖ price(4)
//
// The new round‖price are lifted straight out of the SIGNED message, so the
// spender cannot choose them (bound by Rabin) and cannot replay an old one (round
// must rise). Two branches:
//
//   OP_1  update  a fresher attestation; recreate carrying the new round‖price
//   OP_0  redeem  the funder's signature; sweep the remainder and terminate
//
// The redeem branch is the exit a self-recreating covenant must have: each update
// pays a fee out of the coin, so without an off-switch the remainder would strand
// at dust. The funder can shut the ticker down and recover what is left.

const KEY = require('./oracle-key.json')
const ORACLE_N = BigInt(KEY.n)

const TAG_BYTES = 8
const ROUND_BYTES = 4
const PRICE_BYTES = 4
const STATE_BYTES = ROUND_BYTES + PRICE_BYTES        // 8, pushed as OP_PUSHBYTES_8
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1                  // varint(3) ‖ push-op(1)
const DUST = 2000
const DEFAULT_FEE = 300

function feedTag (s) {
  const b = Buffer.alloc(TAG_BYTES)
  Buffer.from(s, 'latin1').copy(b, 0, 0, TAG_BYTES)
  return b
}
function stateBuf (round, price) {
  const b = Buffer.alloc(STATE_BYTES)
  b.writeUInt32LE(round >>> 0, 0)
  b.writeUInt32LE(price >>> 0, ROUND_BYTES)
  return b
}
function message (tag, round, price) {
  return Buffer.concat([feedTag(tag), stateBuf(round, price)])   // TAG ‖ round ‖ price
}
function padBytes (p) { return Buffer.from([p & 0xff, (p >> 8) & 0xff]) }
function funderChunk (pkh) {
  return C.txOutChunk(bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(pkh)))
}

// --- UPDATE branch: a fresher attestation recreates the ticker ---------------
function updateBody (asm, { nBytes, tag, fee }) {
  // verify the attestation over TAG ‖ round ‖ price (preimage stays on top)
  const scratch = rabinScript.verify(asm, { nBytes, sig: 'rsig', msg: 'msg', pad: 'pad2' })
  asm.roll(scratch); asm.drop()

  // read my own scriptCode; isolate head ‖ oldState ‖ logicTail
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(HEAD_BYTES, 'head', 'rest'); asm.splitAt(STATE_BYTES, 'oldState', 'logicTail')

  // my current round = oldState[0:4]
  asm.roll('oldState'); asm.splitAt(ROUND_BYTES, 'oldRound', 'oldPrice'); asm.drop()
  asm.data(Buffer.from([0]), 'zo'); asm.cat('orp'); asm.bin2num('oldRoundN')

  // the attested new state = msg[8:16]; the tag must be mine
  asm.pick('msg', 'mc'); asm.splitAt(TAG_BYTES, 'tag', 'newState')
  asm.roll('tag'); asm.data(feedTag(tag), 'TAG'); asm.equalVerify()
  asm.pick('newState', 'nsc'); asm.splitAt(ROUND_BYTES, 'newRound', 'newPrice'); asm.drop()
  asm.data(Buffer.from([0]), 'zn'); asm.cat('nrp'); asm.bin2num('newRoundN')

  // FRESHNESS: the new round must strictly exceed mine, or this is a replay
  asm.roll('oldRoundN'); asm.gtVerify()               // newRoundN > oldRoundN

  // recreate: newChunk = head ‖ newState ‖ logicTail
  asm.roll('head'); asm.swap(); asm.cat('hs')         // head ‖ newState
  asm.roll('logicTail'); asm.cat('newChunk')          // ‖ logicTail

  // the successor output: (input value − fee) ‖ newChunk, bound by hashOutputs
  asm.pick('preimage', 'pOver'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.roll('newChunk'); asm.cat('nextOutput')          // newValue8 ‖ newChunk (value first)
  asm.clause(C.requireOutputIs, 2, ['isOut']); asm.verify()
}

// --- REDEEM branch: the funder sweeps the remainder --------------------------
function redeemBody (asm, { funderPKH, fee }) {
  asm.pick('fpub'); asm.hash160('fh'); asm.data(funderPKH, 'FPKH'); asm.equalVerify()
  asm.pick('fsig'); asm.pick('fpub'); asm.checkSigVerify()
  asm.pick('preimage', 'pOver'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.data(funderChunk(funderPKH), 'fchunk'); asm.cat('redeemOutput')
  asm.clause(C.requireOutputIs, 2, ['isOut']); asm.verify()
}

function buildScript ({ round = 0, price = 0, tag, funderPKH, fee = DEFAULT_FEE, oracleN }) {
  const f = Buffer.isBuffer(funderPKH) ? funderPKH : Buffer.from(funderPKH, 'hex')
  if (f.length !== 20) throw new Error('funderPKH must be 20 bytes')
  const nBytes = R.toScriptNum(oracleN || ORACLE_N)

  const s = new Script()
  s.add(stateBuf(round, price)).add(Opcode.OP_DROP)   // state: round ‖ price
  C.authenticateThenBranch(s)                          // one preimage auth, flag → OP_IF

  const up = new StackAsm(s); up.main = ['rsig', 'pad2', 'msg', 'preimage']
  updateBody(up, { nBytes, tag, fee })
  while (up.main.length) up.drop()
  up.raw(Opcode.OP_1, 0, ['ok'])
  const updateDepth = up.main.length

  s.add(Opcode.OP_ELSE)
  const rd = new StackAsm(s); rd.main = ['fsig', 'fpub', 'preimage']
  redeemBody(rd, { funderPKH: f, fee })
  while (rd.main.length) rd.drop()
  rd.raw(Opcode.OP_1, 0, ['ok'])
  if (rd.main.length !== updateDepth) {
    throw new Error(`ticker: branches leave different depths (update ${updateDepth} vs redeem ${rd.main.length})`)
  }
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- scenarios / harness ----------------------------------------------------

const ORACLE_KEY = { p: BigInt(KEY.p), q: BigInt(KEY.q), n: ORACLE_N }
function attest (tag, round, price) {
  const msg = message(tag, round, price)
  const { sig, padding } = R.sign(msg, ORACLE_KEY)
  return { msg, sig, pad2: padBytes(padding) }
}

module.exports = {
  name: 'ticker',
  describe: 'self-recreating oracle mirror: advances only on a fresher (higher-round) signed value',
  example: () => ({
    round: 5, price: 6000, tag: 'BSVUSD', funderPKH: Buffer.alloc(20, 2),
    fee: DEFAULT_FEE, newRound: 6, newPrice: 6300, branch: 'update'
  }),

  TAG_BYTES,
  STATE_BYTES,
  DUST,
  DEFAULT_FEE,
  ORACLE_N,
  buildScript,
  message,
  attest,
  stateBuf,

  lock (tc) {
    if (!tc.funderPKH) throw new Error('funderPKH is required')
    return buildScript(tc)
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    if ((tc.branch || 'update') === 'redeem') {
      const f = Buffer.isBuffer(tc.funderPKH) ? tc.funderPKH : Buffer.from(tc.funderPKH, 'hex')
      if (tc.actualOutputs) return tc.actualOutputs({ fee })
      return [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(f), tc.satoshis - fee)]
    }
    // update: the recreated ticker, carrying the presented new round/price
    const nr = tc.presentRound ?? tc.newRound
    const np = tc.presentPrice ?? tc.newPrice
    const script = buildScript({ round: nr, price: np, tag: tc.tag, funderPKH: tc.funderPKH, fee })
    if (tc.actualOutputs) return tc.actualOutputs({ fee, script })
    return [new bsv.Transaction.Output({ script, satoshis: tc.satoshis - fee })]
  },

  /** The successor UTXO an update leaves behind (nothing, for a redeem). */
  continuation (tc) {
    if ((tc.branch || 'update') === 'redeem') return null
    const params = { round: tc.newRound, price: tc.newPrice, tag: tc.tag, funderPKH: tc.funderPKH, fee: tc.fee ?? DEFAULT_FEE }
    return { script: buildScript(params), params }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)

    if ((tc.branch || 'update') === 'redeem') {
      const fpriv = tc.funderKey || tc.key
      for (let t = 0; t < 50000; t++) {
        tx.nLockTime = t
        const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
        if (!PushTx.sFromPreimage(preimage)) continue
        const fsig = bsv.Transaction.Sighash.sign(
          tx, fpriv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
        return new Script().add(fsig).add(fpriv.publicKey.toBuffer()).add(Opcode.OP_0).add(preimage)
      }
      throw new Error('preimage grind failed after 50000 tries')
    }

    // update: attest the new round/price; forgeRound/forgePresent break it on purpose
    const a = attest(tc.attestTag || tc.tag, tc.newRound, tc.newPrice)
    const msg = tc.presentRound !== undefined || tc.presentPrice !== undefined
      ? message(tc.attestTag || tc.tag, tc.presentRound ?? tc.newRound, tc.presentPrice ?? tc.newPrice)
      : a.msg
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      return new Script().add(a.sig).add(a.pad2).add(msg).add(Opcode.OP_1).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
