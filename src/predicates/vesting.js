'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const covsteps = require('../covsteps')
const Script = bsv.Script
const Opcode = bsv.Opcode

// VESTING — value released CONTINUOUSLY over time. The bench can lock coins until
// a floor ([timelock]) and release a fixed set at once ([covenant]); nothing
// releases them *gradually*. `vesting` streams a grant to a beneficiary linearly
// between two times: at any moment they may withdraw everything vested so far, and
// the covenant recreates itself holding exactly the UNVESTED remainder.
//
//   unvested(T) = total · clamp(end − T, 0, end − start) / (end − start)
//
// The beneficiary withdraws by spending at time T; the covenant computes
// unvested(T) itself, keeps that much in a recreated copy of itself, and pays the
// rest out. Since unvested only falls, each withdrawal extracts exactly what
// vested since the last one — a stream, settled whenever the beneficiary likes.
//
// Why it is sound. "It is at least time T" is not the spender's word: the withdraw
// reads nLockTime from the authenticated preimage AND requires a non-final
// sequence, so the transaction is unminable before T (the [timelock] rule). A
// beneficiary cannot claim future vesting early — a preimage with a future
// nLockTime only mines in the future — and setting nLockTime low merely vests
// less. The amounts are computed by the script, never supplied, so no larger
// withdrawal can be smuggled past the output binding.
//
// Two branches, partitioned by the schedule itself:
//   OP_1  withdraw  unvested ≥ DUST: recreate self@unvested, pay beneficiary the rest
//   OP_0  finish    unvested < DUST: the grant is essentially complete; pay it all out
//
// The finish branch is the exit ([pitfall 18]): a self-recreating covenant whose
// retained value falls to dust must have somewhere to go, or the tail strands.
// This grant is irrevocable — there is no grantor clawback; composing one is the
// obvious variant.

const DUST = 546
const DEFAULT_FEE = 300

/** unvested(T), the same integer arithmetic the script runs (in src/covsteps.js). */
function unvestedAt (total, start, end, T) {
  const dur = end - start
  const rem = Math.min(Math.max(end - T, 0), dur)
  return Math.floor((total * rem) / dur)
}

// The two branch bodies live in src/covsteps.js (vestingWithdraw / vestingFinish),
// shared with the compiler so the spec and the predicate cannot drift.
function buildScript ({ total, start, end, beneficiaryPKH, fee = DEFAULT_FEE }) {
  const b = Buffer.isBuffer(beneficiaryPKH) ? beneficiaryPKH : Buffer.from(beneficiaryPKH, 'hex')
  if (b.length !== 20) throw new Error('beneficiaryPKH must be 20 bytes')
  if (!(end > start && start >= 0)) throw new Error('need end > start >= 0')
  if (!Number.isInteger(total) || total <= 0) throw new Error('total must be a positive integer')

  const s = new Script()
  C.authenticateThenBranch(s)                   // one auth, SIGHASH_ALL, flag → OP_IF

  const wd = new StackAsm(s); wd.main = ['bsig', 'bpub', 'preimage']
  covsteps.vestingWithdraw(wd, { benPKH: b, total, start, end, fee, dust: DUST })
  while (wd.main.length) wd.drop()
  wd.raw(Opcode.OP_1, 0, ['ok'])
  const wdDepth = wd.main.length

  s.add(Opcode.OP_ELSE)
  const fn = new StackAsm(s); fn.main = ['bsig', 'bpub', 'preimage']
  covsteps.vestingFinish(fn, { benPKH: b, total, start, end, fee, dust: DUST })
  while (fn.main.length) fn.drop()
  fn.raw(Opcode.OP_1, 0, ['ok'])
  if (fn.main.length !== wdDepth) {
    throw new Error(`vesting: branches leave different depths (withdraw ${wdDepth} vs finish ${fn.main.length})`)
  }
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- harness plumbing -------------------------------------------------------

module.exports = {
  name: 'vesting',
  describe: 'a grant that vests linearly over time; the beneficiary withdraws the vested part, the rest recreates',
  example: () => ({
    total: 10000, start: 1750000000, end: 1760000000,
    beneficiaryPKH: Buffer.alloc(20, 3), fee: DEFAULT_FEE,
    atTime: 1755000000, branch: 'withdraw'
  }),

  DUST,
  DEFAULT_FEE,
  buildScript,
  unvestedAt,

  lock (tc) {
    if (!tc.beneficiaryPKH) throw new Error('beneficiaryPKH is required')
    return buildScript(tc)
  },

  // withdraws set nLockTime = atTime and must be non-final so the lock bites
  unlockDefaults: { sequenceNumber: 0xfffffffe },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const B = tc.satoshis
    const u = unvestedAt(tc.total, tc.start, tc.end, tc.atTime)
    const b = Buffer.isBuffer(tc.beneficiaryPKH) ? tc.beneficiaryPKH : Buffer.from(tc.beneficiaryPKH, 'hex')
    const benAddr = bsv.Address.fromPublicKeyHash(b)
    if (tc.actualOutputs) return tc.actualOutputs({ B, u, fee, benAddr })
    if ((tc.branch || 'withdraw') === 'finish') {
      return [helpers.p2pkhOutput(benAddr, B - fee)]
    }
    return [
      new bsv.Transaction.Output({ script: buildScript(tc), satoshis: u }),
      helpers.p2pkhOutput(benAddr, B - u - fee)
    ]
  },

  continuation (tc) {
    if ((tc.branch || 'withdraw') === 'finish') return null
    const u = unvestedAt(tc.total, tc.start, tc.end, tc.atTime)
    const params = { total: tc.total, start: tc.start, end: tc.end, beneficiaryPKH: tc.beneficiaryPKH, fee: tc.fee ?? DEFAULT_FEE }
    return { script: buildScript(params), params, satoshis: u }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const bpriv = tc.beneficiaryKey || tc.key
    const preimage = C.grindPreimage(tx, inputIndex, lockingScript, satoshis, tc.atTime, type)
    const bsig = bsv.Transaction.Sighash.sign(
      tx, bpriv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
    const flag = (tc.branch || 'withdraw') === 'finish' ? Opcode.OP_0 : Opcode.OP_1
    return new Script().add(bsig).add(bpriv.publicKey.toBuffer()).add(flag).add(preimage)
  }
}
