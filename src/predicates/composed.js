'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')

// Every clause proven separately, now ANDed on a single authenticated preimage.
//
// The reason to build this rather than assume it: the interesting failures in a
// composition are not in either clause, they are in the interaction. Each clause
// must leave the stack exactly as it found it, or a clause that passes alone
// starts corrupting the one after it — and the symptom is a script that still
// verifies, just not for the reason you think.
// Fixed addresses so a documented byte count is reproducible rather than
// dependent on whichever key happened to be generated.
const EXAMPLE_ADDRESS = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'
const EXAMPLE_ADDRESS_2 = '18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if'

module.exports = {
  name: 'composed',
  describe: 'outputs AND locktime AND non-final sequence, on one authenticated preimage',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ payTo: EXAMPLE_ADDRESS, payAmount: 900, notBefore: 964000 }),

  unlockDefaults: { sequenceNumber: 0xfffffffe },

  // `order` exists to be varied in tests. If a clause ever consumed more stack
  // than it restored, permuting the order would break the script — so a suite
  // that passes under several orders is evidence the invariant actually holds,
  // not just that one hand-checked arrangement happens to work.
  lock ({ payTo, payAmount, notBefore, omit = [], order = ['sighash', 'sequence', 'locktime', 'outputs'] }) {
    const clause = {
      sighash: () => C.requireSighashAll(s),
      sequence: () => C.requireSequenceNonFinal(s),
      locktime: () => C.requireLockTimeAtLeast(s, notBefore),
      outputs: () => C.requireOutputs(s, C.hashOutputs(this.outputs({ payTo, payAmount })))
    }
    const s = new bsv.Script()
    C.authenticate(s)
    for (const name of order) {
      if (omit.includes(name)) continue
      if (!clause[name]) throw new Error(`unknown clause: ${name}`)
      clause[name]()
    }
    return C.finish(s)
  },

  outputs ({ payTo, payAmount, actualPayTo, actualPayAmount }) {
    return [C.p2pkhOutput(actualPayTo ?? payTo, actualPayAmount ?? payAmount)]
  },

  // nLockTime is both the grind nonce and a constrained field, so grind up from
  // the floor rather than from zero — starting at zero would search a range the
  // locktime clause rejects and either fail or waste the whole budget.
  unlock ({ tx, inputIndex, lockingScript, satoshis, notBefore, sighashType, grindFrom }) {
    const base = grindFrom ?? notBefore
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = base + t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
      if (PushTx.sFromPreimage(preimage)) return new bsv.Script().add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
