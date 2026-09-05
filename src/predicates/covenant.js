'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const { leanCore } = require('../pushtx')
const Script = bsv.Script
const Opcode = bsv.Opcode

// Coins that can only move to a destination fixed when they were locked.
//
// The predicate is an equality on hashOutputs, which is the one output
// constraint a preimage can express: it is a double-SHA256 over every output's
// amount and script, so a script cannot read a single amount out of it, only
// compare the whole commitment. Bound this way the spender chooses nothing
// about where the money goes — not the address, not the amount, not the number
// of outputs. Getting a satoshi wrong changes the hash and the spend fails.
// Fixed addresses so a documented byte count is reproducible rather than
// dependent on whichever key happened to be generated.
const EXAMPLE_ADDRESS = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'
const EXAMPLE_ADDRESS_2 = '18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if'

module.exports = {
  name: 'covenant',
  describe: 'coins can only be spent to the exact output set committed at lock time',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ payTo: EXAMPLE_ADDRESS, payAmount: 900 }),

  /**
   * The whole construction rests on OP_PUSH_TX: pushTxCore makes the
   * interpreter compute this transaction's sighash itself and check it with
   * OP_CHECKSIG, so the preimage left on the stack provably belongs to the
   * spend in progress. Without that the hashOutputs comparison is theatre —
   * a spender would just push a preimage describing outputs they never create.
   */
  lock ({ payTo, payAmount }) {
    const expected = PushTx.hashOutputs(this.outputs({ payTo, payAmount }))

    const s = new Script().add(Opcode.OP_DUP)
    leanCore(s)               // authenticate the preimage against this spend
    s.add(Opcode.OP_VERIFY)   // stack: [preimage]

    s.add(Opcode.OP_DUP)
    PushTx.extractHashOutputs(s)                       // last 40, first 32
    s.add(Buffer.from(expected)).add(Opcode.OP_EQUALVERIFY)

    return s.add(Opcode.OP_DROP).add(Opcode.OP_1)
  },

  /**
   * The exact outputs a valid spend must create. The harness and the on-chain
   * path both build the spending transaction from this rather than paying
   * change wherever they like — a covenant that dictates its outputs cannot
   * also let the caller choose them.
   *
   * The fee is therefore whatever the input exceeds this by, not something the
   * spender tunes afterwards: changing an amount to adjust the fee changes
   * hashOutputs and the coin stops being spendable at all.
   */
  outputs ({ payTo, payAmount, actualPayTo, actualPayAmount }) {
    // lock() calls this with the committed pair only. The tx builder calls it
    // with the full context, so a test can direct the spend somewhere the
    // commitment does not cover and watch the script refuse it.
    return [helpers.p2pkhOutput(actualPayTo ?? payTo, actualPayAmount ?? payAmount)]
  },

  unlock ({ tx, inputIndex, lockingScript, satoshis }) {
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis)
      if (PushTx.sFromPreimage(preimage)) return new Script().add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
