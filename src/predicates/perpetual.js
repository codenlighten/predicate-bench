'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Opcode = bsv.Opcode

// A covenant that forces every spend to recreate itself. The coin never leaves
// the lock; it moves forward through identical UTXOs, shrinking by the fee each
// hop. nChain WP1605 — originally taken from the library's audited PELS, now
// rebuilt on the shared primitives so it benefits from the lean OP_PUSH_TX core
// like everything else here.
//
// The interesting problem is circular: to commit to an output paying back into
// THIS script, the script would have to contain its own hash. It sidesteps that
// by reading itself out of the authenticated preimage. Given the BIP-143 layout
//
//   version(4) hashPrevouts(32) hashSequence(32) outpoint(36)   = 104
//   scriptlen(varint) || scriptCode
//   value(8) nSequence(4) hashOutputs(32) nLockTime(4) sighash(4) = 52
//
// the slice preimage[104 : len-52] is byte-for-byte the `scriptlen||script` half
// of a TxOut. So the required next output is just
//
//   <inputValue - fee as 8-byte LE> || preimage[104 : len-52]
//
// and the varint arrives free. The script never learns its own length or hash.
module.exports = {
  name: 'perpetual',
  describe: 'every spend must recreate this exact script, paying itself minus the hop fee',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ hopFee: 150 }),

  lock ({ hopFee }) {
    if (!Number.isInteger(hopFee) || hopFee <= 0) {
      throw new Error('hopFee must be a positive integer')
    }
    // authenticate() does the OP_DUP itself. Adding one here too leaves a
    // second copy of the preimage under the result, which passes consensus and
    // is refused at the broadcast for a dirty stack. That mistake cost 2000 sat.
    const s = new bsv.Script()
    C.authenticate(s)                 // lean OP_PUSH_TX; leaves [preimage]
    C.requireSighashAll(s)            // or hashOutputs binds the wrong thing

    C.selfChunk(s)                    // [preimage, scriptlen||script]
    s.add(Opcode.OP_OVER)             // [preimage, chunk, preimage]
    C.newValueLE(s, hopFee)           // [preimage, chunk, newValue8]
    s.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)   // nextOutput = value8 || chunk
    return C.requireOutputIs(s)
  },

  /**
   * The single output every spend must create: the same script, carrying the
   * input value less one hop fee.
   *
   * There is exactly one, and no change output is possible — hashOutputs
   * commits to the entire output set, so a second output changes the hash and
   * nothing spends. Any extra input a spender adds is therefore donated
   * wholesale to the miner.
   */
  outputs ({ hopFee, satoshis, lockingScript, actualScript, actualAmount, extraOutput }) {
    const outs = [new bsv.Transaction.Output({
      script: actualScript || lockingScript,
      satoshis: actualAmount ?? (satoshis - hopFee)
    })]
    if (extraOutput) {
      outs.push(helpers.p2pkhOutput(bsv.PrivateKey.fromRandom().toAddress(), extraOutput))
    }
    return outs
  },

  /** This covenant recreates itself byte for byte. */
  continuation ({ lockingScript, hopFee }) {
    return { script: lockingScript, params: { hopFee } }
  },

  // nLockTime is unconstrained here, so it is free to serve as the grind nonce.
  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType }) {
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
      if (PushTx.sFromPreimage(preimage)) return new bsv.Script().add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
