'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const covsteps = require('../covsteps')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A covenant that carries STATE, and can only be moved a fixed number of times.
//
// The UTXO's own locking script begins with a 4-byte counter. Every spend must
// recreate the covenant with that counter incremented by exactly one, and the
// script refuses to move at all once it reaches `maxHops`. The result is a coin
// whose transfer count is a fact about the chain rather than a number tracked
// somewhere alongside it — unforgeable, and readable by anyone with the UTXO.
//
// The trick is that a covenant can already read its own bytes out of the
// authenticated preimage's scriptCode. Once it can read itself, it can also
// rebuild itself with one field changed, and demand that the result is what the
// spend pays to. Self-reference plus a single mutation is a state machine.
//
//   script = <4-byte counter> OP_DROP <fixed logic>
//
// The counter is pushed at fixed width and immediately dropped. It never
// participates in execution; it is there to occupy bytes the covenant can find
// at a known offset. Fixed width is what keeps every subsequent offset — and
// the script's own length, and therefore its varint — identical across hops.
//
// There are two branches, chosen by a flag in the unlocking script:
//
//   OP_1  hop     counter < maxHops; recreate with counter+1
//   OP_0  redeem  counter >= maxHops; pay out to a fixed address
//
// The redemption branch is not decoration. A self-recreating covenant with no
// exit strands its remainder permanently — the coin runs out of hops with value
// still in it and nothing can ever move it again. That is a defect, not a
// property, and one branch fixes it: the meter expires INTO a settlement rather
// than into a burn. What the design buys is a bearer instrument with a provable
// transfer limit that then settles to a known party.
const COUNTER_BYTES = 4

// preimage[104 : len-52] is `scriptlen||script`. For scripts of 253..65535
// bytes that varint is 3 bytes, so the counter sits at offset 4 (3 varint + 1
// push opcode) and the remainder resumes at 8.
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1

// Shared covenant primitives — one implementation, in src/clauses.js.
const selfChunk = C.selfChunk
const newValueLE = C.newValueLE
const requireOutputIs = C.requireOutputIs
const txOutChunk = C.txOutChunk

function counterBuf (value) {
  const b = Buffer.alloc(COUNTER_BYTES)
  b.writeUInt32LE(value)
  return b
}





function buildScript ({ counter = 0, maxHops, hopFee, redeemTo }) {
  // Params round-trip through JSON in the deployment ledger, so an Address
  // comes back as a string. Normalize rather than let it reach the script
  // builder, which would throw somewhere far from the cause.
  const settle = typeof redeemTo === 'string' ? bsv.Address.fromString(redeemTo) : redeemTo
  const s = new Script()

  // The state, as data. Pushed and dropped: bytes to be read, not executed.
  // Outside the branches, so its offset never depends on which one runs.
  s.add(counterBuf(counter)).add(Opcode.OP_DROP)

  // One OP_PUSH_TX preamble above the split, not one per branch.
  C.authenticateThenBranch(s)

  // Both branch bodies live in src/covsteps.js, shared with the compiler so the
  // spec and the predicate cannot drift. hop reads the counter keeping the rest
  // for recreation, guards below the limit, and increments; redeem reads the
  // counter discarding the rest, guards at/above the limit (the exact complement,
  // so the two partition every counter value), and settles to a fixed address.
  const HB = { headBytes: HEAD_BYTES, counterBytes: COUNTER_BYTES }

  covsteps.meteredReadCounterKeep(s, HB)             // ---- hop ----
  covsteps.meteredGuardBelow(s, { max: maxHops })
  covsteps.meteredIncrementRecreate(s, { counterBytes: COUNTER_BYTES, fee: hopFee })

  s.add(Opcode.OP_ELSE)

  covsteps.meteredReadCounterDrop(s, HB)             // ---- redeem ----
  covsteps.meteredGuardAtLeast(s, { max: maxHops })
  covsteps.meteredPayFixed(s, { address: settle, fee: hopFee })

  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  // The 3-byte varint assumption is baked into HEAD_BYTES. Outside this range
  // the counter is not where the script looks, and it would rebuild garbage
  // that hashes to nothing — an unspendable coin, silently.
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// Fixed addresses so a documented byte count is reproducible rather than
// dependent on whichever key happened to be generated.
const EXAMPLE_ADDRESS = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'
const EXAMPLE_ADDRESS_2 = '18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if'

module.exports = {
  name: 'metered',
  describe: 'self-recreating covenant carrying a hop counter; refuses to move past maxHops',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ counter: 0, maxHops: 2, hopFee: 250, redeemTo: EXAMPLE_ADDRESS }),

  buildScript,
  counterBuf,

  lock ({ counter = 0, maxHops, hopFee, redeemTo }) {
    if (!Number.isInteger(maxHops) || maxHops <= 0) throw new Error('maxHops must be a positive integer')
    if (!Number.isInteger(hopFee) || hopFee <= 0) throw new Error('hopFee must be a positive integer')
    if (!redeemTo) throw new Error('redeemTo is required: without it the remainder strands at maxHops')
    return buildScript({ counter, maxHops, hopFee, redeemTo })
  },

  outputs ({ counter = 0, maxHops, hopFee, redeemTo, satoshis, branch = 'hop',
             actualCounter, actualScript, actualAmount }) {
    const script = actualScript || (branch === 'redeem'
      ? bsv.Script.buildPublicKeyHashOut(
          typeof redeemTo === 'string' ? bsv.Address.fromString(redeemTo) : redeemTo)
      : buildScript({ counter: actualCounter ?? (counter + 1), maxHops, hopFee, redeemTo }))
    return [new bsv.Transaction.Output({
      script,
      satoshis: actualAmount ?? (satoshis - hopFee)
    })]
  },

  /**
   * The UTXO this spend leaves behind, if any. Unlike a plain self-recreating
   * covenant the successor script is NOT identical to its parent — the counter
   * byte moves — so nothing downstream can find it by comparing script bytes to
   * the deployment. The predicate is the only thing that knows what it becomes.
   */
  continuation ({ counter = 0, maxHops, hopFee, redeemTo, branch = 'hop' }) {
    if (branch === 'redeem') return null
    const next = counter + 1
    return {
      script: buildScript({ counter: next, maxHops, hopFee, redeemTo }),
      params: { counter: next, maxHops, hopFee, redeemTo }
    }
  },

  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType, branch = 'hop' }) {
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
      if (PushTx.sFromPreimage(preimage)) {
        // The flag goes BELOW the preimage: the preimage must be on top for the
        // single hoisted OP_PUSH_TX, which then swaps the flag up for OP_IF.
        return new Script()
          .add(branch === 'redeem' ? Opcode.OP_0 : Opcode.OP_1)
          .add(preimage)
      }
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
