'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A title that pays its creator on every hand-off.
//
// `titled` proved a covenant can accept state it cannot compute. This adds the
// piece that makes it an instrument: every spend must produce TWO outputs, in
// order — the recreated title under its new owner, and a royalty payment to an
// address fixed when the title was minted.
//
// That ordering is the whole new mechanic. hashOutputs is a hash over the
// outputs concatenated in sequence, so the covenant has to build both, in the
// right order, and hash the pair. One output in the wrong position produces a
// different hash and nothing spends. There is no way to "just add" a payment
// afterwards, and no way to drop it.
//
//   script = <owner hash160, 20B> OP_DROP OP_IF <transfer> OP_ELSE <redeem> OP_ENDIF
//
// The beneficiary and the rate live in the logic half, which every hop copies
// verbatim — so neither can be edited by a spender, and neither needs to be
// extracted. Only the owner field is spliced.
const STATE_BYTES = 20
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const BPS_DENOMINATOR = 10000

// Shared covenant primitives — one implementation, in src/clauses.js.
const selfChunk = C.selfChunk
const hash160Of = C.hash160Of
const p2pkhChunk = C.p2pkhTxOutChunk
const requireOutputsAre = C.requireOutputIs   // identical; the name reads better here
const ownerFromChunk = (s) => C.fieldFromChunk(s, HEAD_BYTES, STATE_BYTES)

const P2PKH_PREFIX = Buffer.from('1976a914', 'hex')  // varint(25) OP_DUP OP_HASH160 push20
const P2PKH_SUFFIX = Buffer.from('88ac', 'hex')      // OP_EQUALVERIFY OP_CHECKSIG

function addressString (a) {
  if (typeof a === 'string') return a
  if (Buffer.isBuffer(a)) return bsv.Address.fromPublicKeyHash(a).toString()
  return a.toString()
}

/** What the covenant will compute in script, so JS and script agree exactly. */
function royaltyOn (satoshis, bps) {
  return Math.floor(satoshis * bps / BPS_DENOMINATOR)
}


/**
 * value -> value, royalty.  Truncating division, so the royalty rounds DOWN and
 * the rounding favours the seller. Refused if it truncates to zero: a title
 * whose royalty rounds away has stopped being this instrument, and failing is
 * more honest than silently paying nothing.
 */
function splitRoyalty (s, bps) {
  s.add(Opcode.OP_DUP).add(n(bps)).add(Opcode.OP_MUL).add(n(BPS_DENOMINATOR)).add(Opcode.OP_DIV)
  return s.add(Opcode.OP_DUP).add(n(1)).add(Opcode.OP_GREATERTHANOREQUAL).add(Opcode.OP_VERIFY)
}

/**
 * [value, royalty] -> [value, royalty, remainder as 8-byte LE].
 * The remainder is what output 0 carries: value less the royalty less the fee.
 */
function remainderLE (s, transferFee) {
  s.add(Opcode.OP_2DUP).add(Opcode.OP_SUB).add(n(transferFee)).add(Opcode.OP_SUB)
  return s.add(n(8)).add(Opcode.OP_NUM2BIN)
}

/** [value, royalty, out0] -> [outputs]. Appends the royalty output, in order. */
function appendRoyaltyOutput (s, beneficiary) {
  s.add(Opcode.OP_SWAP).add(n(8)).add(Opcode.OP_NUM2BIN)   // royalty as LE64
  s.add(p2pkhChunk(beneficiary)).add(Opcode.OP_CAT)        // -> out1
  s.add(Opcode.OP_CAT)                                     // out0 || out1, in order
  return s.add(Opcode.OP_NIP)                              // drop the spare value
}


function buildScript ({ owner, beneficiary, royaltyBps, transferFee }) {
  const s = new Script()
  s.add(hash160Of(owner)).add(Opcode.OP_DROP)
  // One OP_PUSH_TX preamble above the split, not one per branch.
  C.authenticateThenBranch(s)

  // ---------------- transfer ----------------
  // in: [newOwner, sig, pubkey, preimage]

  selfChunk(s)
  ownerFromChunk(s)
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_TOALTSTACK)                 // chunk
  s.add(Opcode.OP_TOALTSTACK)                 // preimage
  s.add(Opcode.OP_CHECKSIGVERIFY)
  s.add(Opcode.OP_FROMALTSTACK)               // preimage
  s.add(Opcode.OP_FROMALTSTACK)               // chunk

  s.add(n(HEAD_BYTES)).add(Opcode.OP_SPLIT)
  s.add(n(STATE_BYTES)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
  s.add(Opcode.OP_TOALTSTACK)
  s.add(Opcode.OP_ROT)
  s.add(Opcode.OP_SIZE).add(n(STATE_BYTES)).add(Opcode.OP_EQUALVERIFY)
  s.add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)   // [preimage, nextChunk]

  s.add(Opcode.OP_TOALTSTACK)                        // park the successor
  s.add(Opcode.OP_DUP)
  s.add(n(52)).add(Opcode.OP_RIGHT).add(n(8)).add(Opcode.OP_LEFT).add(Opcode.OP_BIN2NUM)
  splitRoyalty(s, royaltyBps)                        // [preimage, value, royalty]
  remainderLE(s, transferFee)                        // [.., value, royalty, out0amt]
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)   // out0 = amount || successor
  appendRoyaltyOutput(s, beneficiary)
  requireOutputsAre(s)

  s.add(Opcode.OP_ELSE)

  // ---------------- redeem ----------------
  // in: [sig, pubkey, preimage]. Leaving the covenant is a sale too — the exit
  // pays the royalty as well, or a seller could dodge it by cashing out and
  // settling with the buyer off-chain.

  selfChunk(s)
  ownerFromChunk(s)
  s.add(Opcode.OP_DUP).add(Opcode.OP_TOALTSTACK)     // keep the owner for the payout
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_DROP)                              // chunk
  s.add(Opcode.OP_TOALTSTACK)                        // preimage
  s.add(Opcode.OP_CHECKSIGVERIFY)
  s.add(Opcode.OP_FROMALTSTACK)                      // [preimage]

  s.add(Opcode.OP_DUP)
  s.add(n(52)).add(Opcode.OP_RIGHT).add(n(8)).add(Opcode.OP_LEFT).add(Opcode.OP_BIN2NUM)
  splitRoyalty(s, royaltyBps)
  remainderLE(s, transferFee)
  s.add(P2PKH_PREFIX).add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)   // the owner
  s.add(P2PKH_SUFFIX).add(Opcode.OP_CAT)             // out0 = pay the owner
  appendRoyaltyOutput(s, beneficiary)
  requireOutputsAre(s)

  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
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
  name: 'royalty',
  describe: 'a title that pays its creator a share of every hand-off, in two ordered outputs',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ owner: EXAMPLE_ADDRESS, beneficiary: EXAMPLE_ADDRESS_2, royaltyBps: 250, transferFee: 400 }),

  buildScript,
  royaltyOn,

  lock ({ owner, beneficiary, royaltyBps, transferFee }) {
    if (!owner || !beneficiary) throw new Error('owner and beneficiary are required')
    if (!Number.isInteger(royaltyBps) || royaltyBps <= 0 || royaltyBps >= BPS_DENOMINATOR) {
      throw new Error('royaltyBps must be between 1 and 9999')
    }
    if (!Number.isInteger(transferFee) || transferFee <= 0) {
      throw new Error('transferFee must be a positive integer')
    }
    return buildScript({ owner, beneficiary, royaltyBps, transferFee })
  },

  /**
   * Both outputs, in the order hashOutputs commits to. Order is not cosmetic
   * here — swapping them is a different hash and a dead spend.
   */
  outputs ({ owner, newOwner, beneficiary, royaltyBps, transferFee, satoshis,
             branch = 'transfer', actualScript, actualAmount, actualNewOwner,
             actualRoyalty, actualBeneficiary, swapOutputs, dropRoyalty }) {
    const royalty = actualRoyalty ?? royaltyOn(satoshis, royaltyBps)
    const remainder = actualAmount ?? (satoshis - royalty - transferFee)

    const carrier = actualScript || (branch === 'redeem'
      ? bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(hash160Of(owner)))
      : buildScript({ owner: actualNewOwner ?? newOwner, beneficiary, royaltyBps, transferFee }))

    const outs = [
      new bsv.Transaction.Output({ script: carrier, satoshis: remainder }),
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(
          bsv.Address.fromPublicKeyHash(hash160Of(actualBeneficiary ?? beneficiary))),
        satoshis: royalty
      })
    ]
    if (dropRoyalty) return [outs[0]]
    return swapOutputs ? [outs[1], outs[0]] : outs
  },

  continuation ({ newOwner, beneficiary, royaltyBps, transferFee, branch = 'transfer' }) {
    if (branch === 'redeem') return null
    return {
      script: buildScript({ owner: newOwner, beneficiary, royaltyBps, transferFee }),
      params: {
        owner: addressString(newOwner), beneficiary: addressString(beneficiary),
        royaltyBps, transferFee
      }
    }
  },

  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType, branch = 'transfer',
            ownerKey, ownerWif, key, newOwner, pushNewOwner, signWith }) {
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const signer = signWith || ownerKey ||
      (ownerWif ? bsv.PrivateKey.fromWIF(ownerWif) : null) || key
    if (!signer) throw new Error('no signing key: pass ownerWif= for a title you do not hold')

    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
      if (!PushTx.sFromPreimage(preimage)) continue

      const sig = bsv.Transaction.Sighash.sign(
        tx, signer, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)
      ).toTxFormat()

      const s = new Script()
      if (branch !== 'redeem') s.add(hash160Of(pushNewOwner ?? newOwner))
      // The flag goes BELOW the preimage: the preimage must be on top for the
      // single hoisted OP_PUSH_TX, which then swaps the flag up for OP_IF.
      s.add(sig).add(signer.publicKey.toBuffer())
      s.add(branch === 'redeem' ? Opcode.OP_0 : Opcode.OP_1)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
