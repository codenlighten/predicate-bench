'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A transferable title: a coin that carries its current owner in its own script.
//
// The counter in `metered` was state the script could COMPUTE — there was only
// one successor, so nothing had to be trusted. An owner is different: the next
// owner is chosen by the current one, so the script is handed a value it cannot
// derive. That is the interesting case, and the shape of the answer is:
//
//   splice the supplied value into your own bytes, and force everything else
//   to stay identical.
//
// The script reads itself out of the preimage, replaces exactly the 20 bytes of
// the owner field with the 20 bytes it was given, and demands the spend pay to
// the result. The new owner is free; every other byte of the contract — the
// fee, the logic, the branches — is not.
//
//   script = <owner hash160, 20B> OP_DROP OP_IF <transfer> OP_ELSE <redeem> OP_ENDIF
//
// Both branches require the CURRENT owner's signature, so possession of the
// UTXO is not authority; the key named inside it is.
const STATE_BYTES = 20                 // hash160
const VARINT_BYTES = 3                 // scripts of 253..65535
const HEAD_BYTES = VARINT_BYTES + 1    // varint + the 0x14 push opcode

// Shared covenant primitives — one implementation, in src/clauses.js.
const selfChunk = C.selfChunk
const newValueLE = C.newValueLE
const requireOutputIs = C.requireOutputIs
const ownerFromChunk = (s) => C.fieldFromChunk(s, HEAD_BYTES, STATE_BYTES)

const P2PKH_PREFIX = Buffer.from('1976a914', 'hex')  // varint(25) OP_DUP OP_HASH160 push20
const P2PKH_SUFFIX = Buffer.from('88ac', 'hex')      // OP_EQUALVERIFY OP_CHECKSIG

/** The owner as a base58 address string, for the deployment ledger. */
function ownerAddressString (o) {
  if (typeof o === 'string') return o
  if (Buffer.isBuffer(o)) return bsv.Address.fromPublicKeyHash(o).toString()
  return o.toString()
}

function ownerHash (addressOrHash) {
  if (Buffer.isBuffer(addressOrHash)) return addressOrHash
  const a = typeof addressOrHash === 'string' ? bsv.Address.fromString(addressOrHash) : addressOrHash
  return a.hashBuffer
}





function buildScript ({ owner, transferFee }) {
  const s = new Script()
  s.add(ownerHash(owner)).add(Opcode.OP_DROP)
  // One OP_PUSH_TX preamble above the split, not one per branch.
  C.authenticateThenBranch(s)

  // ---------------- transfer: hand the title to a new owner ----------------
  // in: [newOwner, sig, pubkey, preimage]

  selfChunk(s)                                   // [newOwner, sig, pubkey, preimage, chunk]
  ownerFromChunk(s)                              // ... chunk, owner
  // The signer must be the owner named in our own bytes. pubkey is 3 deep once
  // owner is on top, so reach it with OP_PICK rather than shuffling the stack.
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_TOALTSTACK)                    // park chunk
  s.add(Opcode.OP_TOALTSTACK)                    // park preimage
  s.add(Opcode.OP_CHECKSIGVERIFY)                // consumes pubkey, sig -> [newOwner]
  s.add(Opcode.OP_FROMALTSTACK)                  // preimage
  s.add(Opcode.OP_FROMALTSTACK)                  // chunk   [newOwner, preimage, chunk]

  s.add(n(HEAD_BYTES)).add(Opcode.OP_SPLIT)      // [.., head, rest1]
  s.add(n(STATE_BYTES)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)  // drop the old owner
  s.add(Opcode.OP_TOALTSTACK)                    // park the tail
  s.add(Opcode.OP_ROT)                           // [preimage, head, newOwner]
  // A short or long owner field would shift every offset in the successor.
  // The malformed output would fail to match anyway; failing here says why.
  s.add(Opcode.OP_SIZE).add(n(STATE_BYTES)).add(Opcode.OP_EQUALVERIFY)
  s.add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)   // [preimage, nextChunk]

  s.add(Opcode.OP_OVER)
  newValueLE(s, transferFee)
  s.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  requireOutputIs(s)

  s.add(Opcode.OP_ELSE)

  // ---------------- redeem: the owner cashes out of the covenant ----------------
  // in: [sig, pubkey, preimage].  The exit that keeps this from stranding: the
  // title can always leave, but only to the key that currently holds it.

  selfChunk(s)                                   // [sig, pubkey, preimage, chunk]
  ownerFromChunk(s)                              // ... chunk, owner
  s.add(Opcode.OP_DUP).add(Opcode.OP_TOALTSTACK) // keep the owner for the payout
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_DROP)                          // chunk
  s.add(Opcode.OP_TOALTSTACK)                    // park preimage
  s.add(Opcode.OP_CHECKSIGVERIFY)
  s.add(Opcode.OP_FROMALTSTACK)                  // [preimage]

  s.add(Opcode.OP_DUP)
  newValueLE(s, transferFee)                     // [preimage, newValue8]
  s.add(P2PKH_PREFIX).add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)
  s.add(P2PKH_SUFFIX).add(Opcode.OP_CAT)
  requireOutputIs(s)

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
  name: 'titled',
  describe: 'a transferable title: the current owner signs to hand it on, or to cash out',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ owner: EXAMPLE_ADDRESS, transferFee: 400 }),

  buildScript,
  ownerHash,

  lock ({ owner, transferFee }) {
    if (!owner) throw new Error('owner is required')
    if (!Number.isInteger(transferFee) || transferFee <= 0) {
      throw new Error('transferFee must be a positive integer')
    }
    return buildScript({ owner, transferFee })
  },

  outputs ({ owner, newOwner, transferFee, satoshis, branch = 'transfer',
             actualScript, actualAmount, actualNewOwner }) {
    const script = actualScript || (branch === 'redeem'
      ? bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(ownerHash(owner)))
      : buildScript({ owner: actualNewOwner ?? newOwner, transferFee }))
    return [new bsv.Transaction.Output({
      script,
      satoshis: actualAmount ?? (satoshis - transferFee)
    })]
  },

  /**
   * Grind first, then sign. The grind moves nLockTime, nLockTime is in the
   * sighash, so a signature made before the grind signs a transaction that no
   * longer exists.
   */
  /** After a transfer the title still exists — under a new owner. */
  continuation ({ newOwner, transferFee, branch = 'transfer' }) {
    if (branch === 'redeem') return null
    return {
      script: buildScript({ owner: newOwner, transferFee }),
      params: { owner: ownerAddressString(newOwner), transferFee }
    }
  },

  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType, branch = 'transfer',
            ownerKey, ownerWif, key, newOwner, pushNewOwner, signWith }) {
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)

    // Whoever currently holds the title has to sign. On the command line that
    // is the funding wallet by default, or an explicit WIF when the title has
    // moved to somebody else.
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
      // pushNewOwner exists so a test can claim one successor while the
      // transaction pays another. The claim is spliced into the script the
      // covenant demands; the payment is what hashOutputs commits to. They
      // have to be the same value or nothing spends.
      if (branch !== 'redeem') s.add(ownerHash(pushNewOwner ?? newOwner))
      // The flag goes BELOW the preimage: the preimage must be on top for the
      // single hoisted OP_PUSH_TX, which then swaps the flag up for OP_IF.
      s.add(sig).add(signer.publicKey.toBuffer())
      s.add(branch === 'redeem' ? Opcode.OP_0 : Opcode.OP_1)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
