'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Opcode = bsv.Opcode

// A hash time-locked contract: the primitive behind atomic swaps and payment
// channels. Two ways out, and only one can ever be taken.
//
//   claim   the recipient reveals a preimage and signs — available immediately
//   refund  the sender signs, but only after a locktime floor
//
// On Bitcoin this is four opcodes of timelock. On BSV it is not, and that is
// the point of building it here.
//
// **OP_CHECKLOCKTIMEVERIFY does not work on BSV.** Genesis reverted it to
// OP_NOP2 for every output created after 2020, so a script containing it
// enforces no locktime at all — a floor of 999999999 spends with nLockTime 0.
// Worse, it is then a discouraged upgradable NOP: measured on mainnet, such a
// spend is refused with `NOPx reserved for soft-fork upgrades`. A CLTV timelock
// on BSV is therefore both unenforced and unrelayable, which is the worst
// combination available — it looks correct and is neither.
//
// So the refund branch reads nLockTime out of an OP_PUSH_TX-authenticated
// preimage instead, the same construction as `timelock`. That costs roughly 340
// bytes the Bitcoin version does not pay, and it is why the two branches here
// are so lopsided in size.
//
//   claim branch   ~40 bytes    no preimage needed
//   refund branch  ~420 bytes   the whole OP_PUSH_TX apparatus
//
// Putting the preamble inside the refund branch rather than hoisting it keeps
// the common path cheap: a claim never carries the cost of the escape hatch.
module.exports = {
  name: 'htlc',
  describe: 'claim by revealing a secret, or refund after a locktime — no CLTV, because BSV removed it',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => {
    const mk = (n) => { const b = Buffer.alloc(32); b[31] = n; return bsv.PrivateKey.fromBuffer(b) }
    return { secret: 'open sesame', recipient: mk(1), sender: mk(2), notBefore: 964000 }
  },

  lock ({ secret, recipient, sender, notBefore }) {
    const hash = bsv.crypto.Hash.sha256(Buffer.from(secret, 'utf8'))
    // A party may be a key (suite) or a serialised pubkey hex/Buffer, so a
    // recorded deployment rebuilds without the private keys.
    const pub = (k) => k.publicKey ? k.publicKey.toBuffer()
      : Buffer.isBuffer(k) ? k : Buffer.from(k, 'hex')
    const s = new bsv.Script()

    s.add(Opcode.OP_IF)
    // ---- claim: know the secret, and hold the recipient's key ----
    s.add(Opcode.OP_SHA256).add(hash).add(Opcode.OP_EQUALVERIFY)
    s.add(pub(recipient)).add(Opcode.OP_CHECKSIG)

    s.add(Opcode.OP_ELSE)
    // ---- refund: the sender's key, but not before the floor ----
    // in: [sig, preimage]
    C.authenticate(s)                       // OP_PUSH_TX; leaves [sig, preimage]
    C.requireSighashAll(s)
    C.requireSequenceNonFinal(s)            // or nLockTime is inert
    C.requireLockTimeAtLeast(s, notBefore)
    s.add(Opcode.OP_DROP)                   // done with the preimage; [sig]
    s.add(pub(sender)).add(Opcode.OP_CHECKSIG)

    s.add(Opcode.OP_ENDIF)
    return s
  },

  unlockDefaults: { sequenceNumber: 0xfffffffe },

  unlock ({ tx, inputIndex, lockingScript, satoshis, sighashType,
            branch = 'claim', secret, revealed, recipient, sender, notBefore,
            actualNotBefore, signWith }) {
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sign = (key) => bsv.Transaction.Sighash.sign(
      tx, key, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)
    ).toTxFormat()

    if (branch === 'claim') {
      // No preimage, no grinding: the claim path never touches OP_PUSH_TX.
      const key = signWith || recipient
      return new bsv.Script()
        .add(sign(key))
        .add(Buffer.from(revealed ?? secret, 'utf8'))
        .add(Opcode.OP_1)
    }

    // Refund: grind the SEQUENCE so nLockTime stays exactly at the floor, then
    // sign — the grind moves the transaction, so signing first signs something
    // that no longer exists.
    const claimedFloor = actualNotBefore ?? notBefore
    const preimage = C.grindPreimage(
      tx, inputIndex, lockingScript, satoshis, claimedFloor, sighashType)
    const key = signWith || sender
    return new bsv.Script().add(sign(key)).add(preimage).add(Opcode.OP_0)
  }
}
