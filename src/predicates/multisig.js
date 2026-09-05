'use strict'

const bsv = require('@smartledger/bsv')
const BN = bsv.crypto.BN
const Opcode = bsv.Opcode

// m-of-n multisig. The oldest way of splitting authority in Bitcoin, and the
// one predicate here that is not a covenant — included because a bench that
// claims to cover locking scripts should not skip it, and because its refusal
// behaviour surprises people.
//
//   <m> <pk1> ... <pkn> <n> OP_CHECKMULTISIG
//
// Two things are worth knowing before using it.
//
// **Signatures must appear in the same relative order as their keys.**
// OP_CHECKMULTISIG walks the signature and key lists together in one pass; a
// signature that does not match the key it is currently looking at is not
// retried against the others. Two valid signatures from two named owners, in
// the wrong order, do not spend. Nothing in the error says so.
//
// **The leading dummy element must be empty.** OP_CHECKMULTISIG pops one item
// more than it uses, an off-by-one from the original implementation kept for
// compatibility. NULLDUMMY requires that item be empty; measured on mainnet, a
// non-empty dummy is refused as `Dummy CHECKMULTISIG argument must be zero`.
const SIGHASH = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID

// Fixed scalars, so a documented byte count is reproducible rather than
// dependent on whichever keys happened to be generated. Never for real funds.
const EXAMPLE_KEYS = [1, 2, 3].map(n => {
  const b = Buffer.alloc(32)
  b[31] = n
  return bsv.PrivateKey.fromBuffer(b)
})

module.exports = {
  name: 'multisig',
  describe: 'm-of-n: signatures must be present, valid, and in key order',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ m: 2, keys: EXAMPLE_KEYS }),

  lock ({ m, keys }) {
    if (!Number.isInteger(m) || m < 1 || m > keys.length) {
      throw new Error(`m must be between 1 and ${keys.length}`)
    }
    if (keys.length > 16) throw new Error('n above 16 needs a data push, not OP_N')

    // m and n must use OP_1..OP_16, not a one-byte data push. A data push of
    // 0x02 where OP_2 exists is non-minimal, and MINIMALDATA refuses it — which
    // is how this was caught: the suite verifies under node policy, so the
    // happy paths failed with SCRIPT_ERR_MINIMALDATA before ever reaching the
    // signature check.
    const smallInt = (v) => Opcode.OP_1 + (v - 1)

    // A key may be a PrivateKey (suite), a PublicKey, a raw pubkey Buffer, or a
    // hex string — so a recorded deployment rebuilds from serialised pubkeys.
    const pub = (k) => k.publicKey ? k.publicKey.toBuffer()
      : Buffer.isBuffer(k) ? k : Buffer.from(k, 'hex')
    const s = new bsv.Script().add(smallInt(m))
    keys.forEach(k => s.add(pub(k)))
    return s.add(smallInt(keys.length)).add(Opcode.OP_CHECKMULTISIG)
  },

  /**
   * `signWith` selects which keys sign, by index, and in what order — so a case
   * can present two genuinely valid signatures in the wrong order, which is the
   * failure people do not expect.
   */
  unlock ({ tx, inputIndex, lockingScript, satoshis, keys, m, signWith, impostor, dummy, sighashType }) {
    const type = sighashType ?? SIGHASH
    const chosen = signWith || keys.slice(0, m).map((_, i) => i)

    const s = new bsv.Script()
    // The off-by-one element. Empty unless a case is deliberately breaking it.
    s.add(dummy === undefined ? Opcode.OP_0 : dummy)
    for (const idx of chosen) {
      // `impostor` substitutes a key that is NOT among the locking script's,
      // which is the actual outsider case. Swapping a key into `keys` instead
      // would rewrite the lock, and then the outsider is simply a signer.
      const key = (impostor && impostor.at === idx) ? impostor.key : keys[idx]
      s.add(bsv.Transaction.Sighash.sign(
        tx, key, type, inputIndex, lockingScript, new BN(satoshis)
      ).toTxFormat())
    }
    return s
  }
}
