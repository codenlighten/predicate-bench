'use strict'

const bsv = require('@smartledger/bsv')
const BN = bsv.crypto.BN
const N = bsv.crypto.Point.getN()
const G = bsv.crypto.Point.getG()

// An R-puzzle moves the secret out of the key and into the *nonce*.
//
// Every ECDSA signature carries r = (kG).x in the clear. This script parses r
// straight out of the DER bytes in the unlocking script and insists it equals a
// committed value. Producing a signature with a chosen r requires knowing k, so
// knowledge of k is the spending condition — and the key that signs is whatever
// the spender feels like using. The lock never mentions a public key.
//
// Two consequences, both load-bearing and both tested below:
//
//   1. r is a commitment to k, NOT a disclosure of it. Recovering k from
//      r = (kG).x is the discrete log. An observer watching the spend learns r
//      and nothing else — unless they also know the signing key d, because
//      s = k^-1(e + r*d) rearranges to k = s^-1(e + r*d). That rearrangement is
//      the whole mechanism behind "the spend releases a secret": publish d and
//      the nonce falls out of the signature for anyone who cares to look.
//
//   2. Which means an r is strictly single-use in that design. The moment k is
//      recoverable, anyone can sign anything with it, including a transaction
//      paying themselves. See the last two cases.
//
// The library refuses to help you get this wrong: ECDSA marks a caller-supplied
// k spent after one use (`_kFresh`) and falls back to RFC-6979, because signing
// two different messages under one k publishes the private key outright.

/** k whose r has a clear top bit, so DER encodes it as exactly 32 bytes. */
function grindNonce (seed) {
  for (let i = 0; ; i++) {
    const k = new BN(bsv.crypto.Hash.sha256(
      Buffer.concat([Buffer.from(seed, 'utf8'), Buffer.from([i])])
    )).umod(N)
    const r = G.mul(k).getX().umod(N)
    const bytes = r.toBuffer({ size: 32 })
    // A high top bit makes DER prepend 0x00 and the r field 33 bytes long. The
    // script would still work — the length byte drives the split — but the
    // committed value has to match the padded form, and grinding is cheaper
    // than carrying two cases.
    if (bytes[0] < 0x80 && !k.isZero()) return { k, r, rBytes: bytes }
  }
}

/** Sign with a chosen nonce instead of the deterministic one. */
function signWithNonce ({ tx, inputIndex, lockingScript, satoshisBN, sighashType, d, k }) {
  const hashbuf = bsv.Transaction.Sighash.sighash(
    tx, sighashType, inputIndex, lockingScript, satoshisBN
  )
  const ecdsa = new bsv.crypto.ECDSA({ hashbuf, privkey: d, endian: 'little' })
  ecdsa.k = k
  ecdsa._kFresh = true
  ecdsa.sign()
  return ecdsa.sig.set({ nhashtype: sighashType }).toTxFormat()
}

/**
 * Recover the nonce from a spend, given the signing key.
 *
 * This is the "the spend releases a secret" mechanism, and it has a trap in it.
 * BSV enforces LOW_S as a *mandatory* rule, so the signer rewrites s to N-s
 * whenever it lands in the upper half — which negates whatever this rearranges
 * back out. Both k and N-k produce the same r, so the signature gives no way to
 * tell them apart. Half of all spends hand back the wrong one.
 *
 * Reducing to the canonical representative is the whole fix, and omitting it
 * yields a scheme that works in testing and fails on every other segment.
 */
function recoverNonce ({ tx, inputIndex = 0, lockingScript, satoshis, unlockingScript, d }) {
  const sig = bsv.crypto.Signature.fromTxFormat(unlockingScript.chunks[0].buf)
  const e = BN.fromBuffer(
    bsv.Transaction.Sighash.sighash(tx, sig.nhashtype, inputIndex, lockingScript, new BN(satoshis)),
    { endian: 'little' })
  const k = sig.s.invm(N).mul(e.add(sig.r.mul(d.bn))).umod(N)
  return canonicalNonce(k)
}

/** k and N-k are the same puzzle. Pick one, always, on both sides. */
function canonicalNonce (k) {
  return k.cmp(N.shrn(1)) > 0 ? N.sub(k) : k
}

/**
 * Replay an observed signature onto a DIFFERENT transaction.
 *
 * This is WP1605 Claim 2 — "the public key P must be fixed in the locking
 * script" — turned into an attack, and an R-puzzle is the construction that
 * ignores that claim by design.
 *
 * Given any valid (r, s) and any message z', solve for the public key that
 * makes them verify together:
 *
 *     u' = z'/s,  v = r/s,  and we need u'G + vP' = R
 *     therefore   P' = (R - u'G) / v
 *
 * P' is a curve point, not a key: nobody knows its discrete log, and nobody
 * needs to. `OP_CHECKSIG` verifies an equation, and this satisfies it.
 *
 * The consequence for R-puzzles is sharper than "k must stay secret". The
 * attacker never learns k, never learns d, and never holds a private key. One
 * broadcast signature is enough, so the theft window opens the moment the
 * honest spend hits the mempool, not when k is disclosed.
 *
 * @returns {bsv.PublicKey|null} the forged key, or null if neither R works
 */
function forgeKeyFor (sig, tx, inputIndex, lockingScript, satoshis) {
  const z = BN.fromBuffer(
    bsv.Transaction.Sighash.sighash(tx, sig.nhashtype, inputIndex, lockingScript, new BN(satoshis)),
    { endian: 'little' })
  const sInv = sig.s.invm(N)
  const u = z.mul(sInv).umod(N)
  const vInv = sig.r.mul(sInv).umod(N).invm(N)

  // r is an x-coordinate, so R is one of two points. Both yield a working key.
  for (const odd of [false, true]) {
    try {
      const R = bsv.crypto.Point.fromX(odd, sig.r)
      const P = R.add(G.mul(N.sub(u).umod(N))).mul(vInv)   // -u'G as (n-u')G
      return bsv.PublicKey.fromPoint(P, true)
    } catch (err) { /* not on the curve for this parity; try the other */ }
  }
  return null
}

module.exports = {
  name: 'rpuzzle',
  describe: 'spend by signing with a committed ECDSA nonce, under any key',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ nonce: 'the session key', key: bsv.PrivateKey.fromRandom() }),

  lock ({ nonce }) {
    const { rBytes } = grindNonce(nonce)
    return new bsv.Script()
      .add('OP_OVER')                 // sig pubkey sig
      .add('OP_3').add('OP_SPLIT')    // DER header: 0x30 <len> 0x02
      .add('OP_NIP')                  // sig pubkey <rlen || r || ...>
      .add('OP_1').add('OP_SPLIT')    // sig pubkey <rlen> <r || ...>
      .add('OP_SWAP').add('OP_SPLIT') // length byte drives the cut
      .add('OP_DROP')                 // sig pubkey <r>
      .add(rBytes).add('OP_EQUALVERIFY')
      .add('OP_CHECKSIG')             // any key at all — this only proves the tx
  },

  unlock ({ nonce, key, tx, inputIndex, lockingScript, satoshis, satoshisBN, sighashType,
    wrongNonce, signingKey, signingWif, mismatchedPubKey, forge }) {
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)

    // The front-running attack, in full. The attacker sees a signature spending
    // this lock in some transaction, and replays it into their own. Nothing
    // secret is used below: `observed` stands in for what the mempool shows.
    if (forge) {
      const decoy = new bsv.Transaction()
      decoy.addInput(new bsv.Transaction.Input({
        prevTxId: Buffer.alloc(32, 9), outputIndex: 0,
        script: new bsv.Script(), sequenceNumber: 0xffffffff
      }), lockingScript, satoshis)
      decoy.to(bsv.PrivateKey.fromRandom().toAddress(), satoshis - 100)
      const observed = signWithNonce({
        tx: decoy, inputIndex: 0, lockingScript, satoshisBN, sighashType: type,
        d: key, k: grindNonce(nonce).k
      })
      const sig = bsv.crypto.Signature.fromTxFormat(observed)
      const forged = forgeKeyFor(sig, tx, inputIndex, lockingScript, satoshis)
      if (!forged) throw new Error('no curve point for r — cannot forge')
      return new bsv.Script().add(observed).add(forged.toBuffer())
    }

    const { k } = grindNonce(wrongNonce ?? nonce)
    // `signingKey` is the point of the predicate, not a test seam: an R-puzzle
    // is deliberately indifferent to who signs.
    //
    // `signingWif` exists so a real spend can be signed by a DISCLOSED throwaway
    // key. That is the key-release construction: publishing d is what lets an
    // observer solve k = s^-1(e + r*d). Never point it at a key that holds
    // funds — the wallet key is the default here and would be exactly the wrong
    // thing to disclose.
    const d = (signingWif ? bsv.PrivateKey.fromWIF(signingWif) : signingKey) ?? key
    const sig = signWithNonce({ tx, inputIndex, lockingScript, satoshisBN, sighashType: type, d, k })
    return new bsv.Script()
      .add(sig)
      .add((mismatchedPubKey ?? d).publicKey.toBuffer())
  },

  // Exposed so the suite and the docs can do the arithmetic rather than assert it.
  grindNonce,
  signWithNonce,
  recoverNonce,
  canonicalNonce,
  forgeKeyFor
}
