'use strict'

const bsv = require('@smartledger/bsv')
const P = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const Script = bsv.Script
const Opcode = bsv.Opcode

// A leaner OP_PUSH_TX core.
//
// The stock core is 377 bytes and dominates every stateful covenant here. Two
// of its steps are DEAD CODE — not usually dead, provably dead, given the
// constraints the spender's grind already has to satisfy.
//
//   s = (HASH256(preimage) + Gx) mod n,  then NUM2BIN to 32 bytes LE
//
// `sFromPreimage` refuses any preimage unless BOTH of these hold:
//
//   (a) z[0] is in 0x01..0x7f — required so that e, read little-endian, is
//       positive and MINIMALLY ENCODED. Without it the script would need a
//       sign byte and stop being mainnet-relayable.
//   (b) s <= n/2 — low-S, so the in-script signature is canonical.
//
// From (a): e < 0x80 * 2^248 = 2^255. And Gx ~ 0.4756 * 2^256. So
//
//   e + Gx < 0.5*2^256 + 0.4756*2^256 = 0.9756 * 2^256 < n
//
// The sum can never reach n, so **OP_MOD never reduces anything**. Measured over
// 200000 preimages: 4124 accepted by the grind, 0 where the mod would fire.
//
// From (b) plus the sFromPreimage check that sBE[0] >= 0x01: s is in
// [2^248, n/2], whose minimal little-endian encoding is exactly 32 bytes with a
// positive top byte. So **OP_NUM2BIN(32) is a no-op** on every value that can
// reach it. Measured: 0 of 4124 needed it.
//
// Both removals are safe in the strong direction. A preimage that violated the
// assumptions would produce a wrong-length buffer, the 31-way OP_SPLIT reversal
// would fail with INVALID_SPLIT_RANGE, and the spend would be refused. Removing
// them can only make a spend harder to construct, never easier to forge.
//
// What is NOT removable: the two 32-byte endianness flips, 248 of the 377 bytes.
// OP_HASH256 emits big-endian, script arithmetic is little-endian, and DER wants
// big-endian again. Every byte has to move, and at 4 script bytes per byte moved
// the loop is already near the floor for this construction.

const SIGHASH = helpers.SIGHASH

/**
 * Append the in-script signature generator + verifier, minus the dead steps.
 * Pre: top of stack = preimage. Post: top = OP_CHECKSIG result.
 */
function leanCore (script, opts) {
  const sighashType = (opts && opts.sighashType) || SIGHASH

  script.add(Opcode.OP_HASH256)     // z, 32 bytes big-endian
  P.reverseBytes(script, 32)        // -> e, little-endian script number
  script.add(P.gxLe).add(Opcode.OP_ADD)
  //  [removed] N_LE OP_MOD          -- the sum can never reach n
  //  [removed] <32> OP_NUM2BIN      -- s is already exactly 32 bytes
  P.reverseBytes(script, 32)        // -> s, big-endian for the DER INTEGER

  // Gx is both the DER r-value and the body of the 02||Gx pubkey; pushing it
  // once and sharing via the altstack beats embedding a 32-byte constant twice.
  script.add(P.Gx).add(Opcode.OP_DUP)
  script.add(Opcode.OP_2).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)   // 02||Gx
  script.add(Opcode.OP_TOALTSTACK)
  script.add(Buffer.from([0x30, 0x44, 0x02, 0x20])).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  script.add(Buffer.from([0x02, 0x20])).add(Opcode.OP_CAT)
  script.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  script.add(Buffer.from([sighashType])).add(Opcode.OP_CAT)
  return script.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CHECKSIG)
}

/** A bare authenticator, for testing the core in isolation. */
function authenticator () {
  return leanCore(new Script())
}

/**
 * Re-check the assumptions the removals rest on, for a given preimage.
 * Returns null if the preimage would not be accepted anyway, otherwise an
 * object saying whether either removed step would have done work.
 */
function auditAssumptions (preimage) {
  const BN = bsv.crypto.BN
  const s = P.sFromPreimage(preimage)
  if (!s) return null
  const z = bsv.crypto.Hash.sha256sha256(preimage)
  const raw = new BN(z).add(new BN(P.Gx))
  return {
    modWouldReduce: raw.gte(P.N),
    numBinWouldPad: new BN(s).toScriptNumBuffer().length !== 32
  }
}

/**
 * The same core with an OP_CODESEPARATOR immediately before the OP_CHECKSIG.
 *
 * The sighash's `scriptCode` is the script from the last executed
 * OP_CODESEPARATOR to the end, so putting one here excludes the ~340 bytes of
 * endianness-flipping machinery that precede it. The preimage the spender has
 * to push shrinks by the same amount, and since that preimage IS the unlocking
 * script the saving lands twice. Measured on an output covenant:
 *
 *   without   scriptCode 384 B   preimage 543 B   tx 633 B
 *   with      scriptCode  46 B   preimage 203 B   tx 290 B   (-54%)
 *
 * The technique is sCrypt's (`checkPreimageOCS` and friends). Two conditions,
 * and the second is the one that bites:
 *
 * 1. The spender must compute the preimage over the TRUNCATED script — from
 *    just after the separator — or the digests will not agree. `subscript()`
 *    below returns it.
 *
 * 2. **Never on a self-recreating covenant.** Those read their own bytes out of
 *    the preimage's scriptCode to rebuild themselves; truncating it means they
 *    rebuild the tail instead of the script, and the output can never match
 *    hashOutputs. On `perpetual` the separator would leave 2 bytes where 385
 *    are needed. Use it only where the script reads TAIL fields — nLockTime,
 *    hashOutputs, value — and never itself.
 *
 * A smaller trade also comes with it: the signature now commits to less of the
 * locking script. Anything that distinguishes one covenant from another must
 * therefore live AFTER the separator, which for these predicates it does — the
 * committed constants all sit in the logic that follows.
 *
 * @returns {number} the chunk index of the separator, for subscript()
 */
function leanCoreOCS (script, opts) {
  leanCore(script, opts)
  return placeSeparator(script)
}

/** The same for the optimal core. */
function optimalCoreOCS (script, opts) {
  optimalCore(script, opts)
  return placeSeparator(script)
}

/**
 * Put the separator immediately before OP_CHECKSIG — as late as it can go.
 *
 * Placement is worth getting exactly right, because everything before it is
 * excluded from scriptCode and everything after is not. Putting it one chunk
 * earlier leaves the public-key push inside the digest: with the optimal core,
 * whose 33-byte pubkey is pushed inline rather than fetched from the altstack,
 * that alone cost 34 bytes of preimage in every spend.
 */
function placeSeparator (script) {
  const at = script.chunks.length - 1   // the last chunk is OP_CHECKSIG
  script.chunks.splice(at, 0, { opcodenum: Opcode.OP_CODESEPARATOR })
  return at
}

/** The script a spender must build the preimage over, given the separator index. */
function subscript (lockingScript, separatorIndex) {
  return new Script().set({ chunks: lockingScript.chunks.slice(separatorIndex + 1) })
}

// ---------------------------------------------------------------------------
// The OPTIMAL core: 85 bytes instead of 339.
//
// Everything above treats the two endianness reversals as irreducible. They are
// not — they are only irreducible if you insist on a = 1.
//
// OP_HASH256 gives H, 32 bytes big-endian, and e is H read as a big-endian
// integer. OP_BIN2NUM reads those same bytes as a LITTLE-endian script number,
// call it m. OP_1ADD gives m+1, and <32> OP_NUM2BIN writes it back as 32
// little-endian bytes — which is H with byte 0 incremented, because byte 0 is
// the least significant end in little-endian. Read back as the DER `s`, byte 0
// is the MOST significant. So those four opcodes compute
//
//     s = e + 2^248
//
// ECDSA with k = 1 gives s = e + r*a, and r = Gx. So the construction is sound
// for the private key that satisfies r*a = 2^248:
//
//     a = 2^248 * Gx^-1 mod n
//
// The byte-order mismatch is not fought, it is absorbed into the key. Verified:
// Gx * a mod n equals 2^248 exactly.
//
// The cost moves off-chain. `sFromPreimageOptimal` below is stricter than the
// classic one, and a spender grinds until it passes — measured at ~4 tries.
// This is the trade the literature calls Optimal vs Classic: Classic guarantees
// compliance in script at several hundred bytes, Optimal delegates it to
// off-chain malleation for under a hundred.

const OPTIMAL_A = new bsv.crypto.BN(2).pow(new bsv.crypto.BN(248))
  .mul(new bsv.crypto.BN(P.Gx).invm(P.N)).umod(P.N)

/** P = a*G for that key. Fixed, like Gx — malleability requires it. */
const OPTIMAL_PUBKEY =
  bsv.PrivateKey.fromBuffer(OPTIMAL_A.toBuffer({ size: 32 })).publicKey.toBuffer()

const DER_PREFIX = Buffer.concat([
  Buffer.from([0x30, 0x44, 0x02, 0x20]), P.Gx, Buffer.from([0x02, 0x20])
])

function optimalCore (script, opts) {
  const sighashType = (opts && opts.sighashType) || SIGHASH
  script.add(Opcode.OP_HASH256)
  script.add(Opcode.OP_BIN2NUM)                                  // read H little-endian
  script.add(Opcode.OP_1ADD)                                     // + 1 at the LE low end
  script.add(helpers.scriptNum(32)).add(Opcode.OP_NUM2BIN)       // back to 32 bytes = s
  script.add(DER_PREFIX).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  script.add(Buffer.from([sighashType])).add(Opcode.OP_CAT)
  return script.add(OPTIMAL_PUBKEY).add(Opcode.OP_CHECKSIG)
}

/**
 * Whether a preimage works with the optimal core, and the `s` it yields.
 *
 * Four conditions, each of which the classic core would have handled in script:
 *   H[31] < 0x80   or OP_BIN2NUM reads the number as NEGATIVE
 *   H[0] < 0xff    or incrementing byte 0 carries, and s is not H-with-a-bump
 *   s <= n/2       low-S, which the classic core enforced by group subtraction
 *   sBE[0] in 1..0x7f   valid fixed-length DER
 */
function sFromPreimageOptimal (preimage) {
  const BN = bsv.crypto.BN
  const H = bsv.crypto.Hash.sha256sha256(preimage)
  if (H[31] >= 0x80 || H[0] >= 0xff) return null
  const s = new BN(H).add(new BN(2).pow(new BN(248)))
  if (s.gt(P.N.shrn(1))) return null
  const sBE = s.toBuffer({ size: 32 })
  return (sBE[0] >= 0x01 && sBE[0] <= 0x7f) ? sBE : null
}

module.exports = {
  leanCore, leanCoreOCS, subscript, authenticator, auditAssumptions, SIGHASH,
  optimalCore, optimalCoreOCS, sFromPreimageOptimal, OPTIMAL_A, OPTIMAL_PUBKEY
}
