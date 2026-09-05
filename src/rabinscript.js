'use strict'

const Opcode = require('@smartledger/bsv').Opcode

// The Rabin verifier, as a Script clause — the one piece an oracle-gated covenant
// cannot do without, factored out of any single predicate so `oracle` (a binary
// gate) and `settlement` (a computed payout) share exactly one implementation of
// s² mod N == H(message ‖ padding) mod N. See docs/oracle.md for the maths.
//
// Contract. Given three values already on the main stack, named by the caller —
// the Rabin signature `sig`, the signed message `msg`, and the 2-byte `pad` — this
// asserts the signature is a valid Rabin signature over `msg ‖ pad` under the
// hard-coded modulus, and returns the name of ONE scratch value it leaves on top
// (`msg ‖ pad`, reused as the hash input). The caller must drop it. The three
// input values are read through copies and remain where they were.
//
// It deliberately does NOT clean up that last scratch itself: `oracle` was
// deployed byte-for-byte with the scratch dropped by its own trailing cleanup, so
// leaving it here keeps that predicate's on-chain bytes unchanged while letting a
// new caller drop it explicitly.

const HASH_BLOCKS = 4   // SHA256(x‖1)…SHA256(x‖4): 128 bytes, ≥ the demo modulus

// Both sides of the comparison, ending with s² mod N and H mod N adjacent on top
// (over the reusable `r_x` scratch): stack tail becomes [.., r_x, r_hMod, r_sMod].
// verify() and check() differ only in how they consume that final pair.
function _core (asm, { nBytes, sig, msg, pad }) {
  // left side:  sMod = s² mod N
  asm.pick(sig, 'r_s'); asm.bin2num('r_sn'); asm.pick('r_sn', 'r_sn2'); asm.mul('r_ssq')
  asm.data(nBytes, 'r_Na'); asm.mod('r_sMod')

  // right side: hMod = H(msg ‖ pad) mod N, the expanded HASH_BLOCKS-block hash
  asm.pick(msg, 'r_mx'); asm.pick(pad, 'r_px'); asm.cat('r_x')
  for (let i = 1; i <= HASH_BLOCKS; i++) {
    asm.pick('r_x', 'r_xi'); asm.num(i, 'r_ci'); asm.cat('r_xci'); asm.sha256('r_bi')
    if (i > 1) asm.cat('r_blob')          // concatenate onto the running blob
  }
  asm.data(Buffer.from([0]), 'r_z'); asm.cat('r_blobP')      // 0x00 pad => unsigned
  asm.bin2num('r_hn'); asm.data(nBytes, 'r_Nb'); asm.mod('r_hMod')

  asm.roll('r_sMod')                                         // [.., r_x, r_hMod, r_sMod]
}

/**
 * Assert the signature is valid — aborts the spend if not.
 * @returns the stack name of the one scratch value the caller must drop.
 */
function verify (asm, { nBytes, sig, msg, pad }) {
  _core(asm, { nBytes, sig, msg, pad })
  asm.numEqualVerify()                                       // s² mod N == H mod N
  return 'r_x'                                               // scratch: caller drops
}

/**
 * Test the signature WITHOUT aborting — leaves 1 (valid) or 0 (invalid) on top,
 * so a caller can count how many of several oracles agree. Consumes its own
 * scratch; the boolean is all it leaves.
 */
function check (asm, { nBytes, sig, msg, pad }) {
  _core(asm, { nBytes, sig, msg, pad })
  asm.numEqual('r_ok')                                       // [.., r_x, r_ok]
  asm.nip()                                                  // drop r_x, keep the boolean
}

module.exports = { verify, check, HASH_BLOCKS, OP_DROP: Opcode.OP_DROP }
