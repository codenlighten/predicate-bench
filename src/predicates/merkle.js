'use strict'

const bsv = require('@smartledger/bsv')
const Opcode = bsv.Opcode

// Spend by proving a leaf belongs to a committed Merkle tree.
//
// No introspection and no signature — the coin moves for whoever can produce an
// inclusion proof against a root fixed at lock time. It is here because every
// other predicate reasons about the *transaction*, and a bench that claims to
// cover locking scripts should also show Script reasoning about a *data
// structure*. `OP_CAT` and `OP_HASH256` are all it takes.
//
// Per level, seven bytes:
//
//   OP_ROT OP_IF OP_ELSE OP_SWAP OP_ENDIF OP_CAT OP_HASH256
//
// The direction bit decides concatenation order, and getting it backwards is
// the classic Merkle bug: with the stack as [sibling, current], OP_CAT already
// yields `sibling || current`, so the *empty* IF branch is the "sibling on the
// left" case and OP_SWAP is needed only for the other. Written the obvious way
// round it silently verifies against a different tree.
//
// Depth is fixed at lock time, which is not a limitation of Merkle proofs but
// of Script: there are no loops, so every level is unrolled. That is the
// bounded-iteration ceiling the literature describes — a script can check
// membership at depth n, never at "some depth".
module.exports = {
  name: 'merkle',
  describe: 'spend by proving a leaf is in a committed tree — OP_CAT and OP_HASH256, no introspection',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ root: Buffer.alloc(32, 0xab), depth: 4 }),

  lock ({ root, depth }) {
    if (!Number.isInteger(depth) || depth < 1) throw new Error('depth must be a positive integer')
    const r = Buffer.isBuffer(root) ? root : Buffer.from(root, 'hex')
    if (r.length !== 32) throw new Error('root must be 32 bytes')

    const s = new bsv.Script()
    for (let i = 0; i < depth; i++) {
      s.add(Opcode.OP_ROT)                       // [sibling, current, bit] -> bit on top
      s.add(Opcode.OP_IF).add(Opcode.OP_ELSE)    // bit set: sibling on the left, OP_CAT already
      s.add(Opcode.OP_SWAP)                      //          clear: put current first
      s.add(Opcode.OP_ENDIF)
      s.add(Opcode.OP_CAT).add(Opcode.OP_HASH256)
    }
    return s.add(r).add(Opcode.OP_EQUAL)
  },

  /**
   * The proof, pushed so that each level's data is on top when its turn comes:
   * deepest level first, leaf last.
   *
   * `path` is [{ sibling, right }] from the leaf upward, where `right` means the
   * sibling sits on the right — i.e. the current hash is the left input.
   */
  unlock ({ leaf, path, actualLeaf, actualPath }) {
    const p = actualPath || path
    const s = new bsv.Script()
    for (let i = p.length - 1; i >= 0; i--) {
      s.add(p[i].right ? Opcode.OP_0 : Opcode.OP_1)
      s.add(p[i].sibling)
    }
    return s.add(actualLeaf || leaf)
  }
}
