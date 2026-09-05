'use strict'

const bsv = require('@smartledger/bsv')

// The smallest predicate that is genuinely a predicate: the coin moves for
// whoever can produce a preimage of this hash. No key, no identity, no
// signature — knowledge alone is the spending condition.
module.exports = {
  name: 'hashlock',
  describe: 'spend by revealing any preimage of a fixed sha256',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ secret: 'open sesame' }),

  lock ({ secret }) {
    const hash = bsv.crypto.Hash.sha256(Buffer.from(secret, 'utf8'))
    return new bsv.Script()
      .add('OP_SHA256')
      .add(hash)
      .add('OP_EQUAL')
  },

  unlock ({ secret, revealed }) {
    // `revealed` lets a test offer the wrong preimage.
    return new bsv.Script().add(Buffer.from(revealed ?? secret, 'utf8'))
  }
}
