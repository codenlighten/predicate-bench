'use strict'

const bsv = require('@smartledger/bsv')

// The baseline. Not interesting as a predicate — interesting because if this
// does not verify, the harness is wrong and nothing below it can be trusted.
module.exports = {
  name: 'p2pkh',
  describe: 'the standard predicate: prove you hold the key behind this hash',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({ key: require('@smartledger/bsv').PrivateKey.fromRandom() }),

  lock ({ key, address }) {
    // `key` for the suite; `address` so a recorded deployment rebuilds from a
    // string (the spend still needs the key, supplied at unlock time).
    const addr = address ? bsv.Address.fromString(address) : key.toAddress()
    return bsv.Script.buildPublicKeyHashOut(addr)
  },

  unlock ({ key, sign, wrongKey }) {
    const signer = wrongKey || key
    return new bsv.Script()
      .add(sign(signer))
      .add(signer.publicKey.toBuffer())
  }
}
