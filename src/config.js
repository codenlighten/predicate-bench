'use strict'

const path = require('path')

// One switch decides everything network-shaped. Set BSV_NETWORK=testnet to
// point the wallet, the API client and the address prefixes at testnet.
const network = process.env.BSV_NETWORK === 'testnet' ? 'testnet' : 'livenet'
const wocNet = network === 'livenet' ? 'main' : 'test'

module.exports = {
  network,
  wocNet,
  wocBase: `https://api.whatsonchain.com/v1/bsv/${wocNet}`,
  walletFile: process.env.BSV_WALLET_FILE || path.join(__dirname, '..', '.wallet.json'),

  // sat/KB, the rate we pay.
  feePerKb: Number(process.env.BSV_FEE_PER_KB || 100),

  // Sats parked in each deployed test output. Small enough that a broken
  // predicate burns nothing that matters, but above the 546-sat dust
  // threshold: below that the library refuses to serialize the transaction
  // as non-standard, and fighting that with disableDustOutputs would only
  // move the rejection to the miner.
  testOutputSats: Number(process.env.BSV_TEST_SATS || 1000)
}
