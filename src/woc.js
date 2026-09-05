'use strict'

const { wocBase, wocNet } = require('./config')

const sleep = (ms) => new Promise(r => setTimeout(r, ms))

/**
 * 429 and 5xx are transient. Retrying matters most for the broadcast: giving up
 * there turns a rate limit into a spend that never happened, right after the
 * transaction was built and locally verified. Backoff is exponential and the
 * error text is kept, so a persistent failure still says what it was.
 */
async function call (path, opts = {}, attempt = 0) {
  const res = await fetch(wocBase + path, opts)
  const text = await res.text()

  if (!res.ok) {
    const transient = res.status === 429 || res.status >= 500
    if (transient && attempt < 4) {
      await sleep(800 * Math.pow(2, attempt))
      return call(path, opts, attempt + 1)
    }
    throw new Error(`WhatsOnChain ${res.status} on ${path}: ${text.slice(0, 200)}`)
  }
  try { return JSON.parse(text) } catch { return text.trim() }
}

// WoC has returned both a bare array and a {result:[...]} envelope from this
// endpoint over the years. Normalize rather than depend on which one is live.
async function getUtxos (address) {
  const r = await call(`/address/${address}/unspent`)
  const rows = Array.isArray(r) ? r : (r.result || [])
  return rows.map(u => ({
    txId: u.tx_hash,
    outputIndex: u.tx_pos,
    satoshis: u.value,
    height: u.height
  }))
}

const getBalance = (address) => call(`/address/${address}/balance`)
const getRawTx = (txid) => call(`/tx/${txid}/hex`)

const broadcast = (rawtx) => call('/tx/raw', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ txhex: rawtx })
})

// A second, independent explorer.
//
// Relying on one API is a single point of failure that does not announce
// itself: WhatsOnChain's free tier began returning 429 to every request after
// a run of broadcasts, and with only one source the wallet reports an empty
// UTXO set rather than an error. Bitails runs pruned, so it is a cross-check
// and a fallback, not a replacement — it 404s on transactions WoC still has.
const bitailsBase = wocNet === 'main'
  ? 'https://api.bitails.io'
  : 'https://test-api.bitails.io'

async function bitailsUtxos (address) {
  const res = await fetch(`${bitailsBase}/address/${address}/unspent`)
  if (!res.ok) throw new Error(`Bitails ${res.status} for ${address}`)
  const j = await res.json()
  return (j.unspent || []).map(u => ({
    txId: u.txid, outputIndex: u.vout, satoshis: u.satoshis, height: u.blockheight
  }))
}

/**
 * UTXOs from whichever explorer answers. Returns the sources that responded so
 * a caller can tell "no coins" from "nobody would say".
 */
async function getUtxosAnySource (address) {
  const sources = []
  const rows = []
  for (const [name, fn] of [['whatsonchain', getUtxos], ['bitails', bitailsUtxos]]) {
    try {
      const got = await fn(address)
      sources.push(name)
      rows.push(...got)
    } catch (err) { /* try the next one */ }
  }
  const seen = new Set()
  const merged = rows.filter(u => {
    const k = `${u.txId}:${u.outputIndex}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return { rows: merged, sources }
}

module.exports = {
  call, getUtxos, getBalance, getRawTx, broadcast, bitailsUtxos, getUtxosAnySource
}
