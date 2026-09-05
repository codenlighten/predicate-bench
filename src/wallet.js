'use strict'

const fs = require('fs')
const bsv = require('@smartledger/bsv')
const cfg = require('./config')
const woc = require('./woc')

function exists () {
  return fs.existsSync(cfg.walletFile)
}

// The key file is the wallet. It is written 0600 and gitignored; there is no
// second copy anywhere, so `backup` before funding it with anything real.
function create () {
  if (exists()) throw new Error(`refusing to overwrite existing wallet at ${cfg.walletFile}`)
  const key = bsv.PrivateKey.fromRandom(cfg.network)
  const record = {
    network: cfg.network,
    wif: key.toWIF(),
    address: key.toAddress().toString(),
    createdAt: new Date().toISOString()
  }
  fs.writeFileSync(cfg.walletFile, JSON.stringify(record, null, 2), { mode: 0o600 })
  fs.chmodSync(cfg.walletFile, 0o600)
  return record
}

// Import rather than generate, when the funding key already exists elsewhere.
function importWif (wif) {
  if (exists()) throw new Error(`refusing to overwrite existing wallet at ${cfg.walletFile}`)
  const key = bsv.PrivateKey.fromWIF(wif)
  if (key.network.name !== cfg.network) {
    throw new Error(`that WIF is a ${key.network.name} key but BSV_NETWORK resolves to ${cfg.network}`)
  }
  const record = {
    network: cfg.network,
    wif: key.toWIF(),
    address: key.toAddress().toString(),
    importedAt: new Date().toISOString()
  }
  fs.writeFileSync(cfg.walletFile, JSON.stringify(record, null, 2), { mode: 0o600 })
  fs.chmodSync(cfg.walletFile, 0o600)
  return record
}

function load () {
  if (!exists()) throw new Error(`no wallet at ${cfg.walletFile} — run: node bin/cli.js wallet:create`)
  const record = JSON.parse(fs.readFileSync(cfg.walletFile, 'utf8'))
  if (record.network !== cfg.network) {
    throw new Error(
      `wallet is a ${record.network} wallet but BSV_NETWORK resolves to ${cfg.network}`
    )
  }
  const privateKey = bsv.PrivateKey.fromWIF(record.wif)
  return {
    ...record,
    privateKey,
    publicKey: privateKey.publicKey,
    addressObj: privateKey.toAddress()
  }
}

function loadOrCreate () {
  return exists() ? load() : (create(), load())
}

async function balance () {
  const w = load()
  const b = await woc.getBalance(w.address)
  return { address: w.address, ...b, total: (b.confirmed || 0) + (b.unconfirmed || 0) }
}

// Outpoints we have already spent, as "txid:vout".
//
// WhatsOnChain's unspent index lags mempool spends: an output consumed by a
// transaction sitting in the mempool keeps appearing as spendable for a while.
// Building from that list produces a transaction that double-spends an input
// already committed, which the node rejects with txn-mempool-conflict. Since
// this wallet has exactly one spender, a local record is both accurate and
// immediate. Entries are never removed — an outpoint does not become unspent.
const spentFile = () => cfg.walletFile.replace(/\.json$/, '') + '.spent.json'

function readSpent () {
  const f = spentFile()
  return fs.existsSync(f) ? new Set(JSON.parse(fs.readFileSync(f, 'utf8'))) : new Set()
}

// Outputs of our own broadcasts that pay this wallet.
//
// WhatsOnChain's unspent list does not merely lag, it flaps: three consecutive
// calls returned the stale set, then the correct set, then an empty one. A
// build that happens to land on an empty response reports "no UTXOs" for a
// funded wallet. We know exactly what we created, so record it and stop
// asking. WoC is still merged in, for coins that arrive from elsewhere.
const outputsFile = () => cfg.walletFile.replace(/\.json$/, '') + '.utxos.json'

function readOwnOutputs () {
  const f = outputsFile()
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : []
}

/** Record any outputs of a broadcast transaction that pay this wallet. */
function recordOutputs (tx) {
  const w = load()
  const mine = bsv.Script.buildPublicKeyHashOut(w.addressObj).toHex()
  const known = readOwnOutputs()
  const seen = new Set(known.map(u => `${u.txId}:${u.outputIndex}`))
  tx.outputs.forEach((o, i) => {
    if (o.script.toHex() !== mine) return
    const key = `${tx.id}:${i}`
    if (seen.has(key)) return
    known.push({ txId: tx.id, outputIndex: i, satoshis: o.satoshis, at: new Date().toISOString() })
  })
  fs.writeFileSync(outputsFile(), JSON.stringify(known, null, 2), { mode: 0o600 })
  return known
}

/** Record every input of a transaction we have just broadcast. */
function recordSpent (tx) {
  const spent = readSpent()
  for (const input of tx.inputs) {
    spent.add(`${input.prevTxId.toString('hex')}:${input.outputIndex}`)
  }
  fs.writeFileSync(spentFile(), JSON.stringify([...spent], null, 2), { mode: 0o600 })
  return spent
}

// UnspentOutputs the Transaction builder can consume directly. The script is
// derived from our own address rather than trusted from the API response.
async function utxos ({ includeSpent = false } = {}) {
  const w = load()
  const script = bsv.Script.buildPublicKeyHashOut(w.addressObj).toString()
  // Ask every explorer that will answer. If none does, say so rather than
  // silently reporting an empty wallet — "no coins" and "nobody would tell me"
  // look identical to a caller and lead to very different mistakes.
  const { rows, sources } = await woc.getUtxosAnySource(w.address)
  if (!sources.length && !readOwnOutputs().length) {
    throw new Error('no explorer answered and no local record exists — cannot enumerate UTXOs')
  }

  // The local own-output cache only exists to bridge UNCONFIRMED change between
  // back-to-back transactions; once an output confirms, the chain reports it, and
  // once it is spent, both should forget it. But recordSpent only sees inputs of
  // transactions we broadcast, so an output spent by anything else (a covenant
  // recreating itself, a spend from another machine) lingers in the cache and gets
  // offered as an input — which the network rejects with "Missing inputs". So when
  // the chain has answered, keep a cached entry only if the chain still lists it
  // unspent, or it is recent enough to be genuinely unconfirmed. Stale entries are
  // pruned from disk in passing, so the cache self-heals instead of growing forever.
  const OWN_CACHE_TTL_MS = 30 * 60 * 1000
  const chainSet = new Set(rows.map(u => `${u.txId}:${u.outputIndex}`))
  const own = readOwnOutputs()
  const freshOwn = sources.length
    ? own.filter(u => chainSet.has(`${u.txId}:${u.outputIndex}`) ||
        (u.at && Date.now() - Date.parse(u.at) < OWN_CACHE_TTL_MS))
    : own
  if (sources.length && freshOwn.length !== own.length) {
    fs.writeFileSync(outputsFile(), JSON.stringify(freshOwn, null, 2), { mode: 0o600 })
  }

  const spent = includeSpent ? new Set() : readSpent()
  const byOutpoint = new Map()
  for (const u of [...rows, ...freshOwn]) {
    const key = `${u.txId}:${u.outputIndex}`
    if (spent.has(key) || byOutpoint.has(key)) continue
    byOutpoint.set(key, u)
  }

  return [...byOutpoint.values()].map(u => new bsv.Transaction.UnspentOutput({
    txId: u.txId,
    outputIndex: u.outputIndex,
    satoshis: u.satoshis,
    address: w.address,
    script
  }))
}

module.exports = { exists, create, importWif, load, loadOrCreate, balance, utxos, recordSpent, readSpent, recordOutputs, readOwnOutputs }
