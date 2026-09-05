#!/usr/bin/env node
'use strict'

const fs = require('fs')
const path = require('path')
const cfg = require('../src/config')
const wallet = require('../src/wallet')
const onchain = require('../src/onchain')

const [cmd, ...args] = process.argv.slice(2)

// key=value pairs after the positional args become predicate params.
//
// Numeric-looking values are coerced. Everything off the command line is a
// string, and a predicate doing arithmetic on one gets silent nonsense rather
// than an error: `notBefore + 1` on "800000" is "8000001", which is a valid
// nLockTime 10x in the future. Hex is accepted for sequence numbers.
function parseParams (list) {
  const out = {}
  for (const a of list) {
    const i = a.indexOf('=')
    if (i <= 0) continue
    const key = a.slice(0, i)
    const raw = a.slice(i + 1)
    if (/^0x[0-9a-fA-F]+$/.test(raw)) out[key] = parseInt(raw, 16)
    else if (/^-?\d+$/.test(raw) && Number.isSafeInteger(Number(raw))) out[key] = Number(raw)
    else out[key] = raw
  }
  return out
}

const j = (o) => JSON.stringify(o, null, 2)

const commands = {
  async 'wallet:create' () {
    const r = wallet.create()
    // Print the address, never the WIF. A secret echoed to stdout lives on in
    // scrollback, in tmux buffers and in whatever is recording the session.
    console.log(j({ network: r.network, address: r.address, keyFile: cfg.walletFile }))
    console.log(`\nFund this address on ${cfg.network}, then: node bin/cli.js balance`)
    console.log(`The WIF in ${cfg.walletFile} is the only copy. Back it up before funding it.`)
  },

  async 'wallet:import' () {
    const [wif] = args
    if (!wif) throw new Error('usage: wallet:import <WIF>')
    const r = wallet.importWif(wif)
    console.log(j({ network: r.network, address: r.address }))
  },

  async 'wallet:show' () {
    const w = wallet.load()
    console.log(j({ network: w.network, address: w.address, publicKey: w.publicKey.toString() }))
  },

  async balance () {
    console.log(j(await wallet.balance()))
  },

  async utxos () {
    const u = await wallet.utxos()
    console.log(j(u.map(x => ({ txId: x.txId, vout: x.outputIndex, satoshis: x.satoshis }))))
    console.log(`${u.length} utxo(s), ${u.reduce((s, x) => s + x.satoshis, 0)} sats`)
  },

  async predicates () {
    const dir = path.join(__dirname, '..', 'src', 'predicates')
    for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.js'))) {
      const p = require(path.join(dir, f))
      console.log(`${p.name.padEnd(14)} ${p.describe || ''}`)
    }
  },

  async deploy () {
    const [name, ...rest] = args
    if (!name) throw new Error('usage: deploy <predicate> [key=value ...] [--dry-run]')
    const dryRun = rest.includes('--dry-run')
    const r = await onchain.deploy(name, parseParams(rest), { dryRun })
    console.log(j(r))
  },

  async unlock () {
    const [txid, ...rest] = args
    if (!txid) throw new Error('usage: unlock <txid> [key=value ...] [--dry-run] [--force]')
    const d = onchain.readLedger().find(x => x.txid === txid)
    if (!d) throw new Error(`no deployment recorded for ${txid} in ${onchain.LEDGER}`)
    const r = await onchain.unlock(d, parseParams(rest), {
      dryRun: rest.includes('--dry-run'),
      force: rest.includes('--force')
    })
    console.log(j(r))
  },

  async deployments () {
    console.log(j(onchain.readLedger()))
  }
}

const run = commands[cmd]
if (!run) {
  console.log(`smart contract ideation — network: ${cfg.network}\n`)
  console.log('  wallet:create              generate the funding key')
  console.log('  wallet:import <WIF>        use an existing funding key instead')
  console.log('  wallet:show                address and pubkey')
  console.log('  balance                    confirmed + unconfirmed')
  console.log('  utxos                      spendable outputs')
  console.log('  predicates                 list the scripts we have written')
  console.log('  deploy <name> [k=v ...]    lock sats behind a predicate on chain')
  console.log('  unlock <txid> [k=v ...]    spend it back (verified locally first)')
  console.log('  deployments                what we have put on chain')
  console.log('\n  npm test                   run every predicate against the interpreter, offline')
  process.exit(cmd ? 1 : 0)
}

run().catch(err => { console.error('error:', err.message); process.exit(1) })
