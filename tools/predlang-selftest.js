#!/usr/bin/env node
'use strict'

const fs = require('fs')
const path = require('path')
const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const root = path.join(__dirname, '..')
const { build, parse, invariants } = require(path.join(root, 'src/predlang'))

// The surface language is faithful only if a `.pred` source, parsed and compiled,
// is byte-identical to the deployed predicate. This proves it for every predicate
// the compiler covers — the human wrote text, and out came the exact deployed
// Script. Parameters (a genesis, a fee, a commitment) are supplied here the way a
// caller would; the source describes the RULE, not the values.

const src = (name) => fs.readFileSync(path.join(root, 'predlang', name + '.pred'), 'utf8')
const P = (name) => require(path.join(root, 'src/predicates', name))

let failed = 0
function ok (cond, msg) { console.log((cond ? '  ok  ' : 'FAIL  ') + msg); if (!cond) failed++ }

const G = P('lineage').genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
const ADDR = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'

// covenant
{
  const cov = P('covenant'); const ex = cov.example()
  const expected = PushTx.hashOutputs(cov.outputs(ex))
  ok(build(src('covenant'), { expected }).toHex() === cov.lock(ex).toHex(),
    'covenant.pred parses and compiles byte-identical to the predicate')
}
// perpetual
{
  const p = P('perpetual'); const ex = p.example()
  ok(build(src('perpetual'), { fee: ex.hopFee }).toHex() === p.lock(ex).toHex(),
    'perpetual.pred parses and compiles byte-identical to the predicate')
}
// metered
{
  const m = P('metered'); const ex = m.example()
  const params = { state: m.counterBuf(ex.counter), maxHops: ex.maxHops, hopFee: ex.hopFee, settle: bsv.Address.fromString(ex.redeemTo) }
  ok(build(src('metered'), params).toHex() === m.lock(ex).toHex(),
    'metered.pred parses and compiles byte-identical to the predicate')
}
// vesting
{
  const v = P('vesting'); const ex = v.example()
  const params = { benPKH: ex.beneficiaryPKH, total: ex.total, start: ex.start, end: ex.end, fee: ex.fee, dust: 546 }
  ok(build(src('vesting'), params).toHex() === v.lock(ex).toHex(),
    'vesting.pred parses and compiles byte-identical to the predicate')
}
// token
{
  const t = P('token')
  ok(build(src('token'), { state: t.balanceLE(300) }).toHex() === t.lock({ balance: 300 }).toHex(),
    'token.pred parses and compiles byte-identical to the predicate')
}
// lineage
{
  const l = P('lineage')
  ok(build(src('lineage'), { state: G }).toHex() === l.buildScript({ genesis: G }).toHex(),
    'lineage.pred parses and compiles byte-identical to the predicate')
}
// provenance
{
  const pr = P('provenance')
  const state = Buffer.concat([G, pr.hash160Of(ADDR)])
  ok(build(src('provenance'), { state }).toHex() === pr.buildScript({ genesis: G, owner: ADDR }).toHex(),
    'provenance.pred parses and compiles byte-identical to the predicate')
}
// sovereign
{
  const so = P('sovereign')
  const state = Buffer.concat([G, so.hash160Of(ADDR), so.balanceLE(500)])
  ok(build(src('sovereign'), { state }).toHex() === so.buildScript({ genesis: G, owner: ADDR, balance: 500 }).toHex(),
    'sovereign.pred parses and compiles byte-identical to the predicate')
}

// timelock
{
  const tl = P("timelock"); const ex = tl.example()
  ok(build(src("timelock"), { notBefore: ex.notBefore }).toHex() === tl.lock(ex).toHex(),
    "timelock.pred parses and compiles byte-identical to the predicate")
}

// asset
{
  const a = P("asset")
  const state = Buffer.concat([a.hash160Of(ADDR), a.balanceLE(500)])
  ok(build(src("asset"), { state }).toHex() === a.buildScript({ owner: ADDR, balance: 500 }).toHex(),
    "asset.pred parses and compiles byte-identical to the predicate")
}

// the invariant pass carries through the language: a covenant.pred with the output
// binding but no authentication is refused at parse+compile, not emitted.
{
  const cov = P('covenant')
  const expected = PushTx.hashOutputs(cov.outputs(cov.example()))
  const bad = 'predicate bad { require-outputs expected=$expected finish }'
  const probs = invariants(parse(bad, { expected }))
  ok(probs.some((p) => p.code === 'E_UNVERIFIED_PREIMAGE'),
    'the invariant pass carries through: an unauthenticated .pred is refused')
}

if (failed) { console.log(`\n${failed} predlang-selftest failure(s)`); process.exit(1) }
console.log('\nevery predicate is expressible as text, and the text compiles to the deployed bytes')
