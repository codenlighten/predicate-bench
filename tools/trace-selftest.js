#!/usr/bin/env node
'use strict'

const bsv = require('@smartledger/bsv')
const { trace } = require('../src/trace')
const O = bsv.Opcode

// The tracer is a diagnostic tool, so being confidently wrong is worse than
// being silent. It was: when the unlocking script completed and the locking
// script failed on its FIRST opcode, the failure was attributed to the unlocking
// script — it took the phase from the last recorded step, and the step listener
// only fires on success, so nothing from the locking script had been recorded.
//
// Four classes of failure land in four different places. Each is asserted here.

/** A locking script whose first chunk is a non-minimal one-byte push. */
function nonMinimalFirst () {
  const l = new bsv.Script()
  l.chunks.push({ buf: Buffer.from([0x02]), len: 1, opcodenum: 1 })
  const k = bsv.Script.fromBuffer(l.toBuffer())
  return k.add(O.OP_DROP).add(O.OP_DROP).add(O.OP_1)
}

const CASES = [
  {
    name: 'mid-script failure in the locking script',
    unlock: new bsv.Script(),
    lock: bsv.Script.fromASM('OP_1 OP_1 OP_EQUALVERIFY OP_2 OP_3 OP_EQUALVERIFY OP_1'),
    expect: { phase: 'lock', index: 5, inRange: true }
  },
  {
    name: 'first opcode of the locking script',
    unlock: new bsv.Script().add(O.OP_1).add(O.OP_1),
    lock: nonMinimalFirst(),
    expect: { phase: 'lock', index: 0, inRange: true }
  },
  {
    name: 'whole-script check applied before evaluation (SIGPUSHONLY)',
    unlock: new bsv.Script().add(O.OP_1).add(O.OP_NOP),
    lock: bsv.Script.fromASM('OP_1'),
    expect: { phase: 'unlock', inRange: false, whole: 'before' }
  },
  {
    name: 'whole-script check applied after evaluation (CLEANSTACK)',
    unlock: new bsv.Script().add(O.OP_1).add(O.OP_1),
    lock: bsv.Script.fromASM('OP_1'),
    expect: { phase: 'lock', inRange: false, whole: 'after' }
  }
]

let failed = 0
for (const c of CASES) {
  const r = trace(c.unlock, c.lock, { satoshis: 0 })
  const f = r.failedAt
  if (!f) { console.log(`FAIL  ${c.name}: expected a failure, script verified`); failed++; continue }

  const wrong = Object.entries(c.expect).filter(([k, v]) => f[k] !== v)
  if (wrong.length) {
    failed++
    console.log(`FAIL  ${c.name}`)
    for (const [k, v] of wrong) console.log(`        ${k}: expected ${v}, got ${f[k]}`)
  } else {
    console.log(`PASS  ${c.name}`)
  }
}

console.log(failed ? `\n${failed} tracer attribution failure(s)` : '\ntracer attributes all four failure classes correctly')
if (failed) process.exit(1)
