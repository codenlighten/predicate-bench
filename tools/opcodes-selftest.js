'use strict'

// The opcode layer is trustworthy only if it covers EXACTLY the opcode set the library
// (and thus the interpreter) supports — no gaps, no invented opcodes, every code matching.
// This reconciles our catalog against bsv.Opcode, so "the full opcode set is at our
// disposal" is a checked fact, and a node release that adds or removes an opcode makes
// this test fail rather than silently drift.

const bsv = require('@smartledger/bsv')
const { StackAsm } = require('../src/stackasm')
const op = require('../src/opcodes')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

const libNames = Object.keys(bsv.Opcode.map)
const catNames = op.CATALOG.map((o) => o.name)

console.log('the catalog reconciles with the library’s opcode table:')
ok(op.CATALOG.length === libNames.length, `every opcode is catalogued (${op.CATALOG.length} of ${libNames.length})`)
ok(libNames.every((n) => catNames.includes(n)), 'no library opcode is missing from the catalog')
ok(op.CATALOG.every((o) => bsv.Opcode.map[o.name] === o.code), 'every catalogued code matches the library')
ok(op.CATALOG.every((o) => o.hex === '0x' + o.code.toString(16).padStart(2, '0').toUpperCase()), 'every hex is well-formed')

console.log('\nthe honest annotations are present — the traps the bench proved on chain:')
ok(op.byName.OP_CHECKLOCKTIMEVERIFY.status === 'nop', 'OP_CHECKLOCKTIMEVERIFY is marked a NOP (pitfall 6)')
ok(op.byName.OP_CHECKSEQUENCEVERIFY.status === 'nop', 'OP_CHECKSEQUENCEVERIFY is marked a NOP')
ok(op.byName.OP_CODESEPARATOR.status === 'caution', 'OP_CODESEPARATOR is marked a caution (pitfall 7)')
ok(op.byName.OP_CAT.status === 'restored' && op.byName.OP_MUL.status === 'restored', 'OP_CAT and OP_MUL are marked restored-at-Genesis')
ok(!op.isActive('OP_CHECKLOCKTIMEVERIFY') && op.isActive('OP_CAT'), 'isActive() rejects the NOP, accepts the workhorse')

console.log('\nthe expert escape hatch emits any opcode by name:')
{
  const a = new StackAsm(new bsv.Script())
  a.op('OP_CAT', 2, ['joined'])
  const built = a.script().toBuffer()
  ok(built.length === 1 && built[0] === bsv.Opcode.map.OP_CAT, `StackAsm.op('OP_CAT') emits the OP_CAT byte (0x${built[0].toString(16)})`)
}
try { op.opcode('OP_DEFINITELY_NOT_REAL'); ok(false, 'an unknown opcode should throw') }
catch (e) { ok(/no opcode/.test(e.message), `an unknown opcode is refused — “${e.message}”`) }

console.log('\nby category:')
const cats = {}
for (const o of op.CATALOG) cats[o.category] = (cats[o.category] || 0) + 1
for (const [c, n] of Object.entries(cats).sort()) console.log(`  ${String(n).padStart(3)}  ${c}`)

console.log(failed
  ? `\n${failed} failing`
  : '\nthe opcode layer is complete: the full release set is catalogued, reconciled, annotated, and reachable by name')
process.exit(failed ? 1 : 0)
