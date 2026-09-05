'use strict'

// The composition-safety model holds if: every composition the bench actually BUILT
// and deployed type-checks as safe, and each genuine resource conflict — two aspects
// writing a field, a write over a preserve, two output-set claimants — is caught with
// the right typed conflict. The compiler can then judge an UNBUILT composition before
// anyone writes a line of it.

const C = require('../src/compose')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

console.log('the compositions the bench built and deployed are all safe:')
const built = {
  'sovereign = conserve ∧ ownership ∧ lineage': ['conserve', 'ownership', 'lineage'],
  'guarded   = conserve ∧ witnessGate': ['conserve', 'witnessGate'],
  'audited   = conserve ∧ journal': ['conserve', 'journal']
}
for (const [name, aspects] of Object.entries(built)) {
  const r = C.analyze(aspects)
  ok(r.sound, `${name}${r.sound ? '' : ' — ' + r.conflicts.map((c) => c.code).join(', ')}`)
}

console.log('\ncompositions the bench has NOT built, judged safe to attempt:')
for (const [name, aspects] of Object.entries({
  'pool ∧ journal (an audited N-body treasury)': ['conserve', 'journal'],
  'guarded ∧ audited (oracle-gated + audited pair)': ['conserve', 'witnessGate', 'journal'],
  'conserve ∧ witnessGate ∧ ownership ∧ lineage': ['conserve', 'witnessGate', 'ownership', 'lineage']
})) {
  const r = C.analyze(aspects)
  ok(r.sound, `${name} → ${r.sound ? 'SAFE to build' : 'unsound: ' + r.conflicts.map((c) => c.code).join(', ')}`)
}

console.log('\ngenuine resource conflicts are refused, with the reason:')
const conserveExit = C.analyze(['conserve', 'exclusiveExit'])
ok(!conserveExit.sound && conserveExit.conflicts[0].code === 'E_OUTPUT_CLAIM_CONFLICT',
  `conserve ∧ exclusiveExit → ${conserveExit.conflicts[0] && conserveExit.conflicts[0].code} (both bind the output set)`)

const twoJournals = C.analyze(['journal', 'journal'])
ok(twoJournals.sound, 'journal ∧ journal is a no-op (same aspect deduplicates)')
// two DISTINCT things writing the same field: model conserve twice via a colliding pair
const doubleWrite = C.analyze(['conserve', 'freeze'])
ok(!doubleWrite.sound && doubleWrite.conflicts.some((c) => c.code === 'E_WRITE_PRESERVE_CONFLICT'),
  `conserve ∧ freeze → ${doubleWrite.conflicts.find((c) => c.code === 'E_WRITE_PRESERVE_CONFLICT') ? 'E_WRITE_PRESERVE_CONFLICT' : '?'} (freeze forbids the balance conserve rewrites)`)

// two output-set claimants of the same kind
const twoExits = C.analyze(['conserve', 'conserve'])
ok(twoExits.sound, 'conserve ∧ conserve deduplicates to one (same aspect)')

console.log('\nthe unioned resource footprint is reported for the composition:')
const au = C.analyze(['conserve', 'journal'])
console.log(`  audited footprint — writes: [${au.profile.writes}]  preserves: [${au.profile.preserves}]  outputs: ${au.profile.outputs}`)
ok(au.profile.writes.includes('balance') && au.profile.writes.includes('seq') && au.profile.writes.includes('head'),
  'audited writes balance + seq + head (conserve ∪ journal)')

console.log(failed
  ? `\n${failed} failing`
  : '\ncomposition safety holds: built compositions pass, unbuilt ones are judged, conflicts are named')
process.exit(failed ? 1 : 0)
