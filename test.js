'use strict'

const { suite } = require('./src/harness')
const { runs } = require('./cases')


let failed = 0
for (const [predicate, cases] of runs) {
  for (const r of suite(predicate, cases)) {
    const mark = r.passed ? 'PASS' : 'FAIL'
    if (!r.passed) failed++
    console.log(`${mark}  ${r.name}`)
    console.log(`      ${r.lockSize}B lock / ${r.unlockSize}B unlock${r.error ? '  → ' + r.error : ''}`)

    // A case that should have spent but did not is the one worth explaining.
    // Re-run it under the tracer and print where in the script it stopped —
    // otherwise the whole report is an error constant and a byte count.
    if (!r.passed && !r.shouldFail) {
      const { traceCase, explain } = require('./src/trace')
      console.log(explain(traceCase(r.predicate, r.testCase))
        .split('\n').map(l => '      ' + l).join('\n'))
    }
  }
}
console.log(failed ? `\n${failed} failing` : '\nall green')
process.exit(failed ? 1 : 0)
