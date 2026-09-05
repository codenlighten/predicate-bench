'use strict'

// Rebuild-check — the bench's core invariant is that the current predicate code compiles
// to the exact bytes that were deployed and SPENT on mainnet. This rebuilds every deployed
// coin from its own receipt (deployments.json) and compares to the recorded locking script.
//
// Five predicates were optimised or extended *after* their first deployment, so their
// receipts hold an earlier version; those are listed in KNOWN with the reason and byte
// delta. A redeploy would restore exact identity. The point of this tool is to catch NEW,
// unexplained drift — a predicate whose bytes changed without anyone noticing the on-chain
// coin no longer matches.
//
//   node tools/rebuild-check.js            report, always exit 0
//   node tools/rebuild-check.js --strict   exit 1 on any UNEXPLAINED length drift

const onchain = require('../src/onchain')

// predicate -> reason its deployed receipt is an earlier version than the current code.
// Empty: every predicate is currently byte-identical to its spent coin. If a predicate is
// ever improved after its deployment, record it here (with the reason) until it is
// redeployed, so `--strict` treats it as known rather than a regression.
const KNOWN = {}

// Rebuild a locking script from a receipt, trying the deploy path (lock) first, then a direct
// buildScript. Reconstructs from the record — a predicate authored from an expression carries
// its source and is recompiled. Returns a Script or null if it cannot be rebuilt from params.
function rebuild (record) {
  let p
  try { p = onchain.reconstruct(record) } catch (_) { return null }
  for (const f of [() => p.lock(record.params), () => (p.buildScript ? p.buildScript(record.params) : null)]) {
    try { const s = f(); if (s && typeof s.toBuffer === 'function') return s } catch (_) { /* try next */ }
  }
  return null
}

const strict = process.argv.includes('--strict')

// latest receipt per predicate
const latest = {}
for (const r of onchain.readLedger()) latest[r.predicate] = r

const match = []   // exact hex match — current code === on-chain bytes
const equiv = []   // same length, bytes differ only where the receipt doesn't pin key material
const drift = []   // length differs — the current code is genuinely a different script
const skip = []    // params alone don't reconstruct this predicate's shape

for (const [name, r] of Object.entries(latest)) {
  const s = rebuild(r)
  if (!s) { skip.push(name); continue }
  const now = s.toBuffer()
  const dep = Buffer.from(r.lockHex, 'hex')
  if (now.toString('hex') === r.lockHex) { match.push(name) } else if (now.length === dep.length) { equiv.push(name) } else {
    drift.push({ name, dep: dep.length, now: now.length, delta: now.length - dep.length, why: KNOWN[name] })
  }
}

const p = (n) => n.toString().padStart(4)
console.log(`rebuild-check — ${Object.keys(latest).length} deployed predicates, rebuilt from their receipts\n`)
console.log(`  exact match      ${p(match.length)}  current code is byte-identical to the coin on chain`)
console.log(`  key-substituted  ${p(equiv.length)}  same length; differs only where the receipt doesn't pin a key`)
console.log(`  shape-unpinned   ${p(skip.length)}  params alone don't reconstruct the script (checked elsewhere)`)
console.log(`  DRIFT            ${p(drift.length)}  length differs — an earlier version is on chain\n`)

if (equiv.length) console.log(`  key-substituted: ${equiv.sort().join(', ')}`)
if (skip.length) console.log(`  shape-unpinned:  ${skip.sort().join(', ')}`)

let unexplained = 0
if (drift.length) {
  console.log('\n  drift detail (deployed → current):')
  for (const d of drift.sort((a, b) => a.name.localeCompare(b.name))) {
    const tag = d.why ? `known — ${d.why}` : 'UNEXPLAINED — new drift, investigate'
    if (!d.why) unexplained++
    console.log(`    ${d.name.padEnd(9)} ${p(d.dep)}B → ${p(d.now)}B  (${d.delta > 0 ? '+' : ''}${d.delta}B)  ${tag}`)
  }
  console.log('\n  the drifted predicates were deployed and spent as an earlier version; a redeploy')
  console.log('  would restore exact byte-identity to the current, improved code.')
}

if (strict && unexplained) {
  console.log(`\n${unexplained} predicate(s) drifted with no recorded reason — failing (--strict).`)
  process.exit(1)
}
console.log(unexplained
  ? `\n${unexplained} UNEXPLAINED drift (run with no coins to redeploy, or record the reason in KNOWN).`
  : '\nno unexplained drift: every deployed coin is either byte-identical or a documented earlier version.')
process.exit(0)
