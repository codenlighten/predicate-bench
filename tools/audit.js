#!/usr/bin/env node
'use strict'

const fs = require('fs')
const path = require('path')

// Documentation that quotes numbers goes stale silently.
//
// This session restructured the predicates three times and the main table in
// predicates.md kept its original byte counts through all of it — eight of ten
// rows were wrong, and nothing said so. Prose can be reviewed; numbers should be
// derived.
//
// Every predicate exports `example()`, so the true size is computable. This
// compares what the docs claim against what the code builds and what the suite
// actually runs. `--fix` rewrites the numbers.
//
// Deliberately narrow: it checks the LIVE table, not the historical ones in the
// sizing section. Those record what the sizes were at a particular step and are
// supposed to stay put.

// A lookup that runs out silently writes the word "undefined" into the README,
// which is worse than not fixing it. Every caller must fail loudly past the end —
// which it did, at twenty-one, so the table now spells the twenties too.
const ONES = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight',
  'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen',
  'seventeen', 'eighteen', 'nineteen']
const TENS = { 20: 'twenty', 30: 'thirty', 40: 'forty', 50: 'fifty' }
const WORDS = (() => {
  const out = ONES.slice()
  for (const t of [20, 30, 40, 50]) {
    out[t] = TENS[t]
    for (let u = 1; u <= 9; u++) out[t + u] = TENS[t] + '-' + ONES[u]
  }
  return out
})()

/** Markdown the auditor writes has to look hand-written, or nobody edits around it. */
function wrap (text, width = 80) {
  const lines = ['']
  for (const w of text.split(' ')) {
    const line = lines[lines.length - 1]
    if (line && (line + ' ' + w).length > width) lines.push(w)
    else lines[lines.length - 1] = line ? line + ' ' + w : w
  }
  return lines.join('\n')
}

const root = path.join(__dirname, '..')
const DOC = path.join(root, 'docs/predicates.md')
const README = path.join(root, 'README.md')

function actualSizes () {
  const dir = path.join(root, 'src/predicates')
  const out = {}
  for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.js'))) {
    const p = require(path.join(dir, f))
    if (typeof p.example !== 'function') { out[p.name] = { error: 'no example()' }; continue }
    try { out[p.name] = { bytes: p.lock(p.example()).toBuffer().length } } catch (e) { out[p.name] = { error: e.message } }
  }
  return out
}

/** Case counts read from the suite's data, not scraped from its output. */
/**
 * "Every predicate has been deployed and spent on BSV mainnet" was true when it
 * was written and quietly stopped being true three predicates later. Deployment
 * is a fact about the ledger, so derive the sentence from the ledger.
 */
function deployment () {
  const onchain = require(path.join(root, 'src/onchain'))
  const ledger = onchain.readLedger()
  const all = fs.readdirSync(path.join(root, 'src/predicates'))
    .filter(f => f.endsWith('.js')).map(f => f.replace('.js', '')).sort()
  const modules = new Set(all)
  // The catalogue count is the predicate MODULES. A coin authored from an expression carries
  // its own source (no module) — it counts toward the recorded outputs, not the catalogue.
  const live = new Set(ledger.filter(d => modules.has(d.predicate)).map(d => d.predicate))
  const expr = ledger.filter(d => !modules.has(d.predicate)).length
  return { live, absent: all.filter(n => !live.has(n)), n: all.length, outputs: ledger.length, expr }
}

function actualCases () {
  const { runs } = require(path.join(root, 'cases'))
  const counts = {}
  const refusals = {}
  let total = 0
  for (const [predicate, cases] of runs) {
    counts[predicate.name] = cases.length
    refusals[predicate.name] = cases.filter(c => c.shouldFail).length
    total += cases.length
  }
  return { counts, refusals, total }
}

/**
 * The bench's stated discipline is that a predicate is judged by what it
 * REFUSES. Nothing enforced that — a predicate could be added with only happy
 * paths and the suite would look just as green. These are the invariants the
 * discipline actually implies.
 */
function invariants (sizes, counts, refusals, doc) {
  const problems = []
  for (const name of Object.keys(sizes)) {
    // --fix rewrites rows that exist. A predicate with no row at all is
    // invisible to it, so the docs can silently fall a predicate behind — which
    // is how `rpuzzle` nearly shipped undocumented.
    if (doc && !new RegExp(`^\\| \`${name}\`\\ `, 'm').test(doc)) {
      problems.push(`${name}: no row in the predicates.md table`)
    }
    if (sizes[name].error) problems.push(`${name}: example() — ${sizes[name].error}`)
    if (!counts[name]) { problems.push(`${name}: no cases in the suite`); continue }
    if (!refusals[name]) {
      problems.push(`${name}: ${counts[name]} case(s) but NO refusal test — what does it reject?`)
    }
  }
  return problems
}

function main () {
  const fix = process.argv.includes('--fix')
  const sizes = actualSizes()
  const { counts, refusals, total } = actualCases()
  let problems = 0
  let fixed = 0

  let doc = fs.readFileSync(DOC, 'utf8')
  // The live table row: | `name` | NNN B | N | description |
  doc = doc.replace(/^\| `([a-z0-9]+)` \| (\d+) B \| (\d+) \| (.*)$/gm, (whole, name, bytes, cases, desc) => {
    const real = sizes[name]
    if (!real || real.error) { console.log(`  ? ${name}: ${real ? real.error : 'not found'}`); problems++; return whole }
    const okSize = Number(bytes) === real.bytes
    const okCases = Number(cases) === (counts[name] || 0)
    if (okSize && okCases) return whole
    problems++
    console.log(`  ${name.padEnd(10)} doc says ${bytes} B / ${cases} cases; actual ${real.bytes} B / ${counts[name] || 0} cases`)
    fixed++
    return `| \`${name}\` | ${real.bytes} B | ${counts[name] || 0} | ${desc}`
  })

  let readme = fs.readFileSync(README, 'utf8')
  const nPred = Object.keys(sizes).length
  const word = WORDS[nPred]
  if (!word) {
    console.log(`  cannot spell ${nPred} — extend WORDS in tools/audit.js`)
    problems++
  } else {
    // [\w-] not \w: the count words are hyphenated from twenty-one on, and a
    // bare \w stops at the hyphen, so the Status line silently escaped this
    // check the moment the bench passed twenty predicates.
    readme = readme.replace(/(\d+) cases, ([\w-]+) predicates, all green/g, (whole, c, p) => {
      if (Number(c) === total && p === word) return whole
      problems++; fixed++
      console.log(`  README says ${c} cases / ${p} predicates; actual ${total} / ${word}`)
      return `${total} cases, ${word} predicates, all green`
    })
  }

  const dep = deployment()
  const depWord = WORDS[dep.live.size]
  const totalWord = WORDS[dep.n]
  const MARK = /(<!-- audit:deployment -->\n)[\s\S]*?(\n<!-- \/audit -->)/
  if (!MARK.test(readme)) {
    console.log('  README has no <!-- audit:deployment --> block to keep current')
    problems++
  } else if (!depWord || !totalWord) {
    console.log(`  cannot spell ${dep.live.size}/${dep.n} — extend WORDS in tools/audit.js`)
    problems++
  } else {
    const names = dep.absent.map(n => `\`${n}\``)
    const list = names.length > 1
      ? names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1]
      : names[0]
    const sentence = dep.absent.length === 0
      ? `All ${totalWord} predicates have been deployed and spent on BSV mainnet.`
      : `${depWord[0].toUpperCase()}${depWord.slice(1)} of the ${totalWord} predicates have been ` +
        `deployed and spent on BSV mainnet; ${list} ` +
        `exist${dep.absent.length === 1 ? 's' : ''} only in the suite so far.`
    const claim = wrap(sentence + ' Every documented txid is verified against the ' +
      'chain rather than asserted: `npm run verify:chain` confirms all ' +
      dep.outputs + ' recorded outputs exist and match their recorded bytes.')
    readme = readme.replace(MARK, (whole, open_, close) => {
      const current = whole.slice(open_.length, whole.length - close.length)
      if (current === claim) return whole
      problems++; fixed++
      console.log(`  README deployment claim is stale — ${dep.live.size}/${dep.n} deployed, ${dep.outputs} outputs on record`)
      return open_ + claim + close
    })
  }

  // tooling.md quotes "Of N cases, M are refusals" in prose. It drifted from
  // 101/70 to a real 161/106 unnoticed, because nothing derived it. Now it does.
  const TOOLING = path.join(root, 'docs/tooling.md')
  const totalRefusals = Object.values(refusals).reduce((a, b) => a + b, 0)
  let tooling = fs.readFileSync(TOOLING, 'utf8')
  tooling = tooling.replace(/Of (\d+)\s+cases, (\d+) are refusals/, (whole, c, r) => {
    if (Number(c) === total && Number(r) === totalRefusals) return whole
    problems++; fixed++
    console.log(`  tooling.md says ${c} cases / ${r} refusals; actual ${total} / ${totalRefusals}`)
    return `Of ${total} cases, ${totalRefusals} are refusals`
  })

  if (fix) {
    fs.writeFileSync(DOC, doc)
    fs.writeFileSync(README, readme)
    fs.writeFileSync(TOOLING, tooling)
  }

  const inv = invariants(sizes, counts, refusals, doc)
  for (const p of inv) console.log(`  ${p}`)

  if (!problems && !inv.length) {
    console.log('documented numbers match the code')
    console.log(`every predicate has an example() and at least one refusal test`)
    return
  }
  // Two different kinds of failure, and only one of them is mechanical.
  if (problems) console.log(`\n${problems} stale number(s)${fix ? ' — rewritten' : '; run with --fix'}`)
  if (inv.length) console.log(`${inv.length} invariant violation(s) — --fix cannot write a missing test`)
  if (inv.length || (problems && !fix)) process.exit(1)
}

main()
