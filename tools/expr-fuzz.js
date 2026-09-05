'use strict'

// Differential fuzz test for the expression compiler. For hundreds of RANDOM expressions over
// random inputs, it evaluates the expression two ways — a reference interpreter in JS that
// mirrors Script's integer/boolean semantics, and the compiled locking script run against the
// REAL consensus interpreter — and asserts they always agree. A single disagreement is a
// codegen bug (a precedence slip, a stack mismanagement, a sign error), caught here rather than
// on chain. Deterministic: a fixed seed, so CI reproduces the exact run.
//
// It covers the pure-stack fragment (arithmetic, comparison, boolean) where a faithful JS
// reference exists; signatures, hashing and loops are exercised by tools/expr-selftest.js.

const expr = require('../src/expr')
const { run } = require('../src/harness')

const SEED = 0x9e3779b9
const CASES = 400
const MAX_DEPTH = 4
const VARS = ['a', 'b', 'c']

// mulberry32 — a small, seeded PRNG so the run is identical everywhere.
function mulberry32 (seed) {
  return function () {
    seed |= 0; seed = seed + 0x6D2B79F5 | 0
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed)
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t
    return ((t ^ t >>> 14) >>> 0) / 4294967296
  }
}
const rnd = mulberry32(SEED)
const pick = (arr) => arr[Math.floor(rnd() * arr.length)]
const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1))

// ---- random expression generators -----------------------------------------------------
function genArith (depth) {
  if (depth <= 0 || rnd() < 0.4) return rnd() < 0.6 ? { k: 'var', name: pick(VARS) } : { k: 'num', v: int(0, 20) }
  return { k: 'bin', op: pick(['+', '-', '*']), l: genArith(depth - 1), r: genArith(depth - 1) }
}
function genBool (depth) {
  if (depth <= 0) return { k: 'bin', op: pick(['==', '!=', '<', '<=', '>', '>=']), l: genArith(2), r: genArith(2) }
  const roll = rnd()
  if (roll < 0.5) return { k: 'bin', op: pick(['==', '!=', '<', '<=', '>', '>=']), l: genArith(2), r: genArith(2) }
  if (roll < 0.8) return { k: 'bin', op: pick(['&&', '||']), l: genBool(depth - 1), r: genBool(depth - 1) }
  return { k: 'not', a: genBool(depth - 1) }
}

// ---- render to source, and a reference evaluator mirroring Script semantics ------------
function render (node) {
  switch (node.k) {
    case 'num': return String(node.v)
    case 'var': return node.name
    case 'not': return `!(${render(node.a)})`
    case 'bin': return `(${render(node.l)} ${node.op} ${render(node.r)})`
  }
}
function evalNode (node, env) {
  switch (node.k) {
    case 'num': return node.v
    case 'var': return env[node.name]
    case 'not': return evalNode(node.a, env) === 0 ? 1 : 0
    case 'bin': {
      const l = evalNode(node.l, env); const r = evalNode(node.r, env)
      switch (node.op) {
        case '+': return l + r
        case '-': return l - r
        case '*': return l * r
        case '==': return l === r ? 1 : 0
        case '!=': return l !== r ? 1 : 0
        case '<': return l < r ? 1 : 0
        case '<=': return l <= r ? 1 : 0
        case '>': return l > r ? 1 : 0
        case '>=': return l >= r ? 1 : 0
        case '&&': return (l !== 0 && r !== 0) ? 1 : 0     // OP_BOOLAND
        case '||': return (l !== 0 || r !== 0) ? 1 : 0     // OP_BOOLOR
      }
    }
  }
}

// ---- the differential loop -------------------------------------------------------------
let checked = 0; let accepted = 0; let rejected = 0
const failures = []
for (let i = 0; i < CASES; i++) {
  const ast = genBool(MAX_DEPTH)
  const src = `given ${VARS.join(' ')}\nassert(${render(ast)})`
  const env = { a: int(-100, 100), b: int(-100, 100), c: int(-100, 100) }
  const expected = evalNode(ast, env) !== 0
  let ok, err
  try {
    const p = expr.compile(src)
    const r = run(p, { ...env })
    ok = r.ok; err = r.error
  } catch (e) { failures.push({ src, env, note: 'compile/run threw: ' + e.message }); continue }
  checked++
  if (ok === expected) { expected ? accepted++ : rejected++ } else {
    failures.push({ src, env, expected, got: ok, err })
  }
}

console.log('expression compiler — differential fuzz (JS reference vs the consensus interpreter):')
console.log(`  ${checked} random expressions checked  (${accepted} accepted, ${rejected} refused — both exercised)`)
if (failures.length) {
  console.log(`\n  ${failures.length} DISAGREEMENT(S) — a codegen bug:`)
  for (const f of failures.slice(0, 10)) {
    console.log(`    ${f.note || `expected ${f.expected}, interpreter ${f.got}${f.err ? ' (' + f.err + ')' : ''}`}`)
    console.log(`      ${f.src.replace(/\n/g, ' ; ')}   with ${JSON.stringify(f.env)}`)
  }
  process.exit(1)
}
console.log('  every expression agrees with the interpreter — the codegen is faithful across the run.')
process.exit(0)
