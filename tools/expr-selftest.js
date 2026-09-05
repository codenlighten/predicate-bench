'use strict'

// The expression compiler is faithful only if a predicate authored from an EXPRESSION —
// arithmetic, comparison, boolean logic, built-ins — verifies on the REAL consensus
// interpreter, and REFUSES the cases it should. Same bar as every hand-written predicate:
// the refusal tests are the point. (src/expr.js — the leap from composing steps to
// compiling logic; sCrypt's local verify() is a JS port, this is the block validator.)

const bsv = require('@smartledger/bsv')
const expr = require('../src/expr')
const { suite } = require('../src/harness')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

// run a source string through the harness against the interpreter; every case must land as
// expected (shouldFail inverts). Reports one line per predicate.
function predicate (title, source, cases) {
  let allPass = true
  let detail = ''
  try {
    const p = expr.compile(source)
    for (const r of suite(p, cases)) {
      if (!r.passed) { allPass = false; detail += `\n        ✗ ${JSON.stringify(r.testCase)} → ${r.ok ? 'accepted' : r.error}` }
    }
    const size = p.lock(cases[0]).toBuffer().length
    ok(allPass, `${title}  (${cases.length} cases, ${size} B)${detail}`)
  } catch (e) { ok(false, `${title} — compile threw: ${e.message}`) }
}

console.log('predicates AUTHORED from an expression verify on the consensus interpreter, refusals and all:')

// arithmetic + a baked total
predicate('a + b == total', 'given a b\nassert(a + b == this.total)', [
  { a: 60, b: 40, total: 100 },
  { a: 60, b: 41, total: 100, shouldFail: true },
  { a: 100, b: 0, total: 100 }
])

// a range, two asserts
predicate('lo <= x <= hi', 'given x\nassert(x >= this.lo)\nassert(x <= this.hi)', [
  { x: 50, lo: 0, hi: 100 },
  { x: 0, lo: 0, hi: 100 },
  { x: 100, lo: 0, hi: 100 },
  { x: -1, lo: 0, hi: 100, shouldFail: true },
  { x: 101, lo: 0, hi: 100, shouldFail: true }
])

// boolean composition, precedence (&& binds tighter than ||)
predicate('(a>0 && b>0) || c==this.override', 'given a b c\nassert(a > 0 && b > 0 || c == this.override)', [
  { a: 1, b: 1, c: 0, override: 9 },
  { a: 0, b: 1, c: 9, override: 9 },
  { a: 0, b: 1, c: 3, override: 9, shouldFail: true }
])

// multiplication, subtraction, modulo
predicate('a*b - c == 0 && a % this.m == 0', 'given a b c\nassert(a * b - c == 0)\nassert(a % this.m == 0)', [
  { a: 6, b: 7, c: 42, m: 3 },
  { a: 6, b: 7, c: 41, m: 3, shouldFail: true },
  { a: 5, b: 7, c: 35, m: 3, shouldFail: true }
])

// min/max built-ins
predicate('min(a,b) == this.floor', 'given a b\nassert(min(a, b) == this.floor)', [
  { a: 5, b: 8, floor: 5 },
  { a: 8, b: 5, floor: 5 },
  { a: 8, b: 9, floor: 5, shouldFail: true }
])

// a hashlock authored from an expression — hash160 built-in + byte equality
{
  const secret = Buffer.from('open sesame')
  const h = bsv.crypto.Hash.sha256ripemd160(secret).toString('hex')
  predicate('eq(hash160(preimage), h) — a hashlock from one line', 'given preimage\nassert(eq(hash160(preimage), this.h))', [
    { preimage: secret, h },
    { preimage: Buffer.from('guess'), h, shouldFail: true }
  ])
}

// a sha256 commitment
{
  const data = Buffer.from('the answer is 42')
  const d = bsv.crypto.Hash.sha256(data).toString('hex')
  predicate('eq(sha256(x), d)', 'given x\nassert(eq(sha256(x), this.d))', [
    { x: data, d },
    { x: Buffer.from('nope'), d, shouldFail: true }
  ])
}

// negation
predicate('!(a == b)', 'given a b\nassert(!(a == b))', [
  { a: 1, b: 2 },
  { a: 2, b: 2, shouldFail: true }
])

// a real P2PKH, authored from an expression: ownership = hash160(pubkey)==owner AND a
// signature over the spending tx. The sig witness is a PrivateKey; unlock() signs it.
{
  const alice = bsv.PrivateKey.fromRandom()
  const bob = bsv.PrivateKey.fromRandom()
  const owner = bsv.crypto.Hash.sha256ripemd160(alice.toPublicKey().toBuffer())
  predicate('p2pkh from a condition: eq(hash160(pubkey), owner) && checkSig(sig, pubkey)',
    'given sig pubkey\nassert(eq(hash160(pubkey), this.owner))\nassert(checkSig(sig, pubkey))', [
      { sig: alice, pubkey: alice.toPublicKey().toBuffer(), owner },
      { sig: bob, pubkey: bob.toPublicKey().toBuffer(), owner, shouldFail: true },      // wrong owner
      { sig: bob, pubkey: alice.toPublicKey().toBuffer(), owner, shouldFail: true }     // forged pubkey → NULLFAIL
    ])
}

// pay-to-pubkey: a baked pubkey, only its holder's signature spends
{
  const k = bsv.PrivateKey.fromRandom()
  const wrong = bsv.PrivateKey.fromRandom()
  const pubkey = k.toPublicKey().toBuffer().toString('hex')
  predicate('p2pk: checkSig(sig, this.pubkey)', 'given sig\nassert(checkSig(sig, this.pubkey))', [
    { sig: k, pubkey },
    { sig: wrong, pubkey, shouldFail: true }
  ])
}

console.log('\nthe compiler REFUSES malformed source (a bad predicate never reaches the chain):')
const rejects = (title, source, re) => {
  try { expr.compile(source); ok(false, `${title} — compiled but should have thrown`) } catch (e) { ok(re.test(e.message), `${title} → “${e.message}”`) }
}
rejects('unknown function', 'given x\nassert(md5(x) == 0)', /unknown function 'md5'/)
rejects('wrong arity', 'given x\nassert(hash160(x, x) == 0)', /takes 1 argument/)
rejects('undeclared witness', 'given x\nassert(y == 0)', /'y' is not a declared witness/)
rejects('no assert', 'given x', /needs at least one assert/)
rejects('trailing tokens', 'given x\nassert(x + )', /expected|unexpected|trailing/)
try { expr.compile('given x\nassert(x == this.t)').lock({}); ok(false, 'lock without the baked param should throw') } catch (e) { ok(/unbound this\.t/.test(e.message), `unbound param at lock → “${e.message}”`) }

console.log(failed
  ? `\n${failed} failing`
  : '\nthe expression compiler holds: new predicates authored from logic, judged by the real interpreter')
process.exit(failed ? 1 : 0)
