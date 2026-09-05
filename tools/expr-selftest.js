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

// a COVENANT that reads the spending context: a timelock authored from an expression. The
// preimage is bound (OP_PUSH_TX), the input is required non-final (auto), and nLockTime is
// read unsigned and compared to the floor — the same soundness as the deployed `timelock`.
{
  const NB = 964000
  predicate('timelock (reads the spend): tx.locktime >= this.notBefore', 'assert(tx.locktime >= this.notBefore)', [
    { notBefore: NB, at: NB },
    { notBefore: NB, at: NB + 500 },
    { notBefore: NB, at: NB - 1, shouldFail: true },                        // too early
    { notBefore: NB, at: NB, sequenceNumber: 0xffffffff, shouldFail: true } // final input: nLockTime inert
  ])
  // …and it doesn't just behave like the deployed timelock — it IS it, byte for byte. The
  // expression reproduces the hand-tuned covenant already deployed and spent on mainnet.
  const tl = require('../src/predicates/timelock')
  ok(expr.compile('assert(tx.locktime >= this.notBefore)').lock({ notBefore: NB }).toHex() === tl.lock({ notBefore: NB }).toHex(),
    'tx.locktime >= this.notBefore → BYTE-IDENTICAL to the deployed timelock covenant (372 B, already on mainnet)')
}

// output binding: pay() commits the WHOLE output set (hashOutputs) — the spender chooses nothing
{
  const helpers = require('@smartledger/bsv/lib/covenant/helpers')
  const cov = require('../src/predicates/covenant')
  const elsewhere = [helpers.p2pkhOutput('18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if', 900)]
  const params = { payTo: '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS', payAmount: 900 }
  predicate('covenant: pay(this.payTo, this.payAmount)', 'pay(this.payTo, this.payAmount)', [
    params,
    { ...params, actualOutputs: elsewhere, shouldFail: true }   // redirected — hashOutputs mismatch
  ])
  ok(expr.compile('pay(this.payTo, this.payAmount)').lock(params).toHex() === cov.lock(params).toHex(),
    'pay(this.payTo, this.payAmount) → BYTE-IDENTICAL to the deployed covenant (384 B, already on mainnet)')

  // COMPOSE two covenant primitives into one not in the catalogue: a time-locked payment vault
  const NB = 964000
  const base = { dest: '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS', amount: 900, notBefore: NB }
  predicate('vault (pay ∧ timelock): pay(dest, amount); assert(tx.locktime >= notBefore)',
    'pay(this.dest, this.amount)\nassert(tx.locktime >= this.notBefore)', [
      { ...base, at: NB + 50 },
      { ...base, at: NB - 1, shouldFail: true },                                  // too early
      { ...base, at: NB, actualOutputs: elsewhere, shouldFail: true },            // redirected
      { ...base, at: NB, sequenceNumber: 0xffffffff, shouldFail: true }           // final input
    ])
}

// self-recreation: recreate() forwards the coin into another instance of this exact covenant
{
  const helpers = require('@smartledger/bsv/lib/covenant/helpers')
  const perp = require('../src/predicates/perpetual')
  const stranger = [helpers.p2pkhOutput(bsv.PrivateKey.fromRandom().toAddress(), 800)]
  predicate('perpetual: recreate(this.hopFee)', 'recreate(this.hopFee)', [
    { hopFee: 150 },
    { hopFee: 150, actualOutputs: stranger, shouldFail: true }   // does not recreate the covenant
  ])
  ok(expr.compile('recreate(this.hopFee)').lock({ hopFee: 150 }).toHex() === perp.lock({ hopFee: 150 }).toHex(),
    'recreate(this.hopFee) → BYTE-IDENTICAL to the deployed perpetual covenant (385 B, already on mainnet)')

  // compose again: a perpetual that may advance only after a height (recreate ∧ timelock)
  const NB = 964000
  const g = { hopFee: 150, notBefore: NB }
  predicate('time-gated perpetual (recreate ∧ timelock)', 'recreate(this.hopFee)\nassert(tx.locktime >= this.notBefore)', [
    { ...g, at: NB + 10 },
    { ...g, at: NB - 1, shouldFail: true },
    { ...g, at: NB, sequenceNumber: 0xffffffff, shouldFail: true }
  ])
}

// m-of-n multisig: a threshold of signatures, checked in pubkey order (NULLDUMMY dummy)
{
  const keys = [0, 1, 2].map(() => bsv.PrivateKey.fromRandom())
  const pubkeys = keys.map((k) => k.toPublicKey().toBuffer())
  const wrong = bsv.PrivateKey.fromRandom()
  predicate('2-of-3 multisig: checkMultiSig(sig, this.pubkeys)', 'given sig[2]\nassert(checkMultiSig(sig, this.pubkeys))', [
    { sig: [keys[0], keys[1]], pubkeys },
    { sig: [keys[0], keys[2]], pubkeys },
    { sig: [keys[1], keys[0]], pubkeys, shouldFail: true },   // right keys, wrong order
    { sig: [keys[0], wrong], pubkeys, shouldFail: true }      // an impostor
  ])
}

// bounded loops that unroll: a hash chain folds a fixed number of items into a commitment
{
  const H = (b) => bsv.crypto.Hash.sha256sha256(b)
  const seed = H(Buffer.from('genesis'))
  const items = [H(Buffer.from('a')), H(Buffer.from('b')), H(Buffer.from('c'))]
  let h = seed
  for (const it of items) h = H(Buffer.concat([h, it]))
  const commit = h
  predicate('hash chain: fold 3 items, for i in 3 { h = hash256(h ++ item[i]) }',
    'given seed\ngiven item[3]\nlet h = seed\nfor i in 3 {\n  h = hash256(h ++ item[i])\n}\nassert(eq(h, this.commit))', [
      { seed, item: items, commit },
      { seed, item: [items[0], items[1], H(Buffer.from('z'))], commit, shouldFail: true }
    ])
}

// a real Merkle membership proof: an unrolled loop with a runtime direction (if/else per level)
{
  const H = (b) => bsv.crypto.Hash.sha256sha256(b)
  const leaves = Array.from({ length: 8 }, (_, i) => H(Buffer.from('leaf' + i)))
  const idx = 5
  let level = leaves.slice(); let j = idx
  const sib = []; const dir = []
  while (level.length > 1) {
    const right = j & 1
    sib.push(level[right ? j - 1 : j + 1]); dir.push(right ? 1 : 0)
    const nxt = []; for (let k = 0; k < level.length; k += 2) nxt.push(H(Buffer.concat([level[k], level[k + 1]])))
    level = nxt; j = j >> 1
  }
  const root = level[0]
  predicate('Merkle proof: for i in 3 { h = if(dir[i], hash256(sib[i] ++ h), hash256(h ++ sib[i])) }',
    'given leaf\ngiven sib[3]\ngiven dir[3]\nlet h = leaf\nfor i in 3 {\n  h = if(dir[i], hash256(sib[i] ++ h), hash256(h ++ sib[i]))\n}\nassert(eq(h, this.root))', [
      { leaf: leaves[idx], sib, dir, root },
      { leaf: H(Buffer.from('forged')), sib, dir, root, shouldFail: true },
      { leaf: leaves[idx], sib: [sib[0], sib[1], H(Buffer.from('x'))], dir, root, shouldFail: true }
    ])
}

console.log('\nthe compiler REFUSES malformed source (a bad predicate never reaches the chain):')
const rejects = (title, source, re) => {
  try { expr.compile(source); ok(false, `${title} — compiled but should have thrown`) } catch (e) { ok(re.test(e.message), `${title} → “${e.message}”`) }
}
rejects('unknown function', 'given x\nassert(md5(x) == 0)', /unknown function 'md5'/)
rejects('wrong arity', 'given x\nassert(hash160(x, x) == 0)', /takes 1 argument/)
rejects('undeclared witness', 'given x\nassert(y == 0)', /'y' is not a declared witness/)
rejects('index of a non-array', 'given x\nassert(x[0] == 0)', /not a declared witness array/)
rejects('assign before let', 'given x\nh = x\nassert(h == 0)', /assigned before it is introduced with 'let'/)
rejects('no assert', 'given x', /needs at least one assert/)
rejects('trailing tokens', 'given x\nassert(x + )', /expected|unexpected|trailing/)
try { expr.compile('given x\nassert(x == this.t)').lock({}); ok(false, 'lock without the baked param should throw') } catch (e) { ok(/unbound this\.t/.test(e.message), `unbound param at lock → “${e.message}”`) }

console.log(failed
  ? `\n${failed} failing`
  : '\nthe expression compiler holds: new predicates authored from logic, judged by the real interpreter')
process.exit(failed ? 1 : 0)
