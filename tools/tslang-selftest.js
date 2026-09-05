'use strict'

// The TypeScript frontend is faithful only if a `@contract` class, parsed and compiled,
// is byte-identical to the deployed predicate — the developer wrote familiar code, and
// out came the exact deployed Script. And the IR's soundness types must carry through:
// a contract that binds outputs without authenticating cannot compile.

const fs = require('fs')
const path = require('path')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const root = path.join(__dirname, '..')
const { build, check } = require(path.join(root, 'src/tslang'))
const src = (name) => fs.readFileSync(path.join(root, 'contracts', name + '.ts'), 'utf8')
const P = (name) => require(path.join(root, 'src/predicates', name))

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

console.log('@contract classes compile byte-identical to the deployed predicate (linear and branch):')
{
  const cov = P('covenant'); const ex = cov.example()
  const expected = PushTx.hashOutputs(cov.outputs(ex))
  ok(build(src('covenant'), { expected }).toHex() === cov.lock(ex).toHex(),
    'contracts/covenant.ts → covenant, byte-identical')
}
{
  const p = P('perpetual'); const ex = p.example()
  ok(build(src('perpetual'), { fee: ex.hopFee }).toHex() === p.lock(ex).toHex(),
    'contracts/perpetual.ts → perpetual, byte-identical')
}
{
  const t = P('timelock'); const ex = t.example()
  ok(build(src('timelock'), { notBefore: ex.notBefore }).toHex() === t.lock(ex).toHex(),
    'contracts/timelock.ts → timelock, byte-identical')
}

{
  const bsv = require('@smartledger/bsv')
  const m = P('metered'); const ex = m.example()
  const params = { state: m.counterBuf(ex.counter), maxHops: ex.maxHops, hopFee: ex.hopFee, settle: bsv.Address.fromString(ex.redeemTo) }
  ok(build(src('metered'), params).toHex() === m.lock(ex).toHex(),
    'contracts/metered.ts (a two-method branch class) → metered, byte-identical')
}
{
  // an asm branch: each side inherits its own @given stack and is @selfTerminating
  const { parse } = require(require('path').join(root, 'src/tslang'))
  const t = P('token')
  const spec = parse(src('token'), { balance: 300 })
  ok(spec.branch.style === 'asm' && spec.branch.if.epilogue === false && spec.branch.if.given.length === 6 && spec.branch.else.given.length === 3,
    `token.ts is an asm branch, each side @given + @selfTerminating (if ${spec.branch.if.given.length}g, else ${spec.branch.else.given.length}g)`)
  ok(build(src('token'), { balance: 300 }).toHex() === t.lock({ balance: 300 }).toHex(),
    'contracts/token.ts (an asm branch with per-side given) → token, byte-identical')
}
{
  // a single-path asm body behind an authenticate preamble (linear-asm) — the fifth shape
  const l = P('lineage')
  const G = l.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
  ok(build(src('lineage'), { genesis: G }).toHex() === l.buildScript({ genesis: G }).toHex(),
    'contracts/lineage.ts (a linear asm body, @preamble authenticate) → lineage, byte-identical')
}

console.log('\n@dispatch classes lower to a selector cascade (N cases, in method order):')
{
  const ADDR = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
  const { parse } = require(require('path').join(root, 'src/tslang'))
  const a = P('asset')
  const spec = parse(src('asset'), { owner: ADDR, balance: 500 })
  ok(spec.dispatch && spec.dispatch.cases.map((c) => c.selector).join(',') === '3,2,1,0',
    `asset.ts parses to a 4-case dispatch in order — [${spec.dispatch.cases.map((c) => c.selector).join(', ')}]`)
  ok(build(src('asset'), { owner: ADDR, balance: 500 }).toHex() === a.buildScript({ owner: ADDR, balance: 500 }).toHex(),
    'contracts/asset.ts (a four-way dispatch class) → asset, byte-identical')

  const so = P('sovereign')
  const G = Buffer.alloc(36, 7)
  ok(build(src('sovereign'), { genesis: G, owner: ADDR, balance: 500 }).toHex() === so.buildScript({ genesis: G, owner: ADDR, balance: 500 }).toHex(),
    'contracts/sovereign.ts (a three-way dispatch class) → sovereign, byte-identical')

  console.log('\nthe @state field layout is the source of the state bytes — the compiler owns the offsets:')
  ok(spec.layout && spec.layout.map((f) => `${f.name}:${f.type}`).join(', ') === 'owner:hash160, balance:u64',
    `asset.ts declares its layout — [${(spec.layout || []).map((f) => f.name + ':' + f.type).join(', ')}]`)
  // building from field VALUES gives the same state as the predicate's hand-written encoder
  ok(spec.state.equals(Buffer.concat([a.hash160Of(ADDR), a.balanceLE(500)])),
    'the layout encodes {owner, balance} to the exact state buffer (28 bytes)')
  // a field value out of range is refused at build time, not silently truncated
  let ranged = ''
  try { build(src('asset'), { owner: ADDR, balance: 2 ** 56 }) } catch (e) { ranged = e.message }
  ok(/balance/.test(ranged), `an out-of-range field value is refused — ${ranged.slice(0, 56) || 'NOT refused'}`)
}

// a dispatch method without @case(n) is a structural error, caught at parse time
{
  const bad = `@contract('nocase')\n@dispatch\nclass NoCase {\n  a() { finish() }\n  b() { finish() }\n}`
  let threw = false
  try { build(bad, {}) } catch (e) { threw = /@case/.test(e.message) }
  ok(threw, 'a @dispatch method missing @case(n) is refused')
}
// an uncurated call lowers to a step op of the same name; a typo is caught by the compiler
{
  const bad = `@contract('typo')\n@dispatch\nclass Typo {\n  @case(0) @given('x') a() { thisIsNotAStep() }\n}`
  let msg = ''
  try { build(bad, {}) } catch (e) { msg = e.message }
  ok(/E_UNKNOWN_STEP|thisIsNotAStep/.test(msg), `a mistyped step is rejected by the compiler — ${msg.slice(0, 60) || 'NOT rejected'}`)
}

console.log('\nthe soundness types carry through — an unsound contract will not compile:')
// binds outputs but never authenticates → the preimage is forgeable / outputs replayable
const unsound = `@contract('bad')
class Bad {
  spend() {
    requireOutputs(this.expected)
    finish()
  }
}`
const problems = check(unsound, { expected: Buffer.alloc(32) })
ok(problems.length > 0 && problems.some((p) => p.code === 'E_REPLAYABLE_OUTPUTS' || p.code === 'E_UNVERIFIED_PREIMAGE'),
  `a contract that binds outputs without authenticate() is rejected — ${problems.map((p) => p.code).join(', ') || 'NOT rejected'}`)

// the honest inverse: the real contracts type-check clean
ok(check(src('covenant'), { expected: Buffer.alloc(32) }).length === 0, 'covenant.ts type-checks clean')
ok(check(src('perpetual'), { fee: 250 }).length === 0, 'perpetual.ts type-checks clean')

console.log(failed
  ? `\n${failed} failing`
  : '\nthe TypeScript frontend is faithful: familiar code in, the exact deployed Script out, unsound code refused')
process.exit(failed ? 1 : 0)
