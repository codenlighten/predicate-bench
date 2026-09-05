'use strict'

const { compile, invariants } = require('./compile')

// A surface syntax for predicates — the human writes the RULE, the compiler emits
// the opcodes. A `.pred` source parses to a compile() spec; parameters (a genesis,
// a fee, a hashOutputs commitment) are referenced by `$name` and bound at parse
// time. The proof it is faithful is the same as everywhere in this bench: a parsed,
// compiled `.pred` is byte-identical to the deployed predicate (tools/predlang-selftest.js).
//
//   predicate covenant {
//     authenticate
//     require-outputs expected=$expected
//     finish
//   }
//
// The language is thin on purpose. A statement is one shared step; a few readable
// aliases (`authenticate`, `finish`, `require-outputs`) cover the common ones, and
// every other step is its own kebab-cased name. Structure — a leading `state`, a
// `branch`, a `dispatch`, or an `authenticate` preamble over an asm `body` — mirrors
// the four spec shapes the compiler already knows. No new Script; a front-end.

// readable statement aliases -> the step op the compiler runs
const ALIASES = {
  authenticate: 'auth',
  'authenticate-open': 'authOpen',
  'assert-sighash-all': 'assertSighashAll',
  'require-outputs': 'requireOutputs',
  'recreate-self-minus-fee': 'recreateSelfMinusFee',
  finish: 'dropTrue',
  'finish-branch': 'tokFinishBranch'
}
// readable argument names -> the step's param key
const ARG_ALIASES = { head: 'headBytes', counter: 'counterBytes' }

function kebabToCamel (s) {
  return s.split('-').map((p, i) => (i === 0 ? p : p[0].toUpperCase() + p.slice(1))).join('')
}

function tokenize (src) {
  return src
    .replace(/\/\/[^\n]*/g, ' ')                     // strip // comments
    .replace(/([{}(),])/g, ' $1 ')                    // isolate structural chars
    .split(/\s+/).filter(Boolean)
}

function parse (src, params = {}) {
  const t = tokenize(src)
  let i = 0
  const peek = () => t[i]
  const next = () => t[i++]
  const expect = (tok) => { const g = next(); if (g !== tok) throw new Error(`predlang: expected '${tok}', got '${g}'`) }

  const value = (tok) => {
    if (tok[0] === '$') {
      if (!(tok.slice(1) in params)) throw new Error(`predlang: unbound parameter ${tok}`)
      return params[tok.slice(1)]
    }
    if (/^-?\d+$/.test(tok)) return Number(tok)
    return tok
  }

  // a step: an op name, then `key=value` args until the next op or a delimiter
  const parseStep = () => {
    const raw = next()
    const op = ALIASES[raw] || kebabToCamel(raw)
    const step = { op }
    while (peek() && peek().includes('=') && peek() !== '=') {
      const [k, v] = next().split('=')
      step[ARG_ALIASES[k] || k] = value(v)
    }
    return step
  }
  const parseSteps = () => { const s = []; while (peek() && peek() !== '}') s.push(parseStep()); return s }

  const parseGiven = () => {
    if (peek() !== 'given') return undefined
    next(); expect('(')
    const names = []
    while (peek() !== ')') { const nm = next(); if (nm !== ',') names.push(nm) }
    expect(')')
    return names
  }

  const parseBranchBody = () => {
    const given = parseGiven()
    let epilogue
    if (peek() === 'self-terminating') { next(); epilogue = false }
    expect('{'); const steps = parseSteps(); expect('}')
    const body = { steps }
    if (given) body.given = given
    if (epilogue === false) body.epilogue = false
    return body
  }

  expect('predicate')
  const spec = { name: next() }
  while (peek() === 'terminates') { next(); spec.terminates = next() }
  expect('{')

  if (peek() === 'state') { next(); spec.state = value(next()) }
  if (peek() === 'preamble') { next(); spec.preamble = next() }

  const kind = peek()
  if (kind === 'branch') {
    next()
    const style = next()
    const given = parseGiven()
    expect('{')
    expect('if'); const ifBody = parseBranchBody()
    expect('else'); const elseBody = parseBranchBody()
    expect('}')
    spec.branch = { style, if: ifBody, else: elseBody }
    if (given) spec.branch.given = given
  } else if (kind === 'dispatch') {
    next(); expect('{')
    const cases = []
    while (peek() === 'case') {
      next()
      const selector = Number(next())
      const given = parseGiven()
      expect('{'); const steps = parseSteps(); expect('}')
      cases.push({ selector, given, steps })
    }
    expect('}')
    spec.dispatch = { cases }
  } else if (kind === 'body') {
    next()
    const style = next()
    const given = parseGiven()
    let epilogue
    if (peek() === 'self-terminating') { next(); epilogue = false }
    expect('{'); const steps = parseSteps(); expect('}')
    spec.body = { style, steps }
    if (given) spec.body.given = given
    if (epilogue === false) spec.body.epilogue = false
  } else {
    spec.body = parseSteps()                          // linear-raw: a plain statement list
  }

  expect('}')
  return spec
}

/** Parse a `.pred` source (with its parameters) and compile it to a locking Script. */
function build (src, params) {
  return compile(parse(src, params))
}

module.exports = { parse, build, invariants }
