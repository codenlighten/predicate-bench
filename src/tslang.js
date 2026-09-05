'use strict'

const { compile, invariants } = require('./compile')
const { encodeState } = require('./statelayout')

// A TypeScript-flavoured surface for predicates — the ergonomic frontend the whole
// stack was built toward. A developer writes a familiar `@contract` class; the frontend
// parses a RESTRICTED, deterministic subset and lowers it to the same predicate IR that
// `.pred` text does, so the output is byte-identical to the deployed predicate. It is NOT
// a JavaScript interpreter: only the recognised contract vocabulary is accepted, and the
// compiler owns every opcode, offset and push encoding.
//
//   @contract('timelock')                     one method  → a linear predicate
//   class Timelock {
//     spend() { authenticate(); requireSequenceNonFinal(); requireLockTimeAtLeast(this.notBefore); finish() }
//   }
//
//   @contract('metered')                      two methods → a branch predicate
//   @state('$state')                          (first method = the `if` branch, second = `else`)
//   class Metered {
//     advance() { readCounterKeep({ head: 4, counter: 4 }); guardBelow(this.maxHops); incrementRecreate({ counter: 4, fee: this.hopFee }) }
//     expire()  { readCounterDrop({ head: 4, counter: 4 }); guardAtLeast(this.maxHops); payFixed(this.settle, this.hopFee) }
//   }
//
//   @contract('asset')                        @dispatch → a selector cascade (N cases)
//   @state('$state')                          each method is a @case(n) with its @given stack;
//   @dispatch                                 method order is the dispatch order.
//   class Asset {
//     @case(1) @given('ownerA, ownerB, ...') split() { assetExtractState(); assetSplitConserve(); ... }
//     @case(0) @given('newOwner, sig, ...')  transfer() { assetExtractState(); assetTransferSuccessor(); ... }
//   }
//
// A call the curated vocabulary doesn't name lowers to a step op of the same name, so the
// whole STEP registry is reachable from a class; the compiler rejects an unknown one.
//
// Parameters are `this.name` (or `$name` inside a decorator), bound at build time. The
// soundness type checks of the IR carry straight through: a contract that binds outputs
// without authenticating, or drops its exit, will not compile.

// the contract vocabulary → the IR step it lowers to. `args` names the step keys the
// call's positional arguments fill; `named:true` accepts an object literal whose keys
// (aliased) become step keys.
const CALLS = {
  // linear predicates
  authenticate: { op: 'auth' },
  authenticateOpen: { op: 'authOpen' },
  assertSighashAll: { op: 'assertSighashAll' },
  finish: { op: 'dropTrue' },
  finishBranch: { op: 'tokFinishBranch' },
  requireOutputs: { op: 'requireOutputs', args: ['expected'] },
  recreateSelfMinusFee: { op: 'recreateSelfMinusFee', args: ['fee'] },
  requireSequenceNonFinal: { op: 'timelockSeqNonFinal' },
  requireLockTimeAtLeast: { op: 'timelockAtLeast', args: ['floor'] },
  // metered — a branch state machine (a hop counter that expires)
  readCounterKeep: { op: 'meteredReadCounterKeep', named: true },
  readCounterDrop: { op: 'meteredReadCounterDrop', named: true },
  guardBelow: { op: 'meteredGuardBelow', args: ['max'] },
  guardAtLeast: { op: 'meteredGuardAtLeast', args: ['max'] },
  incrementRecreate: { op: 'meteredIncrementRecreate', named: true },
  payFixed: { op: 'meteredPayFixed', args: ['address', 'fee'] },
  // lifecycle — a status state machine (each coarse step is a whole issuer-signed branch)
  lifecycleTransition: { op: 'lifecycleTransition', named: true },
  lifecycleRetire: { op: 'lifecycleRetire', named: true },
  // turns — a two-player turn-based game (each coarse step is a whole branch)
  turnsMove: { op: 'turnsMove', named: true },
  turnsSettle: { op: 'turnsSettle', named: true }
}
const ARG_ALIASES = { head: 'headBytes', counter: 'counterBytes' }

function stripComments (src) { return src.replace(/\/\/[^\n]*/g, '') }

function decorator (src, name) {
  const m = src.match(new RegExp('@' + name + "\\s*\\(\\s*['\"]?([^'\")]+)['\"]?\\s*\\)"))
  if (m) return m[1].trim()
  return new RegExp('@' + name + '(?![\\w(])').test(src) ? true : undefined
}

function argValue (tok, params) {
  tok = tok.trim()
  const m = tok.match(/^this\.(\w+)$/)
  if (m) { if (!(m[1] in params)) throw new Error(`tslang: unbound parameter this.${m[1]}`); return params[m[1]] }
  const d = tok.match(/^\$(\w+)$/)
  if (d) { if (!(d[1] in params)) throw new Error(`tslang: unbound parameter $${d[1]}`); return params[d[1]] }
  if (/^-?\d+$/.test(tok)) return Number(tok)
  const s = tok.match(/^['"](.*)['"]$/)
  if (s) return s[1]
  throw new Error(`tslang: cannot read argument '${tok}'`)
}

// one statement → one IR step
function parseStep (stmt, params) {
  const call = stmt.match(/^(\w+)\s*\(([\s\S]*)\)$/)
  if (!call) throw new Error(`tslang: unrecognised statement '${stmt}'`)
  const def = CALLS[call[1]]
  // Fall back to the call name AS a direct step op: this is how the full curated STEP
  // vocabulary (assetExtractState, assetStride, …) becomes reachable from a class
  // without enumerating every one in CALLS. A typo lowers to an unknown op that the
  // compiler rejects cleanly (E_UNKNOWN_STEP). A raw step takes no arguments.
  const step = { op: def ? def.op : call[1] }
  const argstr = call[2].trim()
  if (argstr) {
    if (!def) throw new Error(`tslang: '${call[1]}(...)' is not a known contract call, and a raw step takes no arguments`)
    if (argstr[0] === '{') {
      for (const pair of argstr.replace(/^\{|\}$/g, '').split(',')) {
        if (!pair.trim()) continue
        const c = pair.indexOf(':')
        const key = pair.slice(0, c).trim()
        step[ARG_ALIASES[key] || key] = argValue(pair.slice(c + 1), params)
      }
    } else {
      const raw = argstr.split(',')
      ;(def.args || []).forEach((key, k) => { if (raw[k] !== undefined) step[key] = argValue(raw[k], params) })
    }
  }
  return step
}

function bodySteps (body, params) {
  const steps = []
  for (let stmt of body.split(/[\n;]+/)) { stmt = stmt.trim(); if (stmt) steps.push(parseStep(stmt, params)) }
  return steps
}

// the last value of a `@name(...)` decorator in a slice (the one nearest the method).
function lastDecorator (src, name) {
  const re = new RegExp('@' + name + "\\s*\\(\\s*['\"]?([^'\")]*)['\"]?\\s*\\)", 'g')
  let m; let last
  while ((m = re.exec(src))) last = m[1].trim()
  return last
}

// a `@given('a, b, c')` decorator → the named unlocking stack, bottom→top (or []).
function givenOf (deco) {
  const g = lastDecorator(deco, 'given')
  return g ? g.split(',').map((x) => x.trim()).filter(Boolean) : []
}

// the state field-layout declarations of a class: top-level `name: type` lines (brace
// depth 1 — inside the class body, outside any method). `@field` is accepted but optional.
// The compiler owns the encoding of these into the state buffer (see statelayout.js), so a
// class declares WHAT its state is, not the byte offsets.
function fieldDecls (src) {
  const out = []
  let depth = 0
  for (const rawline of src.split('\n')) {
    const line = rawline.trim()
    if (depth === 1 && !/[(){}]/.test(line)) {
      const m = line.match(/^(?:@field\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z]\w*)\s*;?\s*$/)
      if (m) out.push({ name: m[1], type: m[2] })
    }
    for (const ch of rawline) { if (ch === '{') depth++; else if (ch === '}') depth-- }
  }
  return out
}

// extract the top-level methods of the class body: [{ name, deco, body }], where `deco`
// is the source preceding the method signature — its per-method decorators (@case/@given).
function methods (src) {
  const out = []
  const re = /\b(\w+)\s*\([^)]*\)\s*\{/g
  let m; let prevEnd = 0
  while ((m = re.exec(src))) {
    if (m[1] === 'if' || m[1] === 'for' || m[1] === 'while' || m[1] === 'switch') continue
    const deco = src.slice(prevEnd, m.index)
    const start = m.index + m[0].length
    let depth = 1; let i = start
    for (; i < src.length && depth > 0; i++) { if (src[i] === '{') depth++; else if (src[i] === '}') depth-- }
    out.push({ name: m[1], deco, body: src.slice(start, i - 1) })
    re.lastIndex = i; prevEnd = i
  }
  return out
}

function parse (src, params = {}) {
  const clean = stripComments(src)
  let name = decorator(clean, 'contract')
  if (name === true || name === undefined) {
    const c = clean.match(/class\s+(\w+)/); if (!c) throw new Error('tslang: no @contract name and no class declaration')
    name = c[1].toLowerCase()
  }
  const spec = { name }
  const term = decorator(clean, 'terminates'); if (term !== undefined) spec.terminates = term === true ? 'terminates' : term
  const pre = decorator(clean, 'preamble'); if (pre !== undefined) spec.preamble = pre === true ? 'authenticate' : pre
  const st = decorator(clean, 'state')
  const fields = fieldDecls(clean)
  if (st !== undefined && st !== true) {
    spec.state = argValue(st, params)                 // @state('$buf') — a pre-built state buffer
  } else if (fields.length) {
    spec.layout = fields                              // field declarations — the compiler owns encoding
    spec.state = encodeState(fields, params)          // built from field VALUES in `params`, in order
  }

  const ms = methods(clean)
  if (!ms.length) throw new Error('tslang: no transition method found')

  // a @dispatch class: each method is a selector case, marked @case(n) with its @given
  // unlocking stack. Method order is the dispatch cascade order, preserved as written.
  if (decorator(clean, 'dispatch')) {
    spec.dispatch = {
      cases: ms.map((mm) => {
        const sel = lastDecorator(mm.deco, 'case')
        if (sel === undefined) throw new Error(`tslang: dispatch method ${mm.name}() needs a @case(n) decorator`)
        return { selector: Number(sel), given: givenOf(mm.deco), steps: bodySteps(mm.body, params) }
      })
    }
    return spec
  }

  // a single-method asm body: one path over the stack-tracking assembler, behind a leading
  // state field and (usually) an authenticate preamble, self-terminating (lineage). Marked
  // by @body('asm') or simply by carrying a @given stack.
  const bodyStyle = decorator(clean, 'body')
  if (ms.length === 1 && ((bodyStyle && bodyStyle !== true) || givenOf(ms[0].deco).length)) {
    const b = { style: (bodyStyle && bodyStyle !== true) ? bodyStyle : 'asm', steps: bodySteps(ms[0].body, params) }
    const g = givenOf(ms[0].deco); if (g.length) b.given = g
    if (/@selfTerminating(?![\w(])/.test(ms[0].deco)) b.epilogue = false
    spec.body = b
    return spec
  }

  if (ms.length === 1) {
    spec.body = bodySteps(ms[0].body, params)          // linear-raw
  } else if (ms.length === 2) {
    // two methods → a branch. `raw` bodies are plain clause lists (metered); an `asm` body
    // runs over the stack-tracking assembler, each side inheriting its own @given stack, and
    // @selfTerminating turns off the clean-stack epilogue because the body ends in its own
    // finish step (token).
    const style = decorator(clean, 'branch'); const s = (style && style !== true) ? style : 'raw'
    const side = (mm) => {
      const b = { steps: bodySteps(mm.body, params) }
      const g = givenOf(mm.deco); if (g.length) b.given = g
      if (/@selfTerminating(?![\w(])/.test(mm.deco)) b.epilogue = false
      return b
    }
    spec.branch = { style: s, if: side(ms[0]), else: side(ms[1]) }
  } else {
    throw new Error(`tslang: ${ms.length} methods — only one (linear) or two (branch) are supported so far`)
  }
  return spec
}

function build (src, params = {}) { return compile(parse(src, params)) }
function check (src, params = {}) { return invariants(parse(src, params)) }

module.exports = { parse, build, check, CALLS }
