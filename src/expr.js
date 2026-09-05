'use strict'

// EXPRESSION COMPILER — author a NEW predicate from a condition, not by naming pre-built
// steps. Where src/tslang.js REPRODUCES the curated covenants (a class names STEPs from
// src/covsteps.js), this COMPILES logic — arithmetic, comparison, boolean, signatures, and
// now bounded loops over fixed-size data — into real Bitcoin Script.
//
// It is deliberately OURS, not sCrypt's: zero-dependency (a hand-written tokeniser +
// recursive-descent parser, not the TypeScript compiler), deterministic, and every opcode is
// emitted through the same StackAsm the mainnet covenants use — judged by the REAL consensus
// interpreter (via the harness), refusal tests and all. sCrypt's local verify() is a
// JavaScript port of the engine; ours is the block validator.
//
//   given sig pubkey
//   assert(eq(hash160(pubkey), this.owner))     // a P2PKH, authored from a condition
//   assert(checkSig(sig, pubkey))
//
//   given leaf                                  // Merkle membership: a bounded loop that
//   given sib[3]                                // unrolls, folding a proof into a root
//   given dir[3]
//   let h = leaf
//   for i in 3 {
//     h = if(dir[i], hash256(sib[i] ++ h), hash256(h ++ sib[i]))
//   }
//   assert(eq(h, this.root))
//
// lock(params) bakes this.* constants; unlock(witness) pushes the given values (and signs a
// PrivateKey witness over the real spending tx). The pair runs through src/harness.js.

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const { StackAsm } = require('./stackasm')
const Opcode = bsv.Opcode
const Script = bsv.Script
const n = helpers.scriptNum

// ---- tokenizer ------------------------------------------------------------------------
const TWO = ['==', '!=', '<=', '>=', '&&', '||', '++']
const ONE = ['<', '>', '+', '-', '*', '/', '%', '!', '(', ')', ',', '{', '}', '[', ']', '=']
function tokenize (src) {
  const toks = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (c === '\n') { toks.push({ t: 'nl' }); i++; continue }
    if (/\s/.test(c)) { i++; continue }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue }   // comment to EOL
    if (c === '0' && src[i + 1] === 'x') {
      let j = i + 2; while (j < src.length && /[0-9a-fA-F]/.test(src[j])) j++
      const hex = src.slice(i + 2, j)
      if (!hex.length || hex.length % 2) throw new Error(`expr: hex literal 0x${hex} needs whole bytes`)
      toks.push({ t: 'hex', v: hex }); i = j; continue
    }
    if (/[0-9]/.test(c)) {
      let j = i; while (j < src.length && /[0-9]/.test(src[j])) j++
      toks.push({ t: 'num', v: Number(src.slice(i, j)) }); i = j; continue
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i; while (j < src.length && /[A-Za-z0-9_.]/.test(src[j])) j++
      toks.push({ t: 'id', v: src.slice(i, j) }); i = j; continue
    }
    const two = src.slice(i, i + 2)
    if (TWO.includes(two)) { toks.push({ t: 'op', v: two }); i += 2; continue }
    if (ONE.includes(c)) { toks.push({ t: 'op', v: c }); i += 1; continue }
    throw new Error(`expr: unexpected character '${c}'`)
  }
  toks.push({ t: 'eof' })
  return toks
}

// ---- parser ---------------------------------------------------------------------------
// A stream cursor with newline-terminated simple statements and { } blocks for `for`.
function parser (toks) {
  let pos = 0
  const peek = () => toks[pos]
  const next = () => toks[pos++]
  const is = (v) => peek() && peek().v === v
  const eat = (v) => { const t = next(); if (!t || t.v !== v) throw new Error(`expr: expected '${v}' but got '${t ? (t.v ?? t.t) : 'end'}'`); return t }
  const skipNl = () => { while (peek() && peek().t === 'nl') pos++ }

  // ---- expressions (precedence climbing): || < && < cmp < ++ < add < mul < unary < primary
  function primary () {
    const t = next()
    if (!t) throw new Error('expr: unexpected end of expression')
    if (t.t === 'num') return { k: 'num', v: t.v }
    if (t.t === 'hex') return { k: 'hex', v: t.v }
    if (t.v === '(') { const e = or(); eat(')'); return e }
    if (t.t === 'id') {
      if (t.v === 'if' && is('(')) {                        // if(cond, a, b) — a conditional
        next(); const c = or(); eat(','); const a = or(); eat(','); const b = or(); eat(')')
        return { k: 'cond', c, a, b }
      }
      if (is('(')) {                                        // a function call
        next(); const args = []
        if (!is(')')) { args.push(or()); while (is(',')) { next(); args.push(or()) } }
        eat(')'); return { k: 'call', fn: t.v, args }
      }
      let node = t.v.startsWith('this.') ? { k: 'param', name: t.v.slice(5) }
        : (t.v.includes('.') ? (() => { throw new Error(`expr: '${t.v}' — only this.<name> may use a dot`) })()
          : { k: 'var', name: t.v })
      if (is('[')) { next(); const idx = or(); eat(']'); node = { k: 'index', base: node, idx } }   // arr[i]
      return node
    }
    throw new Error(`expr: unexpected token '${t.v ?? t.t}'`)
  }
  function unary () { if (is('!')) { next(); return { k: 'not', a: unary() } } return primary() }
  function lvl (ops, below) {
    let left = below()
    while (peek() && peek().t === 'op' && ops.includes(peek().v)) { const op = next().v; left = { k: 'bin', op, l: left, r: below() } }
    return left
  }
  const mul = () => lvl(['*', '/', '%'], unary)
  const add = () => lvl(['+', '-'], mul)
  const cat = () => lvl(['++'], add)
  const cmp = () => lvl(['==', '!=', '<', '<=', '>', '>='], cat)
  const and = () => lvl(['&&'], cmp)
  const or = () => lvl(['||'], and)

  // ---- statements
  function statement () {
    skipNl()
    const t = peek()
    if (!t || t.t === 'eof') return null
    if (t.v === 'given') {
      next()
      const decls = []
      while (peek() && peek().t === 'id') {
        const name = next().v
        let size
        if (is('[')) { next(); const s = next(); if (s.t !== 'num') throw new Error('expr: given array size must be a number'); size = s.v; eat(']') }
        decls.push({ name, size })
      }
      return { k: 'given', decls }
    }
    if (t.v === 'let') { next(); const name = eat0id(); eat('='); return { k: 'let', name, expr: or() } }
    if (t.v === 'for') {
      next(); const varName = eat0id(); if (!is('in')) eat('in'); next()
      const bt = next(); const count = bt.t === 'num' ? bt.v : (bt.v && bt.v.startsWith('this.') ? { param: bt.v.slice(5) } : (() => { throw new Error('expr: for-bound must be a number or this.<name>') })())
      skipNl(); eat('{')
      const body = []
      skipNl(); while (!is('}')) { const s = statement(); if (!s) throw new Error("expr: unterminated for-block"); body.push(s); skipNl() }
      eat('}')
      return { k: 'for', varName, count, body }
    }
    if (t.v === 'assert') { next(); eat('('); const e = or(); eat(')'); return { k: 'assert', expr: e } }
    // assignment: ident = expr
    if (t.t === 'id') { const name = next().v; eat('='); return { k: 'assign', name, expr: or() } }
    throw new Error(`expr: unrecognised statement starting at '${t.v ?? t.t}'`)
  }
  function eat0id () { const t = next(); if (!t || t.t !== 'id') throw new Error('expr: expected a name'); return t.v }

  const stmts = []
  let s
  while ((s = statement()) !== null) stmts.push(s)
  return stmts
}

// ---- codegen: each expression node leaves exactly one value on top of the StackAsm -----
const BIN = {
  '+': (a, l) => a.add(l), '-': (a, l) => a.sub(l), '*': (a, l) => a.mul(l), '/': (a, l) => a.div(l), '%': (a, l) => a.mod(l),
  '++': (a, l) => a.cat(l),
  '==': (a, l) => a.numEqual(l), '!=': (a, l) => a.op('OP_NUMNOTEQUAL', 2, [l]),
  '<': (a, l) => a.op('OP_LESSTHAN', 2, [l]), '<=': (a, l) => a.op('OP_LESSTHANOREQUAL', 2, [l]),
  '>': (a, l) => a.op('OP_GREATERTHAN', 2, [l]), '>=': (a, l) => a.op('OP_GREATERTHANOREQUAL', 2, [l]),
  '&&': (a, l) => a.op('OP_BOOLAND', 2, [l]), '||': (a, l) => a.op('OP_BOOLOR', 2, [l])
}
const CALL = {
  hash160: { arity: 1, emit: (a, l) => a.hash160(l) },
  hash256: { arity: 1, emit: (a, l) => a.hash256(l) },
  sha256: { arity: 1, emit: (a, l) => a.sha256(l) },
  eq: { arity: 2, emit: (a, l) => a.equal(l) },
  min: { arity: 2, emit: (a, l) => a.min(l) },
  max: { arity: 2, emit: (a, l) => a.max(l) },
  checkSig: { arity: 2, emit: (a, l) => a.op('OP_CHECKSIG', 2, [l]) }
}

function bakedPush (asm, v, name, ref) {
  // A Buffer param survives JSON (deployments.json) as { type:'Buffer', data:[...] }; a receipt
  // reconstructed from disk hands it back in that form, so accept it.
  if (v && v.type === 'Buffer' && Array.isArray(v.data)) v = Buffer.from(v.data)
  if (Buffer.isBuffer(v)) return asm.data(v, name)
  if (typeof v === 'number') return asm.num(v, name)
  if (typeof v === 'string' && /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return asm.data(Buffer.from(v, 'hex'), name)
  throw new Error(`expr: ${ref} must be a number, hex string, or Buffer`)
}

// Resolve an index expression to a compile-time integer (a loop constant or a literal).
function constIndex (node, env) {
  if (node.k === 'num') return node.v
  if (node.k === 'var' && node.name in env.loop) return env.loop[node.name]
  throw new Error('expr: an array index must be a compile-time constant (a loop variable or a number)')
}

function emit (node, asm, env) {
  const lbl = () => 't' + (env.ctr.n++)
  switch (node.k) {
    case 'num': asm.num(node.v, lbl()); return
    case 'hex': asm.data(Buffer.from(node.v, 'hex'), lbl()); return
    case 'var':
      if (node.name in env.loop) { asm.num(env.loop[node.name], lbl()); return }   // a bound loop constant
      asm.pick(node.name, lbl()); return
    case 'param': {
      if (!(node.name in env.params)) throw new Error(`expr: unbound this.${node.name}`)
      bakedPush(asm, env.params[node.name], lbl(), `this.${node.name}`)
      return
    }
    case 'index': {
      const i = constIndex(node.idx, env)
      if (node.base.k === 'param') {                       // this.arr[i] — a baked array
        const arr = env.params[node.base.name]
        if (!Array.isArray(arr)) throw new Error(`expr: this.${node.base.name} is not an array`)
        if (i < 0 || i >= arr.length) throw new Error(`expr: this.${node.base.name}[${i}] out of range (len ${arr.length})`)
        bakedPush(asm, arr[i], lbl(), `this.${node.base.name}[${i}]`)
        return
      }
      if (node.base.k === 'var') { asm.pick(node.base.name + i, lbl()); return }    // witness array sib[i] -> sibI
      throw new Error('expr: only a witness or this.<name> may be indexed')
    }
    case 'not': emit(node.a, asm, env); asm.op('OP_NOT', 1, [lbl()]); return
    case 'bin': emit(node.l, asm, env); emit(node.r, asm, env); BIN[node.op](asm, lbl()); return
    case 'cond': {                                         // if(c, a, b) -> OP_IF a OP_ELSE b OP_ENDIF
      emit(node.c, asm, env); asm.beginIf()
      emit(node.a, asm, env)
      asm.elseBranch()
      emit(node.b, asm, env)
      asm.endIf(); asm.rename(lbl())
      return
    }
    case 'call': {
      const def = CALL[node.fn]
      if (!def) throw new Error(`expr: unknown function '${node.fn}' (have: ${Object.keys(CALL).join(', ')})`)
      if (node.args.length !== def.arity) throw new Error(`expr: ${node.fn}() takes ${def.arity} argument(s), got ${node.args.length}`)
      node.args.forEach((a) => emit(a, asm, env))
      def.emit(asm, lbl())
      return
    }
    default: throw new Error(`expr: cannot compile node ${node.k}`)
  }
}

// Emit one statement into the locking script's StackAsm.
function execStmt (st, asm, env) {
  switch (st.k) {
    case 'given': return                                   // declared once, up front
    case 'let': emit(st.expr, asm, env); asm.rename(st.name); return
    case 'assign':
      emit(st.expr, asm, env)                              // new value on top (a temp)
      asm.roll(st.name); asm.drop()                        // remove the previous binding, wherever it sat
      asm.rename(st.name); return
    case 'assert': emit(st.expr, asm, env); asm.verify(); return
    case 'for': {
      const count = typeof st.count === 'number' ? st.count : env.params[st.count.param]
      if (!Number.isInteger(count) || count < 0) throw new Error(`expr: for-bound ${JSON.stringify(st.count)} did not resolve to a non-negative integer`)
      for (let i = 0; i < count; i++) {
        env.loop[st.varName] = i                           // a compile-time constant this iteration
        for (const inner of st.body) execStmt(inner, asm, env)
      }
      delete env.loop[st.varName]
      return
    }
    default: throw new Error(`expr: cannot compile statement ${st.k}`)
  }
}

// ---- the predicate: a source string -> a harness-compatible { lock, unlock } -----------
function compile (source) {
  const stmts = parser(tokenize(source))
  const givenDecls = []
  for (const s of stmts) if (s.k === 'given') givenDecls.push(...s.decls)
  // the flat witness list, arrays expanded to name0..name(N-1), bottom -> top
  const flat = []
  for (const d of givenDecls) {
    if (d.size === undefined) flat.push(d.name)
    else for (let i = 0; i < d.size; i++) flat.push(d.name + i)
  }
  if (!stmts.some((s) => s.k === 'assert')) throw new Error('expr: a predicate needs at least one assert()')

  // Fail fast, at compile time: an unknown function, a wrong arity, an undeclared witness or
  // variable, or an index of something that is not an array. A bad predicate never builds.
  const scalars = new Set(givenDecls.filter((d) => d.size === undefined).map((d) => d.name))
  const arrays = new Map(givenDecls.filter((d) => d.size !== undefined).map((d) => [d.name, d.size]))
  const known = new Set(scalars)
  const vExpr = (node) => {
    switch (node.k) {
      case 'num': case 'hex': case 'param': return
      case 'var': if (!known.has(node.name)) throw new Error(`expr: '${node.name}' is not a declared witness or variable`); return
      case 'index':
        if (node.base.k === 'param') { vExpr(node.idx); return }
        if (node.base.k === 'var') { if (!arrays.has(node.base.name)) throw new Error(`expr: '${node.base.name}' is not a declared witness array (declare 'given ${node.base.name}[N]')`); vExpr(node.idx); return }
        throw new Error('expr: only a witness or this.<name> may be indexed')
      case 'not': vExpr(node.a); return
      case 'bin': vExpr(node.l); vExpr(node.r); return
      case 'cond': vExpr(node.c); vExpr(node.a); vExpr(node.b); return
      case 'call': {
        const d = CALL[node.fn]
        if (!d) throw new Error(`expr: unknown function '${node.fn}' (have: ${Object.keys(CALL).join(', ')})`)
        if (node.args.length !== d.arity) throw new Error(`expr: ${node.fn}() takes ${d.arity} argument(s), got ${node.args.length}`)
        node.args.forEach(vExpr); return
      }
      default: throw new Error(`expr: cannot validate node ${node.k}`)
    }
  }
  const vStmts = (list) => {
    for (const st of list) {
      if (st.k === 'let') { vExpr(st.expr); known.add(st.name) } else if (st.k === 'assign') { if (!known.has(st.name)) throw new Error(`expr: '${st.name}' is assigned before it is introduced with 'let'`); vExpr(st.expr) } else if (st.k === 'assert') { vExpr(st.expr) } else if (st.k === 'for') { known.add(st.varName); vStmts(st.body) }
    }
  }
  vStmts(stmts)

  return {
    name: 'expr',
    given: flat,
    givenDecls,
    source,
    stmts,
    lock (params = {}) {
      const s = new Script()
      const asm = new StackAsm(s).given(flat.slice())
      const env = { params, loop: {}, ctr: { n: 0 } }
      for (const st of stmts) execStmt(st, asm, env)
      while (asm.main.length) asm.drop()                   // discard witness + accumulators
      asm.raw(Opcode.OP_1, 0, ['true'])                    // leave true (clean stack, per policy)
      return s
    },
    unlock (ctx = {}) {
      const s = new Script()
      const push = (v, name) => {
        if (v === undefined) throw new Error(`expr: unlock is missing witness '${name}'`)
        if (v instanceof bsv.PrivateKey) {
          if (typeof ctx.sign !== 'function') throw new Error(`expr: witness '${name}' is a key to sign, but no signing context was given (run it through the harness)`)
          s.add(ctx.sign(v, ctx.sighashType))
        } else if (Buffer.isBuffer(v)) s.add(v)
        else if (v instanceof bsv.PublicKey) s.add(v.toBuffer())
        else if (typeof v === 'number') s.add(n(v))
        else if (typeof v === 'string') s.add(Buffer.from(v, 'hex'))
        else throw new Error(`expr: witness '${name}' must be a number, hex string, Buffer, PublicKey, or (to sign) a PrivateKey`)
      }
      for (const d of givenDecls) {
        if (d.size === undefined) push(ctx[d.name], d.name)
        else {
          const arr = ctx[d.name]
          if (!Array.isArray(arr) || arr.length !== d.size) throw new Error(`expr: witness '${d.name}' must be an array of ${d.size}`)
          for (let i = 0; i < d.size; i++) push(arr[i], `${d.name}[${i}]`)
        }
      }
      return s
    }
  }
}

module.exports = { compile, tokenize, parse: (src) => parser(tokenize(src)) }
