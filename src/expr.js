'use strict'

// EXPRESSION COMPILER — author a NEW predicate from a condition, not by naming pre-built
// steps. Where src/tslang.js REPRODUCES the curated covenants (a class names STEPs from
// src/covsteps.js), this COMPILES arbitrary arithmetic / comparison / boolean logic over
// declared witness values and baked params into real Bitcoin Script — the leap from
// composing steps to compiling expressions, which is what a general contract language does.
//
// It is deliberately OURS, not sCrypt's: zero-dependency (a hand-written recursive-descent
// parser, not the TypeScript compiler), deterministic, and every opcode is emitted through
// the same StackAsm the mainnet covenants use — so there is no opaque compiler to trust, and
// the result is judged by the REAL consensus interpreter (via the harness), refusal tests and
// all, exactly like every other predicate here. sCrypt's local `verify()` is a JavaScript
// port of the engine; ours is the block validator.
//
//   given a b
//   assert(a + b == this.total)
//   assert(a > 0)
//
// lock({ total: 100 }) bakes 100 into the locking script; unlock({ a: 60, b: 40 }) pushes the
// witness. The pair is then run through src/harness.js against the consensus interpreter.

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const { StackAsm } = require('./stackasm')
const Opcode = bsv.Opcode
const Script = bsv.Script
const n = helpers.scriptNum

// ---- tokenizer ------------------------------------------------------------------------
const TWO = ['==', '!=', '<=', '>=', '&&', '||']
const ONE = ['<', '>', '+', '-', '*', '/', '%', '!', '(', ')', ',']
function tokenize (src) {
  const toks = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (/\s/.test(c)) { i++; continue }
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
  return toks
}

// ---- parser (recursive descent, precedence climbing) ----------------------------------
//   ||  <  &&  <  == != < <= > >=  <  + -  <  * / %  <  unary !  <  primary
function parse (toks) {
  let pos = 0
  const peek = () => toks[pos]
  const next = () => toks[pos++]
  const eat = (v) => { const t = next(); if (!t || t.v !== v) throw new Error(`expr: expected '${v}'`); return t }

  function primary () {
    const t = next()
    if (!t) throw new Error('expr: unexpected end of expression')
    if (t.t === 'num') return { k: 'num', v: t.v }
    if (t.t === 'hex') return { k: 'hex', v: t.v }
    if (t.v === '(') { const e = or(); eat(')'); return e }
    if (t.t === 'id') {
      if (peek() && peek().v === '(') {
        next()
        const args = []
        if (peek() && peek().v !== ')') { args.push(or()); while (peek() && peek().v === ',') { next(); args.push(or()) } }
        eat(')')
        return { k: 'call', fn: t.v, args }
      }
      if (t.v.startsWith('this.')) return { k: 'param', name: t.v.slice(5) }
      if (t.v.includes('.')) throw new Error(`expr: '${t.v}' — only this.<name> may use a dot`)
      return { k: 'var', name: t.v }
    }
    throw new Error(`expr: unexpected token '${t.v}'`)
  }
  function unary () { if (peek() && peek().v === '!') { next(); return { k: 'not', a: unary() } } return primary() }
  function level (ops, below) {
    let left = below()
    while (peek() && peek().t === 'op' && ops.includes(peek().v)) { const op = next().v; left = { k: 'bin', op, l: left, r: below() } }
    return left
  }
  const mul = () => level(['*', '/', '%'], unary)
  const add = () => level(['+', '-'], mul)
  const cmp = () => level(['==', '!=', '<', '<=', '>', '>='], add)
  const and = () => level(['&&'], cmp)
  const or = () => level(['||'], and)

  const e = or()
  if (pos !== toks.length) throw new Error(`expr: trailing tokens after expression`)
  return e
}

// ---- codegen: each node leaves exactly one value on top of the StackAsm ----------------
const BIN = {
  '+': (a, l) => a.add(l), '-': (a, l) => a.sub(l), '*': (a, l) => a.mul(l), '/': (a, l) => a.div(l), '%': (a, l) => a.mod(l),
  '==': (a, l) => a.numEqual(l), '!=': (a, l) => a.op('OP_NUMNOTEQUAL', 2, [l]),
  '<': (a, l) => a.op('OP_LESSTHAN', 2, [l]), '<=': (a, l) => a.op('OP_LESSTHANOREQUAL', 2, [l]),
  '>': (a, l) => a.op('OP_GREATERTHAN', 2, [l]), '>=': (a, l) => a.op('OP_GREATERTHANOREQUAL', 2, [l]),
  '&&': (a, l) => a.op('OP_BOOLAND', 2, [l]), '||': (a, l) => a.op('OP_BOOLOR', 2, [l])
}
// built-in functions. arity is what the parser saw; enforced so a typo cannot mis-compile.
const CALL = {
  hash160: { arity: 1, emit: (a, l) => a.hash160(l) },
  hash256: { arity: 1, emit: (a, l) => a.hash256(l) },
  sha256: { arity: 1, emit: (a, l) => a.sha256(l) },
  eq: { arity: 2, emit: (a, l) => a.equal(l) },              // byte-equality (OP_EQUAL)
  min: { arity: 2, emit: (a, l) => a.min(l) },
  max: { arity: 2, emit: (a, l) => a.max(l) },
  // checkSig(sig, pubkey) -> OP_CHECKSIG, leaving a boolean. The sig witness is a real
  // signature over the spending transaction; see unlock() — pass a PrivateKey and it signs.
  checkSig: { arity: 2, emit: (a, l) => a.op('OP_CHECKSIG', 2, [l]) }
}

function bakedPush (asm, v, name, ref) {
  if (Buffer.isBuffer(v)) return asm.data(v, name)
  if (typeof v === 'number') return asm.num(v, name)
  if (typeof v === 'string' && /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return asm.data(Buffer.from(v, 'hex'), name)
  throw new Error(`expr: ${ref} must be a number, hex string, or Buffer`)
}

function emit (node, asm, params, ctr) {
  const lbl = () => 't' + (ctr.n++)
  switch (node.k) {
    case 'num': asm.num(node.v, lbl()); return
    case 'hex': asm.data(Buffer.from(node.v, 'hex'), lbl()); return
    case 'var': asm.pick(node.name, lbl()); return
    case 'param': {
      if (!(node.name in params)) throw new Error(`expr: unbound this.${node.name}`)
      bakedPush(asm, params[node.name], lbl(), `this.${node.name}`)
      return
    }
    case 'not': emit(node.a, asm, params, ctr); asm.op('OP_NOT', 1, [lbl()]); return
    case 'bin': emit(node.l, asm, params, ctr); emit(node.r, asm, params, ctr); BIN[node.op](asm, lbl()); return
    case 'call': {
      const def = CALL[node.fn]
      if (!def) throw new Error(`expr: unknown function '${node.fn}' (have: ${Object.keys(CALL).join(', ')})`)
      if (node.args.length !== def.arity) throw new Error(`expr: ${node.fn}() takes ${def.arity} argument(s), got ${node.args.length}`)
      node.args.forEach((a) => emit(a, asm, params, ctr))
      def.emit(asm, lbl())
      return
    }
    default: throw new Error(`expr: cannot compile node ${node.k}`)
  }
}

// ---- the predicate: a source string -> a harness-compatible { lock, unlock } -----------
function compile (source) {
  let given = []
  const asserts = []
  for (const raw of source.split(/[\n;]+/)) {
    const line = raw.trim()
    if (!line) continue
    const g = line.match(/^given\s+(.+)$/)
    if (g) { given = g[1].split(/[\s,]+/).filter(Boolean); continue }
    const a = line.match(/^assert\s*\(([\s\S]*)\)$/)
    if (a) { asserts.push(parse(tokenize(a[1]))); continue }
    throw new Error(`expr: unrecognised line '${line}' (use 'given a b' or 'assert(<expr>)')`)
  }
  if (!asserts.length) throw new Error('expr: a predicate needs at least one assert()')

  // Fail fast: an unknown function, a wrong arity, or a reference to a witness that was never
  // declared is a compile-time error, not a surprise at lock() — a bad predicate never builds.
  const known = new Set(given)
  const walk = (node) => {
    if (node.k === 'call') {
      const def = CALL[node.fn]
      if (!def) throw new Error(`expr: unknown function '${node.fn}' (have: ${Object.keys(CALL).join(', ')})`)
      if (node.args.length !== def.arity) throw new Error(`expr: ${node.fn}() takes ${def.arity} argument(s), got ${node.args.length}`)
      node.args.forEach(walk)
    } else if (node.k === 'bin') { walk(node.l); walk(node.r) } else if (node.k === 'not') { walk(node.a) } else if (node.k === 'var' && !known.has(node.name)) {
      throw new Error(`expr: '${node.name}' is not a declared witness (given: ${given.join(' ') || 'none'})`)
    }
  }
  asserts.forEach(walk)

  return {
    name: 'expr',
    given,
    source,
    asserts,
    // Build the locking script: read the witness the unlocking script pushed, prove every
    // assertion, discard the witness, leave true (clean stack, as policy requires).
    lock (params = {}) {
      const s = new Script()
      const asm = new StackAsm(s).given(given.slice())
      const ctr = { n: 0 }
      for (const ast of asserts) { emit(ast, asm, params, ctr); asm.verify() }
      while (asm.main.length) asm.drop()
      asm.raw(Opcode.OP_1, 0, ['true'])
      return s
    },
    // The unlocking script pushes the witness values, bottom -> top, push-only (policy). A
    // PrivateKey witness is a SIGNATURE: it is signed over the real spending transaction using
    // the signing context the harness passes in (ctx.sign) — a static value cannot be a valid
    // signature, so `checkSig` needs the tx, not a constant.
    unlock (ctx = {}) {
      const s = new Script()
      for (const name of given) {
        const v = ctx[name]
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
      return s
    }
  }
}

module.exports = { compile, tokenize, parse }
