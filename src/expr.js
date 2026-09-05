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
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { StackAsm } = require('./stackasm')
const C = require('./clauses')
const covsteps = require('./covsteps')

// Fixed-width state field types (a subset — enough for a counter). The width feeds the
// read/increment/recreate splice; the head is always the 3-byte scriptlen varint + the
// 1-byte push opcode (true for a script of 253..65535 bytes, which a covenant always is).
const STATE_TYPES = { u8: 1, u16: 2, u32: 4, u64: 8 }
const STATE_HEAD = 4
function stateBuf (value, width) {
  const b = Buffer.alloc(width)
  b.writeUIntLE(value, 0, Math.min(width, 6))
  return b
}
const Opcode = bsv.Opcode
const Script = bsv.Script
const n = helpers.scriptNum

// Read-only spending-context fields, by name. Each reads a field from the authenticated
// BIP-143 preimage and leaves it as an unsigned number — the same field-read the proven
// clauses use (bytes `len` from `fromEnd`, append 0x00, OP_BIN2NUM), so the sign handling is
// exactly the one already deployed. `guardsSequence` fields make nLockTime meaningful only
// with a non-final input, so reading one auto-injects the sequence guard (pitfall 27).
const CTX = {
  locktime: { fromEnd: 8, len: 4, guardsSequence: true }
}

// ---- tokenizer ------------------------------------------------------------------------
const TWO = ['==', '!=', '<=', '>=', '&&', '||', '++']
const ONE = ['<', '>', '+', '-', '*', '/', '%', '!', '(', ')', ',', '{', '}', '[', ']', '=', ':']
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
        : t.v.startsWith('tx.') ? { k: 'ctx', field: t.v.slice(3) }
          : (t.v.includes('.') ? (() => { throw new Error(`expr: '${t.v}' — only this.<name> and tx.<field> may use a dot`) })()
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
    if (t.v === 'pay') { next(); eat('('); const dest = or(); eat(','); const amount = or(); eat(')'); return { k: 'pay', dest, amount } }
    if (t.v === 'recreate') { next(); eat('('); const fee = or(); eat(')'); let guard = null; if (peek() && peek().v === 'while') { next(); guard = or() } return { k: 'recreate', fee, guard } }
    if (t.v === 'redeem') { next(); eat('('); const dest = or(); eat(')'); return { k: 'redeem', dest } }
    if (t.v === 'state') { next(); const name = eat0id(); eat(':'); const type = eat0id(); return { k: 'state', name, type } }
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

// One p2pkh output a pay() statement commits to, resolved from baked params.
function payOutput (st, params) {
  const dest = params[st.dest.name]
  if (dest === undefined) throw new Error(`expr: pay — unbound this.${st.dest.name}`)
  const amount = st.amount.k === 'num' ? st.amount.v : params[st.amount.name]
  if (typeof amount !== 'number') throw new Error(`expr: pay — amount ${st.amount.k === 'num' ? st.amount.v : 'this.' + st.amount.name} must be a number`)
  return helpers.p2pkhOutput(dest, amount)
}

// The hop fee of a recreate() — a positive integer from a number or a baked param.
function feeOf (st, params) {
  const f = st.fee.k === 'num' ? st.fee.v : (st.fee.k === 'param' ? params[st.fee.name] : undefined)
  if (!Number.isInteger(f) || f <= 0) throw new Error('expr: recreate(fee) — fee must be a positive integer')
  return f
}

function asBuf (v, ref) {
  if (v && v.type === 'Buffer' && Array.isArray(v.data)) v = Buffer.from(v.data)
  if (Buffer.isBuffer(v)) return v
  if (typeof v === 'string' && /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex')
  if (v && typeof v.toBuffer === 'function') return v.toBuffer()             // a PublicKey
  throw new Error(`expr: ${ref} must be a public key (hex or Buffer)`)
}

// checkMultiSig(sigs, pubkeys) — m-of-n, where m is the size of the witness sig array and n is
// the length of the baked pubkey array: <empty-dummy> sig0..sig(m-1) m pub0..pub(n-1) n
// OP_CHECKMULTISIG. The dummy is empty (NULLDUMMY); the sigs are checked in pubkey order.
function emitMultiSig (node, asm, env, label) {
  if (node.args.length !== 2) throw new Error('expr: checkMultiSig(sigs, pubkeys) takes 2 arguments')
  const [sigArg, pkArg] = node.args
  if (sigArg.k !== 'var' || !env.arrays.has(sigArg.name)) throw new Error("expr: checkMultiSig's first argument must be a witness sig array (declare 'given sig[m]')")
  if (pkArg.k !== 'param') throw new Error("expr: checkMultiSig's second argument must be a baked pubkey array (this.pubkeys)")
  const m = env.arrays.get(sigArg.name)
  const pubkeys = env.params[pkArg.name]
  if (!Array.isArray(pubkeys)) throw new Error(`expr: this.${pkArg.name} must be an array of public keys`)
  const nn = pubkeys.length
  if (m > nn) throw new Error(`expr: checkMultiSig needs at least as many keys (${nn}) as signatures (${m})`)
  asm.num(0, 'msDummy')                                              // the required empty dummy
  for (let i = 0; i < m; i++) asm.pick(sigArg.name + i, 'msSig' + i)
  asm.num(m, 'msM')
  for (let i = 0; i < nn; i++) asm.data(asBuf(pubkeys[i], `this.${pkArg.name}[${i}]`), 'msPk' + i)
  asm.num(nn, 'msN')
  asm.op('OP_CHECKMULTISIG', m + nn + 3, [label])                    // pops dummy+m sigs+m+n pubs+n
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
    case 'ctx': {
      const spec = CTX[node.field]
      if (!spec) throw new Error(`expr: unknown context field 'tx.${node.field}' (have: ${Object.keys(CTX).map((f) => 'tx.' + f).join(', ')})`)
      // bytes[len from fromEnd] of the authenticated preimage, read unsigned (append 0x00,
      // OP_BIN2NUM) — exactly the deployed field-read. The preimage copy is consumed; the
      // authenticated preimage underneath is preserved for the next read.
      asm.pick('preimage', lbl())
      asm.num(spec.fromEnd, lbl()); asm.op('OP_RIGHT', 2, [lbl()])
      asm.num(spec.len, lbl()); asm.op('OP_LEFT', 2, [lbl()])
      asm.data(Buffer.from([0]), lbl()); asm.cat(lbl()); asm.bin2num(lbl())
      return
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
      if (node.fn === 'checkMultiSig') return emitMultiSig(node, asm, env, lbl())
      const def = CALL[node.fn]
      if (!def) throw new Error(`expr: unknown function '${node.fn}' (have: ${Object.keys(CALL).join(', ')}, checkMultiSig)`)
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
    case 'pay': return                                     // bound as a set in the covenant path
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
  if (!stmts.some((s) => s.k === 'assert' || s.k === 'pay' || s.k === 'recreate')) throw new Error('expr: a predicate needs at least one assert(), pay() or recreate()')

  // Fail fast, at compile time: an unknown function, a wrong arity, an undeclared witness or
  // variable, or an index of something that is not an array. A bad predicate never builds.
  const scalars = new Set(givenDecls.filter((d) => d.size === undefined).map((d) => d.name))
  const arrays = new Map(givenDecls.filter((d) => d.size !== undefined).map((d) => [d.name, d.size]))
  const known = new Set(scalars)
  const ctxInfo = { used: false, guardsSequence: false }
  const vExpr = (node) => {
    switch (node.k) {
      case 'num': case 'hex': case 'param': return
      case 'ctx': {
        const spec = CTX[node.field]
        if (!spec) throw new Error(`expr: unknown context field 'tx.${node.field}' (have: ${Object.keys(CTX).map((f) => 'tx.' + f).join(', ')})`)
        ctxInfo.used = true
        if (spec.guardsSequence) ctxInfo.guardsSequence = true
        return
      }
      case 'var': if (!known.has(node.name)) throw new Error(`expr: '${node.name}' is not a declared witness or variable`); return
      case 'index':
        if (node.base.k === 'param') { vExpr(node.idx); return }
        if (node.base.k === 'var') { if (!arrays.has(node.base.name)) throw new Error(`expr: '${node.base.name}' is not a declared witness array (declare 'given ${node.base.name}[N]')`); vExpr(node.idx); return }
        throw new Error('expr: only a witness or this.<name> may be indexed')
      case 'not': vExpr(node.a); return
      case 'bin': vExpr(node.l); vExpr(node.r); return
      case 'cond': vExpr(node.c); vExpr(node.a); vExpr(node.b); return
      case 'call': {
        if (node.fn === 'checkMultiSig') {
          if (node.args.length !== 2) throw new Error('expr: checkMultiSig(sigs, pubkeys) takes 2 arguments')
          if (node.args[0].k !== 'var' || !arrays.has(node.args[0].name)) throw new Error("expr: checkMultiSig's first argument must be a witness sig array (declare 'given sig[m]')")
          if (node.args[1].k !== 'param') throw new Error("expr: checkMultiSig's second argument must be a baked pubkey array (this.pubkeys)")
          return
        }
        const d = CALL[node.fn]
        if (!d) throw new Error(`expr: unknown function '${node.fn}' (have: ${Object.keys(CALL).join(', ')}, checkMultiSig)`)
        if (node.args.length !== d.arity) throw new Error(`expr: ${node.fn}() takes ${d.arity} argument(s), got ${node.args.length}`)
        node.args.forEach(vExpr); return
      }
      default: throw new Error(`expr: cannot validate node ${node.k}`)
    }
  }
  const vPay = (st) => {
    if (st.dest.k !== 'param') throw new Error("expr: pay(dest, amount) — dest must be a baked address (this.<name>)")
    if (st.amount.k !== 'param' && st.amount.k !== 'num') throw new Error('expr: pay(dest, amount) — amount must be a number or this.<name>')
  }
  const vStmts = (list) => {
    for (const st of list) {
      if (st.k === 'let') { vExpr(st.expr); known.add(st.name) } else if (st.k === 'assign') { if (!known.has(st.name)) throw new Error(`expr: '${st.name}' is assigned before it is introduced with 'let'`); vExpr(st.expr) } else if (st.k === 'assert') { vExpr(st.expr) } else if (st.k === 'pay') { vPay(st) } else if (st.k === 'recreate') { if (st.fee.k !== 'num' && st.fee.k !== 'param') throw new Error('expr: recreate(fee) — fee must be a number or this.<name>') } else if (st.k === 'for') { known.add(st.varName); vStmts(st.body) }
    }
  }
  vStmts(stmts)

  // A predicate that reads the spending context or binds outputs is a covenant: its only
  // witness is the authenticated preimage, which the unlock synthesises (OP_PUSH_TX). Mixing
  // it with a user witness stack is a real design (preimage + witness together), but a subtle
  // one — kept out of v1 so the sound path stays simple.
  const payStmts = stmts.filter((s) => s.k === 'pay')
  const recreateStmts = stmts.filter((s) => s.k === 'recreate')
  const redeemStmts = stmts.filter((s) => s.k === 'redeem')
  const stateDecls = stmts.filter((s) => s.k === 'state')
  // A bounded counter is the two-branch shape of the deployed `metered` covenant: while the
  // counter is below a cap, increment and recreate (hop); at the cap, settle to a fixed
  // address (redeem). Recognised when a state field carries a guarded recreate and a redeem.
  const bounded = stateDecls.length === 1 && recreateStmts.length === 1 && recreateStmts[0].guard && redeemStmts.length === 1
  if (redeemStmts.length && !bounded) throw new Error("expr: redeem(dest) pairs with a guarded recreate — 'state c; recreate(fee) while c < this.max; redeem(this.settle)'")
  function meteredShape (params) {
    const g = recreateStmts[0].guard
    if (!g || g.k !== 'bin' || g.op !== '<' || g.l.k !== 'var' || g.l.name !== stateDecls[0].name || g.r.k !== 'param') {
      throw new Error(`expr: a bounded counter's guard must be '${stateDecls[0].name} < this.<max>'`)
    }
    if (redeemStmts[0].dest.k !== 'param') throw new Error('expr: redeem(dest) — dest must be a baked address (this.<name>)')
    return {
      max: params[g.r.name], settle: params[redeemStmts[0].dest.name], fee: feeOf(recreateStmts[0], params),
      width: STATE_TYPES[stateDecls[0].type], name: stateDecls[0].name,
      maxName: g.r.name, settleName: redeemStmts[0].dest.name,
      feeName: recreateStmts[0].fee.k === 'param' ? recreateStmts[0].fee.name : null
    }
  }
  if (recreateStmts.length > 1) throw new Error('expr: a covenant can recreate() itself at most once')
  if (recreateStmts.length && payStmts.length) throw new Error('expr: recreate() and pay() both bind the output set — use one (a recreate with a payout tail is a later rung)')
  if (stateDecls.length > 1) throw new Error('expr: a covenant may carry one state field for now (a counter)')
  if (stateDecls.length) {
    if (!(stateDecls[0].type in STATE_TYPES)) throw new Error(`expr: state ${stateDecls[0].name}: unknown type '${stateDecls[0].type}' (have: ${Object.keys(STATE_TYPES).join(', ')})`)
    if (!recreateStmts.length) throw new Error('expr: a state field needs a recreate() — it is carried forward, incremented, into the successor')
    if (ctxInfo.used || stmts.some((s) => s.k === 'assert')) throw new Error('expr: a guarded state covenant (state with tx.<field> or assert) is a later rung; for now a state covenant is the counter and its recreate')
  }
  const usesContext = ctxInfo.used || payStmts.length > 0 || recreateStmts.length > 0
  if (usesContext && flat.length) throw new Error('expr: a covenant (tx.<field>, pay(...) or recreate(...)) cannot also declare a witness (given ...) yet')

  const predicate = {
    name: 'expr',
    given: flat,
    givenDecls,
    source,
    stmts,
    usesContext,
    lock (params = {}) {
      const s = new Script()
      if (usesContext && bounded) {
        // A bounded counter — the two-branch shape of `metered`, byte for byte. A flag in the
        // unlocking script picks the branch: hop (count < max → increment and recreate) or
        // redeem (count >= max → settle to a fixed address). The counter never strands: it
        // advances to the cap, then exits.
        const m = meteredShape(params)
        s.add(stateBuf(params[m.name] ?? 0, m.width)).add(Opcode.OP_DROP)
        C.authenticateThenBranch(s)
        covsteps.meteredReadCounterKeep(s, { headBytes: STATE_HEAD, counterBytes: m.width })
        covsteps.meteredGuardBelow(s, { max: m.max })
        covsteps.meteredIncrementRecreate(s, { counterBytes: m.width, fee: m.fee })
        s.add(Opcode.OP_ELSE)
        covsteps.meteredReadCounterDrop(s, { headBytes: STATE_HEAD, counterBytes: m.width })
        covsteps.meteredGuardAtLeast(s, { max: m.max })
        covsteps.meteredPayFixed(s, { address: bsv.Address.fromString(m.settle), fee: m.fee })
        s.add(Opcode.OP_ENDIF)
        return s
      }
      if (usesContext && stateDecls.length) {
        // A stateful counter covenant: a fixed-width counter at the front (pushed and dropped),
        // then the proven read-increment-recreate machinery (metered's hop). Each spend advances
        // the counter by one into the successor. Monotonic, so it never strands.
        const d = stateDecls[0]; const width = STATE_TYPES[d.type]
        s.add(stateBuf(params[d.name] ?? 0, width)).add(Opcode.OP_DROP)
        C.authenticate(s)
        C.requireSighashAll(s)
        covsteps.meteredReadCounterKeep(s, { headBytes: STATE_HEAD, counterBytes: width })
        covsteps.meteredIncrementRecreate(s, { counterBytes: width, fee: feeOf(recreateStmts[0], params) })
        return s
      }
      if (usesContext) {
        // The preimage is the sole stack item the unlock pushed. Bind it to this spend
        // (OP_PUSH_TX), then — because nLockTime is inert on a final input — require the
        // input non-final, then run the context logic, then drop the preimage and succeed.
        const asm = new StackAsm(s).given(['preimage'])
        C.authenticate(asm.s)                              // net-neutral: [preimage] -> [preimage]
        if (ctxInfo.guardsSequence) C.requireSequenceNonFinal(asm.s)
        if (payStmts.length) {
          // Bind the WHOLE output set: hashOutputs (a double-SHA256 over every output's amount
          // and script) must equal the commitment computed from the pay() destinations. The
          // spender chooses nothing about where the money goes. Net-neutral on the preimage.
          const outs = payStmts.map((st) => payOutput(st, params))
          const expected = PushTx.hashOutputs(outs)
          asm.s.add(Opcode.OP_DUP)
          PushTx.extractHashOutputs(asm.s)                 // last 40, first 32
          asm.s.add(Buffer.from(expected)).add(Opcode.OP_EQUALVERIFY)
        }
        const env = { params, arrays, loop: {}, ctr: { n: 0 } }
        for (const st of stmts) if (st.k !== 'pay' && st.k !== 'recreate') execStmt(st, asm, env)
        if (recreateStmts.length) {
          // Self-recreation: the required output is THIS script, read out of the authenticated
          // preimage (preimage[104 : len-52] is the scriptlen‖script half of a TxOut), carrying
          // the input value minus the hop fee. requireOutputIs leaves the result — the terminal.
          const fee = feeOf(recreateStmts[0], params)
          C.requireSighashAll(asm.s)
          C.selfChunk(asm.s)
          asm.s.add(Opcode.OP_OVER)
          C.newValueLE(asm.s, fee)
          asm.s.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
          C.requireOutputIs(asm.s)
          return s
        }
        asm.drop()                                         // drop the preimage
        asm.raw(Opcode.OP_1, 0, ['true'])
        return s
      }
      const asm = new StackAsm(s).given(flat.slice())
      const env = { params, arrays, loop: {}, ctr: { n: 0 } }
      for (const st of stmts) execStmt(st, asm, env)
      while (asm.main.length) asm.drop()                   // discard witness + accumulators
      asm.raw(Opcode.OP_1, 0, ['true'])                    // leave true (clean stack, per policy)
      return s
    },
    unlock (ctx = {}) {
      const s = new Script()
      if (usesContext && bounded) {
        // The branch flag rides BELOW the preimage: the preimage must be on top for the single
        // hoisted OP_PUSH_TX, which then swaps the flag up for OP_IF. OP_1 = hop, OP_0 = redeem.
        const flag = ctx.branch === 'redeem' ? Opcode.OP_0 : Opcode.OP_1
        return s.add(flag).add(C.grindPreimage(ctx.tx, ctx.inputIndex, ctx.lockingScript, ctx.satoshis, ctx.at ?? 0, ctx.sighashType))
      }
      if (usesContext) {
        // The witness is the BIP-143 preimage of THIS spend. OP_PUSH_TX needs a preimage whose
        // in-script signature is clean low-S, so grind a malleable field. The input is non-final
        // (unlockDefaults), so grindPreimage grinds the sequence and pins nLockTime — to `at`,
        // or this.notBefore, or 0. Passing an `at` below the floor is how a too-early spend is
        // tested (the script then refuses it).
        const pin = ctx.at ?? ctx.notBefore ?? 0
        return s.add(C.grindPreimage(ctx.tx, ctx.inputIndex, ctx.lockingScript, ctx.satoshis, pin, ctx.sighashType))
      }
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
  // A context predicate must be spent by a non-final input, or its nLockTime check is inert.
  if (usesContext && ctxInfo.guardsSequence) predicate.unlockDefaults = { sequenceNumber: 0xfffffffe }
  // A pay() covenant dictates its outputs, so the harness and the on-chain path build the spend
  // from them (not change wherever they like). A test may pass actualOutputs to spend elsewhere
  // and watch the commitment refuse it.
  if (payStmts.length) predicate.outputs = (ctx = {}) => ctx.actualOutputs || payStmts.map((st) => payOutput(st, ctx))
  // A recreate() covenant dictates a single output: this exact script, carrying value − fee. No
  // continuation() is needed — the recreated coin is byte-identical, so onchain records it from
  // the deployment itself. A test passes actualOutputs / actualAmount / actualScript to break it.
  if (bounded) {
    // Two output paths: hop recreates the counter at +1; redeem pays the settle address.
    predicate.outputs = (ctx = {}) => {
      if (ctx.actualOutputs) return ctx.actualOutputs
      const m = meteredShape(ctx)
      if ((ctx.branch || 'hop') === 'redeem') return [helpers.p2pkhOutput(m.settle, ctx.actualAmount ?? (ctx.satoshis - m.fee))]
      const script = ctx.actualScript || predicate.lock({ ...ctx, [m.name]: (ctx[m.name] ?? 0) + 1 })
      return [new bsv.Transaction.Output({ script, satoshis: ctx.actualAmount ?? (ctx.satoshis - m.fee) })]
    }
    predicate.continuation = (ctx = {}) => {
      if ((ctx.branch || 'hop') === 'redeem') return null      // redeem is terminal (pays a p2pkh)
      const m = meteredShape(ctx)
      const np = { [m.name]: (ctx[m.name] ?? 0) + 1 }
      for (const nm of [m.maxName, m.feeName, m.settleName]) if (nm && ctx[nm] !== undefined) np[nm] = ctx[nm]
      return { script: predicate.lock(np), params: np }
    }
  } else if (recreateStmts.length) {
    const successor = (ctx) => stateDecls.length
      ? predicate.lock({ ...ctx, [stateDecls[0].name]: (ctx[stateDecls[0].name] ?? 0) + 1 })  // counter advanced
      : ctx.lockingScript                                                                     // byte-identical
    predicate.outputs = (ctx = {}) => ctx.actualOutputs || [new bsv.Transaction.Output({
      script: ctx.actualScript || successor(ctx),
      satoshis: ctx.actualAmount ?? (ctx.satoshis - feeOf(recreateStmts[0], ctx))
    })]
    // A state covenant's successor differs (the counter advanced), so onchain records it from a
    // continuation with clean params (never the wallet key). A plain recreate needs none.
    if (stateDecls.length) {
      predicate.continuation = (ctx = {}) => {
        const d = stateDecls[0]
        const np = { [d.name]: (ctx[d.name] ?? 0) + 1 }
        if (recreateStmts[0].fee.k === 'param') np[recreateStmts[0].fee.name] = feeOf(recreateStmts[0], ctx)
        return { script: predicate.lock(np), params: np }
      }
    }
  }
  return predicate
}

module.exports = { compile, tokenize, parse: (src) => parser(tokenize(src)) }
