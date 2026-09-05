'use strict'

const { compile } = require('./relcompile')

// A surface syntax for RELATIONSHIPS — the human writes the protocol, the compiler
// emits the coins. A `.rel` source parses to a relcompile declaration; parameters (a
// genesis outpoint, an owner pkh, a sibling outpoint) are referenced by `$name` and
// bound at parse time. Faithfulness is proven the bench's way: a parsed, compiled
// `.rel` is byte-identical to the deployed coins, and an unsound one refuses to
// compile (tools/rellang-selftest.js).
//
//   relationship treasury-pair conservedPair {
//     genesis $genesis
//     member side 0 balance 60 owner $owner
//     member side 1 balance 40 owner $owner
//   }
//
//   relationship escrow-leg dependsOn {
//     beneficiary $beneficiary
//     sibling     $sibling
//     require-flag 1
//   }
//
// The language is thin on purpose: one relationship per source, flat statements, and
// the same template names relcompile already knows. It is a front-end, no new logic.

function stripComments (src) {
  return src.replace(/\/\/[^\n]*/g, '')
}
function resolve (tok, params) {
  if (typeof tok === 'string' && tok[0] === '$') {
    const key = tok.slice(1)
    if (!(key in params)) throw new Error(`unbound parameter $${key}`)
    return params[key]
  }
  return tok
}
function num (tok, params) {
  const v = resolve(tok, params)
  const n = Number(v)
  if (!Number.isFinite(n)) throw new Error(`expected a number, got '${v}'`)
  return n
}

function parse (src, params = {}) {
  const lines = stripComments(src).split('\n').map((l) => l.trim()).filter(Boolean)
  if (!lines.length) throw new Error('empty relationship source')

  // header: relationship <name> <template> {
  const header = lines[0].replace(/\{$/, '').trim().split(/\s+/)
  if (header[0] !== 'relationship' || header.length < 3) {
    throw new Error("first line must be: relationship <name> <template> {")
  }
  const decl = { name: header[1], relationship: header[2] }
  const members = []

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].replace(/\{$/, '').trim()
    if (line === '}' || line === '') continue
    const w = line.split(/\s+/)
    switch (w[0]) {
      case 'genesis': decl.genesis = resolve(w[1], params); break
      case 'beneficiary': decl.beneficiary = resolve(w[1], params); break
      case 'sibling': decl.sibling = resolve(w[1], params); break
      case 'require-flag': case 'requiredFlag': decl.requiredFlag = num(w[1], params); break
      case 'member': {
        // member side <n> balance <n> owner <value>
        const m = {}
        for (let k = 1; k < w.length; k += 2) {
          if (w[k] === 'side') m.side = num(w[k + 1], params)
          else if (w[k] === 'balance') m.balance = num(w[k + 1], params)
          else if (w[k] === 'owner') m.owner = resolve(w[k + 1], params)
          else throw new Error(`unknown member field '${w[k]}'`)
        }
        members.push(m)
        break
      }
      // escape hatches to model a weaker/unsound lowering, for the refusal tests
      case 'claim': decl.claim = w[1]; break
      case 'proofs': decl.proofs = w.slice(1); break
      default: throw new Error(`unknown statement '${w[0]}'`)
    }
  }
  if (members.length) decl.members = members
  return decl
}

function build (src, params = {}) {
  return compile(parse(src, params))
}

module.exports = { parse, build }
