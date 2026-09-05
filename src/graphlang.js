'use strict'

const { compile } = require('./relgraph')

// A surface syntax for the CONSTRAINT GRAPH — a whole protocol of interacting objects
// written as text. `.pred` writes one predicate, `.rel` writes one relationship; a
// `.graph` writes the graph: the objects, and the relationships that bind them. It
// parses to a relgraph declaration, so each object lowers to its coin (byte-identical
// to what is deployed) or is flagged with the composition it needs.
//
//   graph escrowed-treasury {
//     object A
//     object B
//     object O
//
//     conservedPair treasury {
//       genesis $genesis
//       member A side 0 balance 60 owner $owner
//       member B side 1 balance 40 owner $owner
//     }
//
//     dependsOn armed {
//       gate A
//       sibling O
//       oracle $oracle
//       require-flag 1
//     }
//   }
//
// Object A stands in both relationships, so the graph compiler emits the composed
// `guarded` coin for it — byte-identical to the deployed pair coin. A front-end, no
// new logic: everything is checked by src/relgraph.js against the relational ladder.

function stripComments (src) { return src.replace(/\/\/[^\n]*/g, '') }
function resolve (tok, params) {
  if (typeof tok === 'string' && tok[0] === '$') {
    const key = tok.slice(1)
    if (!(key in params)) throw new Error(`unbound parameter $${key}`)
    return params[key]
  }
  return tok
}
function num (tok, params) {
  const v = resolve(tok, params); const x = Number(v)
  if (!Number.isFinite(x)) throw new Error(`expected a number, got '${v}'`)
  return x
}

// A tiny brace-aware line parser: a header line `kind name {`, statement lines, and
// closing `}`. One level of nesting (the graph, then each relationship block).
function parse (src, params = {}) {
  const lines = stripComments(src).split('\n').map((l) => l.trim()).filter(Boolean)
  if (!lines.length || !/^graph\s+\S+\s*\{$/.test(lines[0])) {
    throw new Error('first line must be: graph <name> {')
  }
  const graph = { name: lines[0].split(/\s+/)[1], objects: [], relationships: [] }
  let i = 1
  while (i < lines.length) {
    const line = lines[i]
    if (line === '}') break
    if (line.startsWith('object ')) { graph.objects.push(line.split(/\s+/)[1]); i++; continue }

    // a relationship block: `<type> <name> {` … `}`
    const m = line.match(/^(\w+)\s+(\S+)\s*\{$/)
    if (!m) throw new Error(`unexpected line: ${line}`)
    const rel = { type: m[1], name: m[2] }
    const members = []
    i++
    while (i < lines.length && lines[i] !== '}') {
      const w = lines[i].split(/\s+/)
      switch (w[0]) {
        case 'genesis': rel.genesis = resolve(w[1], params); break
        case 'oracle': rel.gateParams = { ...(rel.gateParams || {}), sibling: resolve(w[1], params) }; break
        case 'require-flag': case 'requiredFlag': rel.gateParams = { ...(rel.gateParams || {}), requiredFlag: num(w[1], params) }; break
        case 'gate': rel.gate = w[1]; break
        case 'sibling': rel.sibling = w[1]; break
        case 'logs': case 'object': rel.object = w[1]; break        // the object a journal logs
        case 'seq': rel.seq = num(w[1], params); break
        case 'member': {
          // member <ObjectName> side <n> balance <n> owner <value>  (or index <n> for a pool)
          const m2 = { name: w[1] }
          for (let k = 2; k < w.length; k += 2) {
            if (w[k] === 'side' || w[k] === 'index') m2[w[k] === 'side' ? 'side' : 'index'] = num(w[k + 1], params)
            else if (w[k] === 'balance') m2.balance = num(w[k + 1], params)
            else if (w[k] === 'owner') m2.owner = resolve(w[k + 1], params)
            else throw new Error(`unknown member field '${w[k]}'`)
          }
          members.push(m2)
          break
        }
        default: throw new Error(`unknown statement '${w[0]}' in ${rel.type}`)
      }
      i++
    }
    i++ // consume the relationship's closing '}'
    if (members.length) {
      rel.members = members.map((m) => m.name)
      rel.memberParams = members
    }
    graph.relationships.push(rel)
  }
  return graph
}

function build (src, params = {}) { return compile(parse(src, params)) }

module.exports = { parse, build }
