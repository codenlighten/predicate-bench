'use strict'

const bsv = require('@smartledger/bsv')
const Interpreter = bsv.Script.Interpreter
const Opcode = bsv.Opcode
const BN = bsv.crypto.BN

// Locating a failure in a 600-byte covenant.
//
// The interpreter's stepListener fires AFTER each opcode and only when it
// succeeded, so the failing opcode never reaches it — which is precisely the
// one you want. It can be recovered: step() advances the program counter before
// returning false, so the failure is at `pc - 1`, and that agrees with
// `lastTracedPc + 1`. Both are computed below and cross-checked.
//
// A raw step dump of these scripts runs to hundreds of lines, nearly all of it
// OP_PUSH_TX preamble. So this reports a WINDOW around the failure instead, with
// the stack as it stood entering the failing opcode, and says structurally where
// in the script that is — which branch, and how far past the branch opcode.

/** An opcode label that never throws, including for data pushes. */
function safeOpLabel (opcode) {
  const num = opcode && typeof opcode.toNumber === 'function'
    ? opcode.toNumber()
    : (opcode && opcode.num)
  if (num === undefined || num === null) return '?'
  if (num === 0) return 'OP_0'
  if (num >= 1 && num <= 75) return `PUSH(${num})`
  if (num === 76) return 'OP_PUSHDATA1'
  if (num === 77) return 'OP_PUSHDATA2'
  if (num === 78) return 'OP_PUSHDATA4'
  try { return Opcode.fromNumber(num).toString() } catch (e) { return '0x' + num.toString(16) }
}

/** Render one script chunk the way it reads in a disassembly. */
function chunkText (chunk) {
  if (chunk.buf) {
    const h = chunk.buf.toString('hex')
    return h.length <= 24 ? h : `${h.slice(0, 16)}…(${chunk.buf.length}B)`
  }
  if (chunk.opcodenum === 0) return 'OP_0'
  try { return Opcode.fromNumber(chunk.opcodenum).toString() } catch (e) {
    return '0x' + chunk.opcodenum.toString(16)
  }
}

function stackText (stack) {
  if (!stack || !stack.length) return '(empty)'
  return stack.map(b => {
    const h = Buffer.from(b).toString('hex')
    if (!h) return '<empty>'
    return h.length <= 20 ? h : `${h.slice(0, 12)}…(${b.length}B)`
  }).join(' | ')
}

/**
 * Where a chunk index sits relative to the script's branch structure.
 * Derived from the script alone, so no predicate has to annotate anything.
 */
function locate (script, index) {
  const name = (c) => {
    if (c.buf) return null
    try { return Opcode.fromNumber(c.opcodenum).toString() } catch (e) { return null }
  }

  // Walk the conditionals to find which branch the index actually sits in,
  // rather than guessing from the nearest preceding branch opcode — nested
  // conditionals would make that wrong.
  let depth = 0
  let branch = null      // the innermost enclosing branch at `index`
  const open = []
  let landmark = null

  for (let i = 0; i <= index && i < script.chunks.length; i++) {
    const op = name(script.chunks[i])
    if (op === 'OP_IF' || op === 'OP_NOTIF') {
      open.push({ at: i, side: op === 'OP_IF' ? 'IF' : 'NOTIF' })
      depth++
    } else if (op === 'OP_ELSE' && open.length) {
      open[open.length - 1] = { at: i, side: 'ELSE' }
    } else if (op === 'OP_ENDIF' && open.length) {
      open.pop(); depth--
    } else if (['OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_HASH256', 'OP_EQUALVERIFY'].includes(op) && i < index) {
      landmark = { at: i, op }
    }
    if (i === index) branch = open.length ? open[open.length - 1] : null
  }

  const parts = []
  if (branch) {
    const d = index - branch.at
    parts.push(`in the ${branch.side} branch (opened at chunk ${branch.at}, ${d} opcode${d === 1 ? '' : 's'} in)`)
  } else {
    parts.push('outside any conditional')
  }
  if (landmark) parts.push(`nearest landmark: ${landmark.op} at chunk ${landmark.at}`)
  return parts.join('; ')
}

/**
 * Run a locking/unlocking pair, recording every step.
 * Verifies under node policy by default — consensus alone hides MINIMALDATA.
 */
function trace (unlockingScript, lockingScript, opts = {}) {
  const interp = new Interpreter()
  const steps = []
  interp.stepListener = function (step, stack, altstack) {
    steps.push({
      phase: interp.script === lockingScript ? 'lock' : 'unlock',
      pc: step.pc,
      // Opcode.toString() throws for data-push opcodes ("does not have a string
      // representation"), and the interpreter swallows that as console noise on
      // every push. Label it safely instead.
      op: safeOpLabel(step.opcode),
      stack: stack.map(b => Buffer.from(b)),
      altstack: altstack.map(b => Buffer.from(b))
    })
  }

  const flags = opts.flags !== undefined
    ? opts.flags
    : require('./clauses').policyFlags()

  const ok = interp.verify(
    unlockingScript, lockingScript,
    opts.tx || new bsv.Transaction(), opts.inputIndex || 0,
    flags, new BN(opts.satoshis || 0)
  )

  const last = steps[steps.length - 1]

  // WHICH script failed comes from the interpreter, not from the last recorded
  // step. `verify()` evaluates the unlocking script, then the locking script,
  // and `interp.script` still points at whichever it was in — whereas the last
  // recorded step is from whichever last SUCCEEDED. When the unlocking script
  // completes and the locking script fails on its very first opcode, nothing
  // from the locking script was ever recorded, and taking the phase from the
  // last step attributed the failure to the wrong script entirely.
  const phase = interp.script === lockingScript ? 'lock'
    : interp.script === unlockingScript ? 'unlock'
      : (last ? last.phase : 'unlock')
  const script = phase === 'lock' ? lockingScript : unlockingScript

  // step() advances the program counter before returning false, so the failure
  // is at pc - 1. The trace gives a second derivation, but only when its last
  // step is in the same script — across the boundary it is measuring the wrong
  // one, and a disagreement there would be noise rather than a warning.
  const byPc = interp.pc - 1
  const sameScript = last && last.phase === phase
  const byTrace = sameScript ? last.pc + 1 : null

  // Not every failure belongs to an opcode. Some rules are checked against the
  // whole script — SIGPUSHONLY before evaluation begins, CLEANSTACK after it
  // ends — and for those the program counter points outside the chunk list.
  // Reporting "chunk -1" invents a location that does not exist.
  // A post-evaluation check lands IN range but on the wrong opcode: pc - 1
  // points back at the last thing that ran, and that thing succeeded. The tell
  // is that it was recorded — the step listener only fires on success, so if
  // the last recorded step sits at the same index, the failure is not there.
  const lastSucceededHere = sameScript && last.pc === byPc
  const inRange = byPc >= 0 && byPc < script.chunks.length && !lastSucceededHere
  const whole = inRange ? null : ((byPc < 0) ? 'before' : 'after')

  const failedAt = ok ? null : {
    phase,
    index: byPc,
    inRange,
    whole,
    agrees: (!inRange || byTrace === null) ? null : byPc === byTrace,
    chunk: inRange ? chunkText(script.chunks[byPc]) : null,
    total: script.chunks.length
  }

  return { ok, err: interp.errstr || '', steps, failedAt, lockingScript, unlockingScript }
}

/** A focused report: what failed, where, and the stack going into it. */
function explain (result, opts = {}) {
  if (result.ok) return 'VALID'
  const before = opts.before ?? 6
  const after = opts.after ?? 2
  const f = result.failedAt
  const out = []

  out.push(`${result.err}`)
  if (!f) return out.join('\n')

  const script = f.phase === 'lock' ? result.lockingScript : result.unlockingScript

  if (!f.inRange) {
    // A whole-script rule. Naming the script and when it is checked is the
    // whole of the location; there is no opcode to point at.
    out.push(`  a whole-script check on the ${f.phase} script ` +
             `(${f.total} chunk${f.total === 1 ? '' : 's'}), applied ${f.whole} evaluation`)
    const last = result.steps[result.steps.length - 1]
    out.push('')
    out.push(`  stack : ${stackText(last && last.stack)}`)
    out.push(`  steps executed : ${result.steps.length}`)
    return out.join('\n')
  }

  out.push(`  in the ${f.phase} script, chunk ${f.index} of ${f.total}`)
  out.push(`  ${locate(script, f.index)}`)
  if (f.agrees === false) {
    out.push('  (note: pc and trace disagree on the index; window may be off by one)')
  } else if (f.agrees === null) {
    out.push('  (the failure is the first opcode of this script, so there is no preceding step here)')
  }

  out.push('')
  const lo = Math.max(0, f.index - before)
  const hi = Math.min(script.chunks.length - 1, f.index + after)
  for (let i = lo; i <= hi; i++) {
    const marker = i === f.index ? '>>' : '  '
    out.push(`  ${marker} ${String(i).padStart(4)}  ${chunkText(script.chunks[i])}`)
  }

  // The stack entering the failing opcode is the last recorded one — and it is
  // still correct across the boundary, because verify() carries the stack from
  // the unlocking script into the locking script.
  const last = result.steps[result.steps.length - 1]
  out.push('')
  out.push(`  stack going in : ${stackText(last && last.stack)}` +
    (last && last.phase !== f.phase ? `   (carried over from the ${last.phase} script)` : ''))
  if (last && last.altstack.length) out.push(`  altstack       : ${stackText(last.altstack)}`)
  out.push(`  steps executed : ${result.steps.length}`)
  return out.join('\n')
}

/**
 * Trace a harness-style case. Rebuilds exactly what the harness would, so a
 * failing test can be explained without reconstructing it by hand.
 */
function traceCase (predicate, testCase = {}) {
  const { run } = require('./harness')
  const r = run(predicate, testCase)
  if (r.phase === 'build') return { ok: false, err: `build failed: ${r.error}`, steps: [], failedAt: null }
  return trace(r.unlockingScript, r.lockingScript, {
    tx: r.tx, inputIndex: 0, satoshis: testCase.satoshis ?? predicate.satoshis ?? 1000
  })
}

module.exports = { trace, explain, traceCase, locate, chunkText, stackText }
