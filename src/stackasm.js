'use strict'

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// A stack-tracking assembler for authoring complex locking scripts.
//
// Hand-writing OP_PICK/OP_ROLL depths for a covenant with a dozen live values is
// how subtle, security-relevant stack bugs get in. This tracks a symbolic model
// of the main and alt stacks by NAME and emits the right depth for each access,
// so the covenant reads as data flow rather than as stack juggling.
//
// It is not separately unit-tested: its correctness is proven end-to-end, because
// a wrong depth produces a script the real consensus interpreter rejects, and the
// covenants built on it carry adversarial test suites that would fail. If the
// tests are green, the emitted depths were right.
class StackAsm {
  constructor (script) {
    this.s = script || new bsv.Script()
    this.main = []   // names, bottom -> top
    this.alt = []    // names, bottom -> top
    this._frames = [] // open OP_IF frames, for branch modelling
  }

  // --- conditional branches -------------------------------------------------
  // A linear stack model cannot follow two paths, so a branch is modelled by
  // snapshotting the stack at OP_IF, running the IF body, restoring the snapshot
  // for the ELSE body, and asserting at OP_ENDIF that both bodies leave the same
  // depth — the invariant CLEANSTACK ultimately depends on.
  /** OP_IF, consuming the boolean now on top; snapshot for the ELSE body. */
  beginIf () {
    this.s.add(Opcode.OP_IF)
    this.main.pop()                                  // the condition is consumed
    this._frames.push({ snap: this.main.slice(), altSnap: this.alt.slice(), ifEnd: null })
  }
  /** OP_ELSE: record where the IF body ended, restore the snapshot for the ELSE body. */
  elseBranch () {
    this.s.add(Opcode.OP_ELSE)
    const f = this._frames[this._frames.length - 1]
    f.ifEnd = { main: this.main.slice(), alt: this.alt.slice() }
    this.main = f.snap.slice()
    this.alt = f.altSnap.slice()
  }
  /** OP_ENDIF: assert both bodies left the same shape, keep it. */
  endIf () {
    this.s.add(Opcode.OP_ENDIF)
    const f = this._frames.pop()
    const other = f.ifEnd || { main: f.snap, alt: f.altSnap }   // no ELSE => IF must be neutral
    if (other.main.length !== this.main.length || other.alt.length !== this.alt.length) {
      throw new Error(`stackasm: IF/ELSE branches leave different depths ` +
        `(${other.main.length}/${other.alt.length} vs ${this.main.length}/${this.alt.length})`)
    }
    return this
  }

  /** Depth of the topmost occurrence of `name` measured from the top (0 = top). */
  _depth (name) {
    for (let i = this.main.length - 1; i >= 0; i--) {
      if (this.main[i] === name) return this.main.length - 1 - i
    }
    throw new Error(`stackasm: '${name}' is not on the main stack [${this.main.join(', ')}]`)
  }

  // --- introducing values ---------------------------------------------------
  /** Push constant bytes (or a number via scriptNum) as `name`. */
  data (buf, name) { this.s.add(buf); this.main.push(name); return this }
  num (v, name) { this.s.add(n(v)); this.main.push(name); return this }
  /** Declare that the unlocking script has already left these on the stack (bottom→top). */
  given (names) { this.main.push(...names); return this }
  /** Declare items already parked on the altstack (bottom→top), e.g. a pre-parked preimage. */
  seedAlt (names) { this.alt.push(...names); return this }

  // --- copying / moving -----------------------------------------------------
  /** Copy `name` to the top as `as`. */
  pick (name, as) {
    const d = this._depth(name)
    if (d === 0) this.s.add(Opcode.OP_DUP)
    else if (d === 1) this.s.add(Opcode.OP_OVER)
    else this.s.add(n(d)).add(Opcode.OP_PICK)
    this.main.push(as || (name + '*'))
    return this
  }
  /** Move `name` to the top (consuming it from where it was). */
  roll (name) {
    const d = this._depth(name)
    if (d === 0) { /* already top */ }
    else if (d === 1) this.s.add(Opcode.OP_SWAP)
    else if (d === 2) this.s.add(Opcode.OP_ROT)
    else this.s.add(n(d)).add(Opcode.OP_ROLL)
    // remove the (topmost) occurrence and re-push on top
    for (let i = this.main.length - 1; i >= 0; i--) {
      if (this.main[i] === name) { this.main.splice(i, 1); break }
    }
    this.main.push(name)
    return this
  }

  // --- altstack -------------------------------------------------------------
  toAlt () { this.s.add(Opcode.OP_TOALTSTACK); this.alt.push(this.main.pop()); return this }
  fromAlt () { this.s.add(Opcode.OP_FROMALTSTACK); this.main.push(this.alt.pop()); return this }
  /** Name the item currently on top (e.g. after fromAlt). */
  rename (name) { this.main[this.main.length - 1] = name; return this }

  // --- consuming / rearranging on top --------------------------------------
  drop () { this.s.add(Opcode.OP_DROP); this.main.pop(); return this }
  nip () { this.s.add(Opcode.OP_NIP); const t = this.main.pop(); this.main[this.main.length - 1] = t; return this }
  swap () {
    this.s.add(Opcode.OP_SWAP)
    const a = this.main.length - 1
    ;[this.main[a], this.main[a - 1]] = [this.main[a - 1], this.main[a]]
    return this
  }

  // --- byte ops (operate on the top items) ---------------------------------
  /** OP_SPLIT the top item at absolute offset `at`, leaving [lo, hi]. */
  splitAt (at, lo, hi) {
    this.s.add(n(at)).add(Opcode.OP_SPLIT)
    this.main.pop(); this.main.push(lo, hi); return this
  }
  /** CAT the top two (2nd ‖ top) into `name`. */
  cat (name) {
    this.s.add(Opcode.OP_CAT)
    this.main.pop(); this.main[this.main.length - 1] = name; return this
  }
  hash256 (name) { this.s.add(Opcode.OP_HASH256); this.main[this.main.length - 1] = name || 'h256'; return this }
  hash160 (name) { this.s.add(Opcode.OP_HASH160); this.main[this.main.length - 1] = name || 'h160'; return this }
  sha256 (name) { this.s.add(Opcode.OP_SHA256); this.main[this.main.length - 1] = name || 'sha'; return this }
  /** OP_MOD: [a, b] -> a % b. */
  mod (name) { this.s.add(Opcode.OP_MOD); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  /** OP_CHECKSIGVERIFY: consume [sig, pubkey] (pubkey on top), verify against this input. */
  checkSigVerify () { this.s.add(Opcode.OP_CHECKSIGVERIFY); this.main.pop(); this.main.pop(); return this }
  bin2num (name) { this.s.add(Opcode.OP_BIN2NUM); this.main[this.main.length - 1] = name || (this.main[this.main.length - 1] + '#'); return this }
  num2bin (width, name) { this.s.add(n(width)).add(Opcode.OP_NUM2BIN); this.main.pop(); this.main.push(name); return this }
  add (name) { this.s.add(Opcode.OP_ADD); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  sub (name) { this.s.add(Opcode.OP_SUB); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  mul (name) { this.s.add(Opcode.OP_MUL); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  div (name) { this.s.add(Opcode.OP_DIV); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  max (name) { this.s.add(Opcode.OP_MAX); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  min (name) { this.s.add(Opcode.OP_MIN); this.main.pop(); this.main[this.main.length - 1] = name; return this }
  /** OP_SPLIT the top item at an offset already on the stack: [buf, n] -> [lo, hi]. */
  split (lo, hi) { this.s.add(Opcode.OP_SPLIT); this.main.pop(); this.main.pop(); this.main.push(lo, hi); return this }
  /** Assert the top two are numerically ordered, consuming both and the result. */
  geVerify () { this.s.add(Opcode.OP_GREATERTHANOREQUAL).add(Opcode.OP_VERIFY); this.main.pop(); this.main.pop(); return this }
  /** Assert 2nd > top (strictly), consuming both. */
  gtVerify () { this.s.add(Opcode.OP_GREATERTHAN).add(Opcode.OP_VERIFY); this.main.pop(); this.main.pop(); return this }
  /** Assert 2nd < top (strictly), consuming both. */
  ltVerify () { this.s.add(Opcode.OP_LESSTHAN).add(Opcode.OP_VERIFY); this.main.pop(); this.main.pop(); return this }
  leVerify () { this.s.add(Opcode.OP_LESSTHANOREQUAL).add(Opcode.OP_VERIFY); this.main.pop(); this.main.pop(); return this }
  size (name) { this.s.add(Opcode.OP_SIZE); this.main.push(name || 'size'); return this }
  /** Push size(name) as `outName` without leaving a copy of the item. */
  sizeOf (name, outName) { this.pick(name); this.size(outName); this.nip(); return this }

  // --- checks (consume) -----------------------------------------------------
  equalVerify () { this.s.add(Opcode.OP_EQUALVERIFY); this.main.pop(); this.main.pop(); return this }
  equal (name) { this.s.add(Opcode.OP_EQUAL); this.main.pop(); this.main[this.main.length - 1] = name || 'eq'; return this }
  verify () { this.s.add(Opcode.OP_VERIFY); this.main.pop(); return this }
  numEqualVerify () { this.s.add(Opcode.OP_NUMEQUALVERIFY); this.main.pop(); this.main.pop(); return this }
  /** OP_NUMEQUAL: consume two numbers, leave 1 if equal else 0 (does not abort). */
  numEqual (name) { this.s.add(Opcode.OP_NUMEQUAL); this.main.pop(); this.main[this.main.length - 1] = name || 'neq'; return this }

  /** Raw opcode with an explicit stack-model delta, for anything not covered. */
  raw (opcode, pop = 0, push = []) {
    this.s.add(opcode)
    for (let i = 0; i < pop; i++) this.main.pop()
    this.main.push(...push)
    return this
  }

  // The expert escape hatch: emit ANY opcode in the current release by name, resolving
  // it through the complete opcode catalog (src/opcodes.js). Anything a clause or step
  // does not cover is still reachable here — the full opcode set, at the bottom tier.
  op (name, pop = 0, push = []) {
    return this.raw(require('./opcodes').opcode(name), pop, push)
  }

  // Bind HASH256(the item named `outName`) to the preimage's hashOutputs field — the
  // single output-binding every self-recreating covenant ends with. Extracted here for
  // the same reason `clauses.selfChunk` was: it was byte-identical in four predicates
  // (lifecycle, turns, resolution, market), so one implementation, exercised by every
  // one of their suites, is less code and better tested. Requires a `preimage` on the
  // model. Emits DUP, RIGHT 40, LEFT 32 — i.e. preimage[len-40 : len-8] = hashOutputs.
  bindOutput (outName, preimageName = 'preimage') {
    this.pick(outName); this.hash256('oh')
    this.pick(preimageName)
    this.s.add(Opcode.OP_DUP).add(n(40)).add(Opcode.OP_RIGHT).add(n(32)).add(Opcode.OP_LEFT)
    this.main.push('hoField')      // the clause DUPs the picked preimage and leaves the field
    this.nip(); this.equalVerify()
    return this
  }

  /** Run a clause helper that takes the raw bsv.Script and a known stack delta. */
  clause (fn, pop = 0, push = []) {
    fn(this.s)
    for (let i = 0; i < pop; i++) this.main.pop()
    this.main.push(...push)
    return this
  }

  script () { return this.s }
  /** Debug: current model. */
  toString () { return `main[${this.main.join(', ')}] alt[${this.alt.join(', ')}]` }
}

module.exports = { StackAsm }
