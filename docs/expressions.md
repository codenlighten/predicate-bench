# Expressions — authoring a predicate from a condition

Every other authoring surface in this bench *reproduces* a curated covenant: a
[`@contract`](compiler.md) class names steps from a shared vocabulary and the compiler
emits the exact deployed bytes. That is the right tool for the hard, hand-optimised
covenants — and the wrong one for a rule nobody has written yet, because there is no step
for `a + b == 100`.

The expression compiler (`src/expr.js`) closes that gap. You write a *condition*; it emits
real Bitcoin Script:

```
given a b
assert(a + b == this.total)
assert(a > 0)
```

`lock({ total: 100 })` bakes the constant into the locking script; `unlock({ a: 60, b: 40 })`
pushes the witness. The pair is then run through [the harness](tooling.md) against
`bsv.Script.Interpreter` — the same evaluator that validates blocks — with the refusal
tests that judge every predicate here. Nothing is simulated.

## What it compiles

- **Witness values** — declared with `given a b c`, pushed by the unlocking script.
- **Baked params** — `this.total`, `this.hash` — constants spliced into the locking script
  at `lock(...)`, so one source parameterises many coins.
- **Arithmetic** — `+ - * / %` (`OP_ADD`/`OP_SUB`/`OP_MUL`/`OP_DIV`/`OP_MOD`; BSV restored
  the disabled math opcodes at Genesis).
- **Comparison** — `== != < <= > >=`, leaving a boolean.
- **Boolean** — `&& || !`, with the usual precedence (`||` loosest, unary `!` tightest).
- **Built-ins** — `hash160(x)`, `hash256(x)`, `sha256(x)`, byte-equality `eq(a, b)`,
  `min(a, b)`, `max(a, b)`, **`checkSig(sig, pubkey)`** — a real signature check against the
  spending transaction (`OP_CHECKSIG`) — and **`checkMultiSig(sigs, pubkeys)`**, an m-of-n
  threshold where `m` is the size of the witness sig array and `n` the baked pubkey array
  (`OP_CHECKMULTISIG`, checked in key order, with the empty `NULLDUMMY` dummy).
- **`assert(expr)`** — each becomes an `OP_VERIFY`; the script ends by discarding the
  witness and leaving `true`, so the stack is clean (as relay policy requires).

A hashlock — knowledge of a preimage as a spending condition — is one line:

```
given preimage
assert(eq(hash160(preimage), this.h))
```

And ownership is a real signature, so a **P2PKH is two**:

```
given sig pubkey
assert(eq(hash160(pubkey), this.owner))
assert(checkSig(sig, pubkey))
```

The `sig` witness is not a constant — a valid signature commits to the whole spending
transaction. Pass a private key for it and `unlock(...)` signs over the real tx through the
harness's signing context; a static value could never satisfy `OP_CHECKSIG`. This compiles to
a 32-byte lock that the interpreter accepts for the owner and refuses for anyone else — a
forged public key trips `NULLFAIL`, the same policy bit the hand-written predicates respect.

## Bounded loops, unrolled

A predicate can iterate over fixed-size data with a **compile-time-bounded loop** — the same
safe model sCrypt enforces (`for i < CONST`, no `break`, no recursion). The bound is known
when the script is built, so the loop is *unrolled*: there is no loop in the emitted Script,
just the body repeated, and the loop variable `i` is a constant in each copy.

A loop carries an accumulator introduced with `let` and updated by assignment, indexes
witness arrays (`given sib[3]`) and baked arrays (`this.path[i]`) by the constant `i`,
concatenates bytes with `++`, and branches at run time with `if(cond, a, b)` (a real
`OP_IF`/`OP_ELSE`/`OP_ENDIF`, both arms checked to leave the same stack). That is exactly
what a **Merkle membership proof** needs:

```
given leaf
given sib[3]                       # the proof: one sibling per level
given dir[3]                       # 1 if our node is the right child
let h = leaf
for i in 3 {
  h = if(dir[i], hash256(sib[i] ++ h), hash256(h ++ sib[i]))
}
assert(eq(h, this.root))
```

`lock({ root })` bakes the tree root; `unlock({ leaf, sib: [...], dir: [...] })` supplies a
leaf and its path. It compiles to a 97-byte lock (a 3-deep unrolled fold) that the
interpreter accepts for a genuine member and refuses for a forged leaf or a tampered path.
The bound must resolve to a constant — a number or a baked `this.N` — so the script size is
fixed and knowable, never spender-controlled.

## Reading the spending context — a covenant from a condition

The expressions so far constrain a *witness*. A `tx.<field>` read constrains the *spending
transaction itself* — which makes the predicate a covenant. Today `tx.locktime` is exposed:

```
assert(tx.locktime >= this.notBefore)
```

Reading `tx.locktime` turns the predicate into one: the compiler binds the BIP-143 preimage to
this spend (OP_PUSH_TX), reads the field unsigned exactly as the deployed clauses do, and —
because nLockTime is inert on a final input — **auto-injects the non-final-sequence guard**
([pitfall 27](pitfalls.md); you cannot forget it). The unlocking script synthesises the
preimage, grinding a field until its in-script signature is clean low-S.

The striking part: that one line compiles **byte-identical to the hand-tuned
[`timelock`](predicates.md#timelock) covenant already deployed and spent on mainnet** (372 B).
The expression compiler did not approximate a timelock — it reproduced the exact on-chain one
from a condition, so it inherits that covenant's soundness and its refusals: a too-early spend
and a final-sequence spend are both rejected by the real interpreter.

Output binding is the other half. A `pay(dest, amount)` statement commits the **whole output
set**: the compiler bakes the double-SHA256 of the outputs and requires the preimage's
`hashOutputs` to equal it, so the spender chooses nothing about where the money goes.

```
pay(this.payTo, this.payAmount)
```

That one line compiles **byte-identical to the deployed [`covenant`](predicates.md#covenant)**
(384 B) — the second on-chain covenant reproduced from a condition.

And the primitives **compose**. Neither of these is in the catalogue on its own; the
composition is:

```
pay(this.dest, this.amount)            # a time-locked payment vault
assert(tx.locktime >= this.notBefore)
```

A 413-byte vault that moves the coins only to a fixed destination and only after a height,
verified on the interpreter to refuse a redirected output, a too-early spend, and a final
input. This is the covenant frontier working: two proven primitives, combined into one that
was never written by hand, judged by the block validator. The next rung — **self-recreation**
(a covenant whose output is another instance of itself, carrying updated state) — builds on
the same preimage-and-`pay` bridge, held to the same real-interpreter, refusal-first bar.

## From the command line

A predicate authored from an expression is a first-class citizen of the CLI. Write it in a
`.expr` file (`examples/` has `p2pkh`, `hashlock`, `merkle`), then build, deploy and spend it —
no JavaScript:

```bash
node bin/cli.js build  examples/p2pkh.expr owner=@pkh      # compile, show the 32-byte script
node bin/cli.js deploy examples/p2pkh.expr owner=@pkh      # lock sats behind it on chain
node bin/cli.js unlock <txid> sig=@key pubkey=@pubkey      # spend it back (verified first)
```

`@pkh`, `@pubkey` and `@key` resolve to the funding wallet's pubkey-hash, public key and
private key. `@key` is only ever a *spend-time* witness to sign with — baking a private key
into a locking script (or a receipt) is refused, at the CLI and again in `onchain.deploy`.
The deployed coin records its source, so `unlock` recompiles the predicate from the receipt and
`verify:chain` confirms the bytes on chain.

## How it is built (and why it is ours, not sCrypt's)

sCrypt compiles a strict subset of TypeScript through the real TypeScript compiler to an
intermediate language, and tests locally against a **JavaScript port** of the script engine.
This compiler is deliberately smaller and more honest about its seams:

- **Zero-dependency.** A hand-written tokeniser and recursive-descent parser (precedence
  climbing), not the `typescript` package. The subset is small and deterministic on purpose.
- **Emitted through [`StackAsm`](authoring.md).** Every operator lowers to a call on the same
  stack-tracking assembler the mainnet covenants use — there is no opaque backend to trust,
  and each opcode is one already exercised on chain.
- **Judged by the real interpreter.** The output is verified by the block validator, not a
  reimplementation, and every example carries `shouldFail` cases. A predicate that accepts
  the right answer is half-proven; the refusals are the point.
- **It refuses bad source at compile time** — an unknown function, a wrong arity, a witness
  that was never declared. A malformed predicate never builds, let alone reaches the chain.
- **The codegen is fuzzed against its own semantics.** `tools/expr-fuzz.js` generates hundreds
  of random arithmetic/boolean expressions, evaluates each with a reference interpreter in JS
  and with the compiled script on the consensus interpreter, and asserts they always agree. A
  swapped operator or a mismanaged stack would show up as a disagreement — the run is seeded, so
  it is deterministic, and it is part of `npm test`.

See `tools/expr-selftest.js` for the full set — arithmetic, ranges, boolean composition, the
built-ins, a hashlock and a sha256 commitment — each verified against the interpreter.

## Where it sits

This is the beginning of a general contract *language*, complementary to the curated
covenants rather than a replacement: expressions for new, straight-line logic and bounded
iteration; `@contract` classes and the [`StackAsm`](authoring.md) escape hatch for the
hand-tuned, self-recreating covenants. Ownership authors from a condition (`checkSig`) and
Merkle-style proofs from a bounded loop; the natural next step — named **structs** over the
existing fixed-width fields, so a state layout has field names rather than positions —
extends the surface without giving up the real-interpreter, mainnet-proven, refusal-first bar
the rest of the bench holds. A real TypeScript-AST front end is the eventual richer subset;
the hand-written parser is the deliberate, zero-dependency start.
