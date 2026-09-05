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
  `min(a, b)`, `max(a, b)`, and **`checkSig(sig, pubkey)`** — a real signature check against
  the spending transaction (`OP_CHECKSIG`).
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

See `tools/expr-selftest.js` for the full set — arithmetic, ranges, boolean composition, the
built-ins, a hashlock and a sha256 commitment — each verified against the interpreter.

## Where it sits

This is the beginning of a general contract *language*, complementary to the curated
covenants rather than a replacement: expressions for new, straight-line logic; `@contract`
classes and the [`StackAsm`](authoring.md) escape hatch for the hand-tuned, self-recreating
covenants. Ownership already authors from a condition (`checkSig`); the natural next steps —
compile-time-bounded loops that unroll (Merkle proofs, iteration), and structs and fixed-size
arrays over the existing fixed-width fields — extend the expression surface without giving up
the real-interpreter, mainnet-proven, refusal-first bar the rest of the bench holds.
