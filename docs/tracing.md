# Tracing a failure

`SCRIPT_ERR_VERIFY` somewhere inside 592 bytes is not a diagnosis. `src/trace.js`
turns it into one, and the suite runs it automatically for any case that should
have spent and did not.

## Four places a failure can land

Not every failure belongs to an opcode, and the ones that do are not always in
the script you were last watching.

| where | how it presents |
|---|---|
| mid-script | `pc - 1`, with a preceding step to cross-check against |
| the **first** opcode of a script | `pc - 1`, and **nothing recorded** from that script yet |
| before evaluation (SIGPUSHONLY) | `pc - 1` is **below** the chunk list |
| after evaluation (CLEANSTACK) | `pc - 1` points at an opcode that **succeeded** |

Each needed its own handling, and the tracer got two of them wrong before this
was written down.

**Which script failed comes from the interpreter, not the last step.** `verify()`
evaluates the unlocking script and then the locking script, and `interp.script`
still points at whichever it was in — whereas the last *recorded* step is from
whichever last succeeded. When the unlocking script completed and the locking
script failed on its very first opcode, taking the phase from the last step
attributed the failure to the wrong script entirely, and showed a window of the
wrong disassembly. That is worse than no tracer: it is a confident wrong answer.

**A post-evaluation check lands in range but on the wrong opcode.** `pc - 1`
points back at the last thing that ran, and that thing succeeded. The tell is
that it was *recorded* — the step listener only fires on success, so if the last
recorded step sits at the same index, the failure is not there. Those are
reported as whole-script checks with no opcode named, because naming one would
be inventing a location.

`npm run selftest:trace` asserts all four, and was confirmed to fail when the
original phase derivation is put back.

## Recovering the failing opcode

The interpreter's `stepListener` fires **after** each opcode and only when it
succeeded — so the opcode you care about never reaches it. It is recoverable:
`step()` advances the program counter before returning false, so the failure is
at `pc - 1`. That is cross-checked against `lastTracedPc + 1`, and the report
says so if the two ever disagree.

Two smaller things the library's own tracer trips over, fixed here:

- `Opcode.toString()` **throws** for data-push opcodes, and the interpreter
  swallows it as `Error in Step callback` on every push — nineteen lines of
  noise before the actual answer. Labelled safely instead.
- Branch location is computed by walking `OP_IF`/`OP_ELSE`/`OP_ENDIF` and
  tracking depth, not by finding the nearest preceding branch opcode, which
  nesting would make wrong.

## What it prints

A window, not a dump — these scripts run 300+ opcodes and nearly all of it is
OP_PUSH_TX preamble. An off-by-one in a record offset, introduced deliberately:

```
FAIL  registry: transfer advances the record
      SCRIPT_ERR_EQUALVERIFY
        in the lock script, chunk 302 of 424
        in the IF branch (opened at chunk 282, 20 opcodes in); nearest landmark: OP_EQUALVERIFY at chunk 280

            299  OP_3
            300  OP_PICK
            301  OP_HASH160
        >>  302  OP_EQUALVERIFY
            303  OP_TOALTSTACK

        stack going in : … | 9bcf681c7149…(20B) | 909bcf681c71…(20B)
```

The two 20-byte values are the whole answer. `909bcf681c71…` is the hash160 of
the signing pubkey; `9bcf681c7149…` is what the script extracted — **the same
bytes shifted left by one.** The off-by-one is visible rather than deduced.

The tracer verifies under `consensus | MINIMALDATA`, the same policy the
broadcast path checks, so it cannot report a pass the network would refuse.
