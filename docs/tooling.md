# The verification apparatus

A covenant is permanent. A mistake in a locking script cannot be patched, only
abandoned, and this repository has 3000 satoshis of proof that a script can be
correct by every local measure and still be refused by the network.

So the bench is built around one idea: **a claim that is not checked is not
known**. Six tools, each answering a different question, all wired into
`npm test` or one command away.

```
npm test              predicate cases, tracer self-test, cross-references, documented numbers
npm run probe         do the policy probes still isolate one rule each?
npm run probe -- --broadcast    what does the network enforce, today?
npm run verify:chain  does every documented txid still exist and match?
npm run audit         are the documented numbers still true?
npm run check:docs    does every cross-reference resolve?
```

---

## harness.js — does the script do what is claimed?

Runs a predicate against `bsv.Script.Interpreter`, the same evaluator that
validates blocks, with a real BIP-143 FORKID sighash over a real spending
transaction. Never a simulator: see the README on what
`SmartContract.simulateScript` can and cannot tell you.

Two decisions inside it matter more than the rest.

**It verifies under policy, not consensus.** `clauses.policyFlags()` is the one
definition of what a node will actually relay, shared with the tracer and the
broadcast path so they cannot drift:

```
consensus | MINIMALDATA | CLEANSTACK | SIGPUSHONLY | LOW_S | NULLFAIL
        | DISCOURAGE_UPGRADABLE_NOPS | NULLDUMMY
```

All seven bits measured, none assumed.

Consensus alone is not a smaller check, it is a different one. Both stranded
outputs in this repository passed consensus.

**Refusal is a first-class result.** `shouldFail: true` inverts a case, and
several cases go further — they *omit a guard* and assert the corresponding
attack **succeeds**, so the test fails if anyone deletes the guard. Of 450 cases, 284 are refusals.

## trace.js — where did it fail?

`SCRIPT_ERR_VERIFY` inside 600 bytes is not a diagnosis. The tracer reports the
failing opcode, the branch it sits in, a window of surrounding disassembly, and
the stack going in — see [tracing.md](tracing.md). The suite runs it
automatically for any case that should have spent and did not.

A diagnostic that is confidently wrong is worse than none, so it has its own
self-test: `npm run selftest:trace` asserts all four classes of failure
location, and was verified to fail when the bug it was written for is put back.

## probe.js — what does the network actually enforce?

The flag list above was hand-written, and twice a missing flag cost a
permanently unspendable output. So it is measured: build a transaction that is
consensus-valid but violates exactly one standardness rule, broadcast it, read
the node's answer. **Refused transactions are free**, so policy can be probed
without spending anything.

It has found two things reasoning missed.

**Three rules are mandatory and the library called none of them consensus.**
SIGPUSHONLY, LOW_S and NULLFAIL all come back `mandatory` — the node judges such
a script *invalid*, not merely non-standard — while `currentConsensusFlags()`
contained none of the three. Reported and fixed in @smartledger/bsv 9.5.0.

Which changed what this tool is for. Once the library agrees with the network,
the probes stop *isolating* — consensus itself now rejects them — and reporting
that as a failure would flag the fix as a regression. So it now reports the
**comparison**: what the network answered (mandatory or policy) against how the
library classifies it. Those should agree, and a divergence is worth a look.

**Two enforced rules were missing from the list.** `DISCOURAGE_UPGRADABLE_NOPS`
and `NULLDUMMY`, both found by probing rather than by anything going wrong.

Three of the seven need the offending construct inside a *locking* script, which
would normally risk the stake. An escape branch —
`OP_IF <the thing being tested> OP_ENDIF OP_1` — makes a refusal cost only fees.

See [pitfall 3](pitfalls.md#3-measure-the-flags-dont-reason-about-them).

## verify-chain.js — is the documented history still true?

A documented txid is a claim. This checks three independent things and does not
conflate them:

1. the transaction exists on chain;
2. its bytes match what the local ledger recorded;
3. the current code, given the recorded params, rebuilds those same bytes.

Only (1) or (2) failing is an error. (3) failing is a **generation gap**,
expected after a refactor — reporting it as a failure would train people to
ignore the tool. Naming it instead turns the chain into a visible size history.

It also annotates the two outputs that can never be spent, which otherwise read
as ordinary rows.

## audit.js — are the documented numbers still true?

Prose can be reviewed; numbers should be derived. Every predicate exports
`example()`, so its true size is computable, and the suite's cases live in
`cases.js` as data. The audit compares what the docs claim against what the code
builds and what the suite runs, and `--fix` rewrites the drift.

It matters: the main predicate table survived three refactors with its original
byte counts, and **eight of ten rows were wrong** with nothing saying so.

It also enforces the invariants the bench's discipline implies — every predicate
must have an `example()` and **at least one refusal test**. A predicate with only
happy paths would otherwise look identically green.

## anchors.js — do the cross-references resolve?

A dead anchor fails silently; it scrolls to the top of the page rather than
erroring. Cross-references into a numbered document break every time the
numbering changes, which happened three times while reordering the pitfalls by
cost. The number is not the identity of a section, the title is — so this
repairs by matching the title and rewriting whatever number precedes it.

It checks two kinds of rot. The first is a **dead anchor**: the target no longer
exists, repaired by title match. The second is quieter — a **mislabelled link**
whose anchor resolves but whose visible text still names the old number. A link
reading "pitfall 2" whose target is the `#9-…` section scrolls to the right place
and reads as a lie. That class survived every anchor repair until it was checked
for directly, at which point four labels across the docs turned out stale. The
number after `#` is the truth; `--fix` rewrites the label to match it. The doc set
is auto-discovered — every `.md` in the root and `docs/` — so a new document is
validated the moment it exists.

---

## stackasm.js — authoring, not verifying

The one tool here that builds rather than checks. `src/stackasm.js` tracks a
symbolic model of the main and alt stacks by name and emits the `OP_PICK`/`OP_ROLL`
depths, so a covenant with a dozen live values reads as data flow instead of depth
arithmetic. It has no test file on purpose: a wrong depth produces a script the
interpreter rejects, and the covenants built on it carry adversarial suites that
would fail — so if the tests are green, the depths were right. Full treatment in
[authoring.md](authoring.md).

## The rule underneath all of it

**A check you have not seen fail is not a check.**

Every tool here was wrong on its first run, and each was caught only by
deliberately breaking the thing it guards:

| tool | what it got wrong first time |
|---|---|
| `audit` | scraped test output; four false positives on predicates whose suite block re-requires its own module |
| `audit` | a fallback overwrote a `p2pkh` count the parser had already got right |
| `anchors` | collapsed consecutive spaces; GitHub turns *each* space into a hyphen, so a removed em-dash leaves `--` |
| `anchors` | checked anchor targets but not link *text*, so four `[pitfall N]` labels drifted out of sync with the sections they pointed at |
| the timelock watcher | used `confirmations` as the release signal — it stays undefined until a block, well after the lock opens |

So: violate what the guard guards, confirm the specific message appears, and
check the **exit code** too — a chain of `&&` only fails if each step genuinely
exits non-zero. Two structural habits removed whole classes of this:

- **Read data, not output.** The audit's false positives vanished when it
  imported `cases.js` instead of parsing stdout.
- **Separate mechanical drift from real violations.** "Run with `--fix`" is
  wrong advice for a missing test.
