# The architecture: from a predicate over money to a language of Predicate Objects

[model.md](model.md) makes one claim: **a Bitcoin locking script is a predicate**
`Allowed(S, S', W)` that decides whether a state `S` may become `S'` given witness
`W`. That is the seed. This document is the tree that grew from it — the full stack
this bench builds on that seed, from the raw opcodes up to a language that describes
*networks of interacting stateful objects* and refuses to emit an unsound one.

It is meant to be read once, top to bottom, as the map. Every box below is a real
file with real tests, and — for the predicates — a real transaction on BSV mainnet.

---

## 1. The Predicate Object

A UTXO under a covenant is not just coins behind a rule. It is a small, persistent
**object** whose every property is enforced by the predicate that guards it:

```
    O  =  ( Data, State, Authority, Invariants, Transition Rules, History )
```

| facet | what it is | how the bench enforces it |
|---|---|---|
| **Data** | immutable identity fixed at creation | a genesis outpoint or id spliced into `scriptCode`, carried unchanged every hop ([lineage](predicates.md#lineage), [conserve](predicates.md#conserve)) |
| **State** | mutable fields the object carries forward | fixed-width fields in `scriptCode`, read and re-spliced on each spend ([registry](predicates.md#registry), [lifecycle](predicates.md#lifecycle)) |
| **Authority** | who may move it | an owner pkh *is a state field*; a signature over the spend is required to change anything ([titled](predicates.md#titled), [delegation](predicates.md#delegation)) |
| **Invariants** | what must always hold | boolean clauses `VERIFY`-checked on every transition — a conserved sum, a monotone counter, a bounded status ([token](predicates.md#token), [ticker](predicates.md#ticker)) |
| **Transition rules** | which next states are legal | the predicate body: a state machine, a schedule, a rebalance, a descent proof |
| **History** *(optional)* | a commitment to how the object reached this state | an append-only audit chain in state — `head = HASH256(oldHead ‖ record)` advanced every transition ([journal](predicates.md#journal), [audited](predicates.md#audited)) |

The rest of the architecture is what you need to make objects like this *real* (they
survive on chain), *sound* (they cannot be cheated or counterfeited), and
*composable* (they can be related to one another).

---

## 2. The layers

Each layer is proven against the one below it; nothing is asserted that is not
checked, and the predicates are checked against the *actual consensus interpreter*
and then broadcast to mainnet.

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  constraint graph        objects + relationships; unions each       │  src/relgraph.js
   │  (a protocol)            object's obligations, EMITS composed coins  │
   ├──────────────────────────────────────────────────────────────────┤
   │  relationship compiler   a relationship declaration → the coins     │  src/relcompile.js
   │  + surface syntax        that realise it, gated by the ladder        │  src/rellang.js
   ├──────────────────────────────────────────────────────────────────┤
   │  type systems            unsound constructions are UNEXPRESSIBLE:    │  compile.js·relational.js
   │                          object caps · sibling ladder · composition   │  compose.js
   ├──────────────────────────────────────────────────────────────────┤
   │  predicate compiler      a spec / .pred / @contract .ts → the bytes, │  compile.js·predlang.js
   │  + surface syntax        byte-identical to the deployed predicate    │  tslang.js
   ├──────────────────────────────────────────────────────────────────┤
   │  predicates              45 covenants, each Allowed(S,S',W)          │  src/predicates/*.js
   │                          — interpreter-checked, 45/45 on mainnet     │
   ├──────────────────────────────────────────────────────────────────┤
   │  clauses & preimage      the grammar: OP_PUSH_TX, self-reference,    │  src/clauses.js
   │                          output binding, the stack-tracking assembler │  src/stackasm.js
   ├──────────────────────────────────────────────────────────────────┤
   │  Script                  the consensus interpreter, under relay policy │
   └──────────────────────────────────────────────────────────────────┘
```

- **Script → clauses.** Raw opcodes are hard to compose; [clauses.md](clauses.md)
  and [preimage.md](preimage.md) build the reusable grammar — obtaining the spending
  transaction in-script (`OP_PUSH_TX`), reading a covenant's own bytes, binding
  outputs via `hashOutputs`, and a [stack-tracking assembler](authoring.md) so a
  covenant can be written by name instead of by raw stack juggling.
- **clauses → predicates.** [predicates.md](predicates.md) is the catalogue: 45
  covenants, each one `Allowed(S, S', W)` with a different body, each judged by what
  it **refuses** (adversarial tests), and — bar the two deliberate strandings — spent on [mainnet](mainnet-log.md).
- **predicates → compiler.** [compiler.md](compiler.md) turns a predicate into
  *data*: a spec that emits the deployed bytes exactly, a `.pred`
  [surface syntax](compiler.md) that reads like the rule it enforces, and a restricted
  **`@contract` TypeScript** frontend (`src/tslang.js`) — a familiar class with a
  `spend()` method, lowered to the same IR and byte-identical to the deployed predicate,
  with the soundness types carried through (an unsound contract will not compile). The class
  covers **all five deployed predicate shapes**: a linear body (`covenant`), a linear `@body('asm')`
  behind an `@preamble` (`lineage`), a two-method raw branch (`metered`), a two-method `@branch('asm')`
  where each side carries its own `@given` stack and is `@selfTerminating` (`token`), and a `@dispatch`
  class — an N-case selector cascade, each method a `@case(n)` with its `@given` stack, in dispatch
  order (`asset`, `sovereign`). Every one compiles byte-identical to the deployed covenant. A call the curated
  vocabulary doesn't name lowers to a step of the same name, so the whole step registry is
  reachable from a class while the compiler still refuses an unknown one. A class also declares
  its **state layout** as typed fields (`owner: hash160`, `balance: u64`) — the compiler owns
  the offsets and push-encoding (`src/statelayout.js`), building the exact on-chain state bytes
  from field values and refusing an out-of-range one, so fixed width stays load-bearing
  ([pitfall 21](pitfalls.md#21-fixed-width-state-or-the-offsets-move)) without the developer counting bytes.
- **predicates → type systems.** The compiler doesn't just emit — it **refuses**.
  A single-object capability system rejects a covenant that reads outputs without
  committing to the whole transaction, or recreates a genesis without proving
  descent. Above it, the [relational ladder](relational.md) does the same for what
  one coin concludes about another.
- **type systems → relationship compiler.** [relational.md](relational.md#from-checker-to-compiler)
  lifts the check into a lowering: a relationship *declaration* becomes the coins
  that realise it, and a `.rel` [surface syntax](relational.md#two-templates-and-a-surface-syntax)
  writes those declarations as text.
- **relationship compiler → constraint graph.** [relational.md](relational.md#the-constraint-graph)
  compiles a *graph* of objects and relationships, unioning each object's
  obligations and emitting the composed predicate where one exists — and a `.graph`
  surface syntax (`src/graphlang.js`) writes that whole protocol as text, the third
  tier after `.pred` and `.rel`.

---

## The three audiences

The same compiler serves three levels of user — not three separate frameworks, one stack
with three surfaces, so nothing is a toy that can't reach the machinery beneath it.

- **Beginner** — domain builders (`src/highlevel.js`), one per problem area, each lowering
  to a deployed predicate byte-identically: `ledger('DepartmentBudget', { accounts })` →
  [`ledger`](predicates.md#ledger) (accounting), `credential('Certificate', { issuer })` →
  [`lifecycle`](predicates.md#lifecycle) (status), `capability('SpendAuthority', { budget, owner })`
  → [`delegation`](predicates.md#delegation) (authority), and
  `game('TicTacToe', { players })` → [`turns`](predicates.md#turns) (a turn-based game),
  `escrow('Delivery', { recipient, sender, secret, notBefore })` → [`htlc`](predicates.md#htlc)
  (pay-on-secret-or-refund), `stream('AuditLog', { publisher })` → [`journal`](predicates.md#journal)
  (an append-only log), and `predictionMarket('RainTomorrow', { question, … })` → a
  fully-collateralised prediction market whose *shape follows the fields*: `yesOwner`/`noOwner`
  gives a binary [`market`](predicates.md#market), an `outcomes` array a categorical
  [`marketN`](predicates.md#marketn), and a `low`/`high` range with `longOwner`/`shortOwner` a
  scalar [`marketScalar`](predicates.md#marketscalar) — the question text hashed to its id, the
  quorum and timelocked refund owned by the compiler. And `positionMarket('ElectionMarket', { genesis })`
  → a [`descentmarket`](predicates.md#descentmarket) with `writePosition(...)` → [`positionv2`](predicates.md#positionv2)
  coins, for a market of *many* positions written before the outcome is known — the descent proof, the
  quorum and the identity check owned by the compiler. Each returns the coins, a plain-English
  statement of what Bitcoin will enforce, and errors in the user's own vocabulary
  (*“'operations' holds only 50, so it cannot transfer 999”*; *“REVOKED is a terminal state —
  nothing can follow it”* — never a Script error).
- **Application developer** — the `@contract` [TypeScript frontend](compiler.md) and the
  `.pred`/`.rel`/`.graph` languages: declare state, transitions, invariants, and
  relationships; the compiler owns offsets, push-encoding, and stack depth.
- **Expert** — the predicate IR and the [`StackAsm`](authoring.md) assembler directly,
  when a covenant needs machinery no surface exposes yet.

The rule that keeps this honest: *the beginner's output is the same bytes the expert would
have written by hand* — proven by holding every tier to byte-identity with what is deployed
on mainnet.

---

## 3. Three classes of relationship

Every predicate is a relationship between states. There turn out to be exactly three
primitive kinds, plus their composition — and the bench has a mainnet-proven
predicate for each.

### Temporal — an object and its own future

`Sₙ → Sₙ₊₁`. The object carries state forward across a chain of UTXOs; each spend is
one iteration of a loop the blockchain runs (see [model.md](model.md)). A
self-recreating covenant reads its own bytes and demands its successor keep them,
minus a permitted change.

[`perpetual`](predicates.md#perpetual) · [`metered`](predicates.md#metered) ·
[`ticker`](predicates.md#ticker) · [`vesting`](predicates.md#vesting) ·
[`lifecycle`](predicates.md#lifecycle) · [`journal`](predicates.md#journal) ·
[`delegation`](predicates.md#delegation)

### Genealogical — an object and its ancestry

`G → S₁ → S₂ → …`. The object proves, cheaply and on every move, that it descends
from a unique genesis — so a counterfeit with the right bytes can be *created* but
never *spent*. The witness is bounded (one hop); the network's own history closes the
induction.

[`lineage`](predicates.md#lineage) · [`provenance`](predicates.md#provenance) ·
[`sovereign`](predicates.md#sovereign)

### Relational — an object and its live siblings

`P(A, B, …)`. Several objects, spent in one transaction, constraining one another.
This is the hardest class, because a covenant's window onto its siblings is so narrow
— and the whole of [relational.md](relational.md) is the type theory that makes it
sound.

[`companion`](predicates.md#companion) · [`token`](predicates.md#token) ·
[`asset`](predicates.md#asset) · [`witness`](predicates.md#witness) ·
[`conserve`](predicates.md#conserve) · [`pool`](predicates.md#pool)

### Composition — two relationships in one object

The classes combine. [`sovereign`](predicates.md#sovereign) is genealogical ∧
relational (descent ∧ conservation) in one coin. [`guarded`](predicates.md#guarded)
is `conserve ∧ witness`: a conserved pair whose rebalance is *also* gated on an
oracle's state — the exact object the [constraint graph](relational.md#the-constraint-graph)
specified before it existed, then built and deployed. [`pool`](predicates.md#pool)
generalises [`conserve`](predicates.md#conserve) from two bodies to N, and
[`audited`](predicates.md#audited) is the first *cross-class* composition —
`conserve` (relational) ∧ `journal` (temporal) — a conserved pair whose every
rebalance is appended to an embedded tamper-evident audit chain.

Read the composed names as an **algebra** rather than as bespoke contracts:

```
    sovereign  =  conserve ∧ ownership ∧ lineage
    guarded    =  conserve ∧ witness
    pool       =  conserve, for N bodies
    audited    =  conserve ∧ journal
    ledger     =  pool ∧ journal   (audited, for N bodies)
```

Each is a point in a composition lattice over the primitive predicates, and the
[constraint graph](relational.md#the-constraint-graph) is where a declaration selects
one: an object's role-set names the composition, and the graph emits it byte-identical
where the bench has built it (or names the frontier where it has not). The open
question the algebra frames — *which compositions are meaningful and sound?* — is
answered, for each pair, by the [type systems](#5-two-type-systems-one-discipline-unsound--unexpressible):
two predicates compose only when their capabilities and the state they read, write and
claim do not conflict.

---

## 4. What a covenant can know about a sibling — the ladder

The relational class rests on one hard fact: **a covenant can see sibling outpoints
(`hashPrevouts`) and committed outputs (`hashOutputs`), but never a sibling's
unlocking script or signature.** Every fact about a sibling must therefore be
*earned*, and the facts form a ladder (full treatment in [relational.md](relational.md)):

```
  UntrustedSibling
    ├─ coSpend   ▶ SiblingCoSpent        outpoint ∈ hashPrevouts  (live, current)   companion
    ├─ backtrace ▶ SiblingAuthenticated  source tx rebuilt → its txid  (real, not forged)  token
    └─ descent   ▶ SiblingDescent        descends from a unique genesis  (canonical)   lineage

  SiblingCanonical  ⇐  SiblingCoSpent ∧ SiblingAuthenticated ∧ SiblingDescent
```

And the pay-off, the result this bench discovered by building it:

> **Global conservation needs the top rung.** Reading a sibling's amount *without*
> proving descent lets a counterfeit inflate the total; proving descent *without*
> reading the amount cannot enforce a sum. A total that can never be inflated needs
> both, plus the co-spend. A relationship that claims a bounded total but omits the
> descent proof **does not type-check** — the counterfeit inflation is unexpressible.

---

## 5. Two type systems, one discipline: unsound = unexpressible

The bench's compounding advantage is that a soundness lesson learned once is enforced
forever. A runtime attack becomes a compile-time impossibility.

- **Single-object capabilities** ([compiler.md](compiler.md)) — every step declares
  the capabilities it *gives* and *needs*; a spec type-checks only if each need is
  met on its spend path. `Authenticated`, `BoundToWholeTx`, `ProvenSibling`,
  `ProvenDescent`, `AuthorisedOwner`, `EnforceableLockTime` — each maps to a typed
  error (`E_REPLAYABLE_OUTPUTS`, `E_COUNTERFEIT`, …) and a real pitfall.
- **The sibling ladder** ([relational.md](relational.md)) — the cross-object
  version, above.

Both are validated the same way the predicates are: `deriveRefusals` reads the type
rules backwards and generates the adversarial mutant for each — a predicate with a
proof removed, which must fail to compile with the right typed error. **The source
and the security spec become the same artifact.**

**A third check governs composition itself** (`src/compose.js`). Each composable
aspect declares a resource footprint — what state it `reads`, `writes`, `preserves`,
which transaction `outputs` it binds, and the capabilities it `requires`. Two aspects
may share one covenant only when those resources do not collide:

```
    two aspects WRITE the same field        →  E_WRITE_CONFLICT
    one WRITES a field another PRESERVES    →  E_WRITE_PRESERVE_CONFLICT
    two aspects both bind the OUTPUT SET    →  E_OUTPUT_CLAIM_CONFLICT
```

This makes the [predicate algebra](#3-three-classes-of-relationship) decidable: the
graph can take a composition **no one has built** — `pool ∧ journal`,
`guarded ∧ audited` — and report whether it is even *safe to build*, before a line of
it is written. `conserve ∧ journal` type-checks (disjoint writes: `balance` vs
`seq,head`); `conserve ∧ exclusiveExit` does not (two output-set claimants). Every
composition the bench actually deployed — `sovereign`, `guarded`, `audited` — passes;
the checker is held to that by `tools/compose-selftest.js`.

---

## 6. The method

Everything here came out of one loop, and the loop is the reason the knowledge
compounds:

```
   invent a predicate
        → test it adversarially (judged by what it REFUSES)
        → run it on the real consensus interpreter
        → check it against relay policy, not just consensus
        → broadcast and spend it on mainnet
        → when something strands or a witness lie slips through, name the pitfall
        → encode the pitfall as a compile-time invariant
        → every future predicate in that family inherits the protection
```

Three commitments make it trustworthy:

1. **The real interpreter, under relay policy.** Not a simulator. Consensus alone
   hides `MINIMALDATA` and `CLEANSTACK`; the harness verifies under what a node will
   actually *relay*. See [pitfalls.md](pitfalls.md) 1–3.
2. **Everything on chain.** All 45 predicates deployed and spent on BSV mainnet; the
   receipts are in [mainnet-log.md](mainnet-log.md), and `npm run verify:chain`
   re-checks every recorded output against the chain. A documented number is checked
   against the code by `npm run audit`; a claim about the chain is checked against
   the chain.
3. **Failures are kept.** The two consensus-valid-but-unrelayable strandings that
   started the bench, and the [`conserve`](predicates.md#conserve) pair stranded by a
   fixed-output-count backtrace ([pitfall 26](pitfalls.md#26-a-fixed-output-count-backtrace-strands-a-coin-whose-parent-has-change)),
   sit on chain beside the successes. They are not embarrassments; they are language
   design input — each became a rule the compiler now enforces.

---

## 7. The honest limits

- **Script is bounded**: no unbounded loops, no mutable memory beyond `scriptCode`,
  no clock beyond the block, no network calls. What lifts the ceiling is that most of
  what *looks* iterative is structural — a chain of UTXOs, a bounded inductive
  witness, a signed attestation, a backtrace instead of a trusted push.
- **Cross-object soundness is narrow by construction**: a covenant only ever learns
  what the transaction commits to. [`companion`](predicates.md#companion) is honest
  about binding identity but not value; the ladder is honest about which claims each
  rung supports.
- **Not every composition is built yet.** The [constraint graph](relational.md#the-constraint-graph)
  will happily *specify* an object whose obligations span predicates the bench has
  not composed, and it says so — naming the frontier rather than inventing a coin —
  until that predicate is built and registered (as `guarded` was).

---

## 8. Where to read next

- **[model.md](model.md)** — the foundational thesis, in full: iteration as a UTXO
  chain, the network as inductive verifier, the witness discipline.
- **[predicates.md](predicates.md)** — the catalogue, in ascending size, each adding
  one idea and its refusals.
- **[relational.md](relational.md)** — the cross-object type theory, the ladder, the
  relationship compiler, and the constraint graph.
- **[compiler.md](compiler.md)** — the single-object compiler and `.pred` language.
- **[pitfalls.md](pitfalls.md)** — what it cost to learn, most expensive first.
- **[mainnet-log.md](mainnet-log.md)** — the receipts.
- **[preimage.md](preimage.md)** · **[clauses.md](clauses.md)** ·
  **[authoring.md](authoring.md)** · **[cross-input.md](cross-input.md)** ·
  **[oracle.md](oracle.md)** · **[sizing.md](sizing.md)** ·
  **[tracing.md](tracing.md)** · **[tooling.md](tooling.md)** — the reference layer.

Bitcoin is a distributed state-transition machine. UTXOs hold the state, transactions
propose the transitions, Script is the predicate a transition must satisfy — and,
worked all the way up, those predicates become **objects with data, state, authority,
and invariants, related to one another by a language that will not let you build an
unsound one.** Everything in this repository is a consequence.
