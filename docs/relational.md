# The relational type ladder

Every predicate in this bench reasons about one coin's spend. A handful —
[`companion`](predicates.md#companion), [`token`](predicates.md#token),
[`witness`](predicates.md#witness), [`conserve`](predicates.md#conserve) — reason
about a coin's **relationship to another coin spent beside it**. Those are the hard
ones, because a covenant's window onto its siblings is so narrow, and getting the
window wrong is how a covenant silently becomes unsound. This document is the type
system that makes those relationships checkable, built in `src/relational.js` and
held to the bench's usual standard by `tools/relational-selftest.js`.

## What a covenant can and cannot learn about a sibling

A covenant validating input *i* is handed input *i*'s preimage — and that preimage
commits to only two things about the *other* inputs:

- **`hashPrevouts`** — the hash of every input's outpoint, in order. A covenant
  cannot read the set out of a hash, but the spender can push the outpoints and the
  covenant checks they hash correctly (the [`companion`](predicates.md#companion)
  trick). So a covenant can prove *"this specific outpoint is one of my
  co-inputs."*
- **`hashOutputs`** — the hash of every output. Same shape: the covenant can prove
  an output it *builds* is in the set.

That is the whole window. A covenant **cannot** see a sibling's unlocking script,
its signature, or its preimage. Anything else it wants to know about a sibling —
what it holds, whether it is genuine — has to be reconstructed from those two
commitments plus data the spender provides and the covenant verifies.

## The ladder

Because every fact about a sibling must be earned, the facts form a ladder. Each
rung is a proof the transaction actually carries; a covenant may only use a fact
once it has climbed to the rung that establishes it.

```
  UntrustedSibling                    bytes the spender pushed — prove nothing
    │
    ├─ coSpend ───────────────▶  SiblingCoSpent
    │      the sibling's outpoint is in hashPrevouts: a LIVE input, spent now.
    │      Its state is therefore CURRENT, not historical.        (companion)
    │
    ├─ backtrace ─────────────▶  SiblingAuthenticated
    │      the sibling's source tx, rebuilt and hashed, equals that outpoint's
    │      txid: the committed bytes there are real, not forged.  (token)
    │
    └─ descent ───────────────▶  SiblingDescent
           the sibling descends from a unique genesis: a canonical member, not
           a look-alike minted from a plain UTXO.                  (lineage)

  SiblingCanonical  ⇐  SiblingCoSpent ∧ SiblingAuthenticated ∧ SiblingDescent
```

`SiblingCanonical` is a **derived** capability, exactly like `EnforceableLockTime`
in the [single-object type system](compiler.md): it is not proved directly but
*arises* wherever its three constituents all hold. Sound values come only from
sound combinations.

## What each claim needs

An invariant over a sibling is only as sound as the rung it stands on. The type
system pins each kind of claim to the rung it requires — and those requirements are
not arbitrary, they are the results this bench learned the hard way:

| claim | what it asserts | rung required |
|---|---|---|
| `stateGate` | a decision keyed to a sibling's committed state | `SiblingCoSpent` + `SiblingAuthenticated` |
| `localConservation` | a sum preserved across *this* co-spend | `SiblingAuthenticated` |
| `globalConservation` | a total that can never be inflated | `SiblingCanonical` |

The last row is the crux, and it is the exact thing the [`conserve`](predicates.md#conserve)
capstone turned on:

> Reading a sibling's amount **without** proving descent lets a counterfeit sibling
> carry any balance and inflate the total. Proving descent **without** reading the
> amount cannot enforce a sum at all. A bounded total needs *both* — plus the
> co-spend that makes the sibling the real, current partner rather than a fake.

So a relation that claims to bound a total but carries only a co-spend and a
backtrace does not merely fail at runtime — **it does not type-check**. The counterfeit
inflation is an unexpressible state, the same way the token-merge's missing
backtrace is unexpressible in the [single-object compiler](compiler.md).

## The bench's cross-object predicates, typed

Each cross-object predicate is a relationship spec — a sibling, the proofs it
carries, and the claims it makes — and the checker confirms the proofs earn the
rungs the claims need:

| predicate | proofs it carries | claim | sound? |
|---|---|---|---|
| [`witness`](predicates.md#witness) | `coSpend`, `backtrace` | `stateGate` | ✓ |
| [`token`](predicates.md#token) | `backtrace` | `localConservation` | ✓ |
| [`sovereign`](predicates.md#sovereign) | `backtrace`, `descent` | `localConservation` | ✓ |
| [`conserve`](predicates.md#conserve) | `coSpend`, `backtrace`, `descent` | `globalConservation` | ✓ |

`token` conserves **locally** — the sum holds across the one merge it performs —
with only a backtrace, and makes no global-supply claim; that is why it needs no
descent. `conserve` claims a total that holds *forever across the whole population*,
so it needs the top rung. The ladder draws exactly that line.

## Judged by what it refuses

As with the predicates, the type system is worth nothing until you see what it
**rejects**. `deriveRefusals` reads the ladder backwards: for each sound relation it
drops one proof and confirms the drop makes the relation unsound, with a typed
error naming the missing rung. From the four sound relations it derives seven
adversarial mutants, including the headline three:

```
  conserve − coSpend    →  E_COUNTERFEIT_INFLATION
  conserve − backtrace  →  E_COUNTERFEIT_INFLATION
  conserve − descent    →  E_COUNTERFEIT_INFLATION
```

and the finer distinctions:

```
  stateGate  without coSpend    →  E_STALE_SIBLING        (state may be historical)
  stateGate  without backtrace  →  E_UNAUTHENTIC_SIBLING  (bytes are forgeable)
```

The typed errors:

| code | meaning |
|---|---|
| `E_STALE_SIBLING` | reads a sibling not proven co-spent — its state may be historical, not current |
| `E_UNAUTHENTIC_SIBLING` | uses a sibling's committed bytes with no backtrace proving the source — forgeable |
| `E_UNCANONICAL_SIBLING` | treats a sibling as a canonical member without proving descent |
| `E_COUNTERFEIT_INFLATION` | bounds a total using a sibling balance not proven canonical — a counterfeit can inflate it |

## Why this is the language layer

The single-object [compiler](compiler.md) reproduces a covenant's bytes from a spec
and rejects unsound single-coin constructions at compile time. This ladder is the
same idea one level up: it is the vocabulary for describing **relationships between
persistent objects**, and it makes the unsound relationships unexpressible. A future
high-level source that says `A conservesWith B` compiles to nothing until it can
also show `A` and `B` are co-spent, authenticated, and descended — the compiler
emitting the companion check, the backtrace, and the descent proof each coin's
covenant must carry. The predicates in this bench are the proof that each of those
lowerings is real and runs on mainnet; the ladder is the proof that they compose
soundly.

## From checker to compiler

The ladder above is a *checker*: hand it a relationship's proofs and claims and it
says sound or not. `src/relcompile.js` makes it a *compiler* — a relationship
**declaration** lowers to the coins that realise it, but only after the ladder
confirms it is sound.

```
  conservedPair {
    invariant: a total fixed for the life of the pair, uncounterfeitable
    members:   [ {side:0, balance:60, owner:…}, {side:1, balance:40, owner:…} ]
  }
        │  compile()
        ▼
  side-0 coin  (1025 B — byte-identical to the deployed conserve genesis 54c9…:0)
  side-1 coin  (1025 B)
  + obligation plan:
      · require the partner’s outpoint in hashPrevouts        (companion)
      · rebuild the shared parent tx, hash to my funding txid (token)
      · prove descent from the genesis outpoint               (lineage)
      · bind [side0′, side1′] to hashOutputs, sum preserved   (conserve)
```

The invariant names a **claim** on the ladder (`globalConservation`); the lowering
names the **proofs** its coins carry (`coSpend`, `backtrace`, `descent`). `compile`
checks the proofs establish the rung the claim needs, then emits the coins and the
plan. The coins are byte-identical to the `conserve` pair deployed on mainnet — the
compiler does not re-implement the covenant, it *selects and parameterises* the
predicate that already carries the obligations, exactly as a lowering should.

The gate is the whole point. A declaration that asks for a bounded total but whose
lowering omits the descent proof — the inflatable pair the review warned of — does
not compile:

```
  compile(conservedPair without descent)  ✗  E_COUNTERFEIT_INFLATION
  compile(conservedPair without co-spend)  ✗  E_COUNTERFEIT_INFLATION
```

You cannot, by construction, emit a protocol whose invariant its coins cannot
enforce. `tools/relcompile-selftest.js` holds the compiler to exactly this: a sound
`conservedPair` lowers to the deployed bytes, and the unsound variants refuse. It is
the first end-to-end lowering of a *multi-object* protocol in the bench — the seed of
the constraint-graph compiler, where `A conservesWith B` and `A descendsFrom G` are
source, and the obligations each coin must carry are emitted from the graph.

### Two templates, and a surface syntax

The compiler knows two relationship templates so far, each lowering to a predicate
already proven on mainnet:

| relationship | invariant | lowers to | claim / rung |
|---|---|---|---|
| `conservedPair` | a total fixed forever, uncounterfeitable | [`conserve`](predicates.md#conserve) pair | `globalConservation` / Canonical |
| `conservedGroup` | a total fixed across N members forever | [`pool`](predicates.md#pool) (N bodies) | `globalConservation` / Canonical |
| `dependsOn` | release only while a named coin is co-spent with a state | [`witness`](predicates.md#witness) | `stateGate` / CoSpent+Authenticated |

And relationships can be *written*, not just built as objects. `src/rellang.js` parses
a `.rel` source into a declaration — parameters bound by `$name`, exactly as the
[`.pred` language](compiler.md) does for single predicates:

```
relationship treasury-pair conservedPair {
  genesis $genesis
  member side 0 balance 60 owner $owner
  member side 1 balance 40 owner $owner
}

relationship escrow-leg dependsOn {
  beneficiary  $beneficiary
  sibling      $sibling
  require-flag  1
}
```

`tools/rellang-selftest.js` holds the syntax to the same bar as everything else:
`treasury-pair.rel` compiles to the `conserve` pair deployed at `54c9…`, `escrow-leg.rel`
to the `witness` at `1754…`, both byte-for-byte — and `naive-pair.rel`, which asks for
a bounded total while omitting the descent proof, refuses with `E_COUNTERFEIT_INFLATION`.
The relationships are text, the text compiles to the deployed bytes, and the unsound
text does not compile at all.

## The constraint graph

One relationship at a time is still not a *system*. `src/relgraph.js` compiles a
**graph** — several objects and the relationships that bind them — where an object may
stand in more than one relationship at once, and its coin must then carry the
obligations of all of them.

```
  objects:        A, B, O
  relationships:  A conservesWith B      (conservedPair)
                  A dependsOn O           (dependsOn gate)

  ⇒ B  — one relationship         → a conserve coin, byte-identical to 54c9…:1
  ⇒ O  — a passive tagged coin    → a witness sibling, no covenant of its own
  ⇒ A  — TWO relationships        → obligations of conserve ∧ witness
```

The graph type-checks iff every relationship type-checks on the ladder — one unsound
relationship (an inflatable pair) refuses the whole graph with `E_COUNTERFEIT_INFLATION`.
Each object's obligation set is the **union** over its relationships. Where that union
is a single existing predicate, the compiler emits its bytes; where it spans two
predicates the bench has not composed, it emits the combined obligation plan and names
the composition needed — **honest about the frontier rather than inventing a coin**:

```
  A needs a predicate composing: conserve ∧ witness
  A's obligation plan:
    · require the partner’s outpoint in hashPrevouts        (companion)
    · rebuild the shared parent tx, hash to my funding txid (token)
    · prove descent from the genesis outpoint               (lineage)
    · bind [side0′, side1′] to hashOutputs, sum preserved   (conserve)
    · read the sibling’s committed state field and gate on it (witness)
```

That last line was where the research pointed next — and it has now been walked. The
graph compiler *specified* a coin (a treasury half that both conserves with its partner
and is armed by an oracle) that no single predicate implemented; its obligation plan was
the spec, and [`guarded`](predicates.md#guarded) — `conserve ∧ witness` in one covenant —
is the predicate built to it and **deployed on mainnet**. So the graph no longer merely
*names* that composition: it emits `guarded`, byte-identical to the deployed coin, for
exactly that role-set. `tools/relgraph-selftest.js` holds all of it: single-relationship
objects lower to their deployed bytes, the two-relationship object lowers to the composed
`guarded` coin (byte-identical to `3925…`:0), and the unsound graph refuses. When a
future composition has no predicate yet, the graph falls back to naming the frontier —
honest, not invented — until that predicate is built and registered too.

### The whole protocol as text

The surface syntax has three tiers now, one per layer of the stack, and each compiles
to bytes identical to what is deployed on mainnet:

| tier | writes | file | example |
|---|---|---|---|
| `.pred` | one predicate | [compiler.md](compiler.md) | `predlang/*.pred` |
| `.rel` | one relationship | `src/rellang.js` | `rellang/*.rel` |
| `.graph` | a whole protocol | `src/graphlang.js` | `graphlang/*.graph` |

A `.graph` names the objects and the relationships that bind them; `tools/graphlang-selftest.js`
compiles `escrowed-treasury.graph` — a pair `A conservesWith B` and a gate `A dependsOn O` —
and confirms object `A`, standing in both, lowers to the composed [`guarded`](predicates.md#guarded)
coin byte-identical to `3925…`:0, while `B` lowers to a plain [`conserve`](predicates.md#conserve)
coin and `O` is a passive sibling. The protocol is text; the text is the deployed bytes.
