# Bitcoin is a state-transition machine; Script is the predicate

Everything in this bench is one idea, worked out forty-five ways and then
mechanised. The idea is not that Bitcoin Script has a long list of features. It is
that Script has almost none — a handful of small primitives — and that this is
enough, because the primitives compose into an **arbitrary boolean condition over
the spending transaction and its witness**.

Write it as a predicate. A UTXO holds a state `S`. A transaction proposes to
replace it with a successor state `S'`, carrying witness data `W` — signatures,
parent transactions, oracle attestations, preimages, whatever the rule needs. The
locking script is the function that decides whether that transition is allowed:

```
    Allowed( S, S', W )  →  TRUE | FALSE
```

TRUE, the coins move to `S'`. FALSE, they do not move at all. That is the whole
machine. A contract is not a program that runs; it is a **predicate that the next
state must satisfy.**

---

## Every contract in this repo is a predicate

The catalogue looks like a list of unrelated applications — payments, timelocks,
tokens, oracles, vesting. It is not. Each is the same `Allowed(S, S', W)` with a
different body, and each was built from the same opcode primitives (stack moves,
hashing, signatures, arithmetic, comparison, byte slicing, branching, and
[transaction introspection through the preimage](preimage.md)):

| the rule, in words | the predicate | where |
|---|---|---|
| only the holder of this key may spend | `HASH160(pubkey)==pkh ∧ checksig(sig,pubkey)` | [p2pkh](predicates.md#p2pkh) |
| reveal a value whose hash is `X` | `SHA256(w)==X` | [hashlock](predicates.md#hashlock) |
| not spendable before time `T` | `preimage.nLockTime ≥ T ∧ input non-final` | [timelock](predicates.md#timelock) |
| pay exactly this output set | `preimage.hashOutputs == H` | [covenant](predicates.md#covenant) |
| the successor must be this same covenant | `HASH256(value ‖ selfChunk) == preimage.hashOutputs` | [perpetual](predicates.md#perpetual) |
| the successor counter is mine `+ 1` | `S'.counter == S.counter + 1` | [metered](predicates.md#metered) |
| split conserves the balance | `S'₀.bal + S'₁.bal == S.bal` | [token](predicates.md#token) |
| both owners authorise a merge | `checksig(ownerA) ∧ checksig(ownerB)` | [token](predicates.md#token)/[asset](predicates.md#asset) |
| this child descends from genesis `G` | `parent spent G ∨ parent was a valid token of G` | [lineage](predicates.md#lineage) |
| 2 of 3 oracles attest the same value | `Σ rabinValid(sigᵢ, m, Nᵢ) ≥ 2` | [quorum](predicates.md#quorum) |
| the new oracle round exceeds the stored one | `S'.round > S.round` | [ticker](predicates.md#ticker) |
| pay exactly the amount vested by time `T` | `S'.retained == total·(end−T)/(end−start)` | [vesting](predicates.md#vesting) |

None of these are special Bitcoin features. They are predicates assembled out of
primitives, and the assembling is now systematic — see the [compiler](compiler.md).

---

## The blockchain supplies the iteration

The obvious objection is that Script has no unbounded loop, no mutable memory, no
way to run a process forward. It does not need one. A loop is a sequence of state
updates; Bitcoin expresses that sequence as a chain of UTXOs, each spend the body
of one iteration:

```
    UTXO(S₀) ──tx──▶ UTXO(S₁) ──tx──▶ UTXO(S₂) ──tx──▶ UTXO(S₃)
              Allowed          Allowed          Allowed
```

Instead of `while (cond) { update(state) }` running inside one program, each
transition is a separate transaction that the covenant re-imposes on its own
successor. This is not a workaround; it is the natural shape. A
[self-recreating covenant](predicates.md#perpetual) reads its own bytes out of the
authenticated preimage and demands the next output carry the same script — so the
predicate propagates itself forward, unchanged, hop after hop. Give one field
permission to change and the loop has a body: [metered](predicates.md#metered)
advances a counter, [ticker](predicates.md#ticker) advances an oracle round,
[vesting](predicates.md#vesting) releases value as a function of the block clock.
The **chain is the iteration**, and each UTXO is one frame of the running machine.

---

## The network is the inductive verifier

The second objection is depth: if `S₁₀₀₀` must prove it descended legitimately from
`S₀`, does the spender have to carry a thousand transactions? No — and
[lineage](predicates.md#lineage) is the proof. A spend proves only its **immediate**
transition, and relies on induction for the rest:

- to move, `Sₙ` proves its parent `Sₙ₋₁` satisfied the covenant one hop back;
- but `Sₙ₋₁` only exists on chain because *its* covenant ran and was accepted when
  it was spent — the network already checked that transition;
- so proving one hop, plus the network's prior acceptance of every earlier hop,
  establishes the whole history back to the single spend of genesis `G`.

The witness is **bounded** — two parent transactions per spend, not `O(n)` — and
the blockchain itself is the verifier that closes the induction. A counterfeit
(the right bytes, minted from a plain UTXO) is byte-valid but **unspendable**,
because its one funding hop never spent `G` and never will. Authenticity is not
stored; it is *re-proven, cheaply, on every move*, and the network's own history is
what makes that cheap.

---

## What the witness carries

`W` is whatever evidence the predicate needs to check, supplied by the spender and
verified — never trusted — by the script:

- a **signature**, checked against this transaction's own sighash ([p2pkh](predicates.md#p2pkh));
- a **preimage** of this transaction, so the script can read its own outputs,
  value, and locktime ([preimage.md](preimage.md));
- a **parent transaction**, bound to its outpoint because a txid is its hash
  ([token](predicates.md#token), [lineage](predicates.md#lineage));
- a **sibling input**, bound by `hashPrevouts` ([cross-input.md](cross-input.md));
- an **oracle attestation** — a value signed off-chain, verified in-script with
  modular arithmetic because there is no `OP_CHECKDATASIG` ([oracle.md](oracle.md)).

The discipline that runs through all of it: the script must **verify** every piece
of the witness, never accept it on faith. The sharpest lesson in the bench is a
witness lie the naive design believed — a
[merge that trusts a pushed sibling balance mints money from nothing](cross-input.md).
The fix is to prove the sibling's balance by rebuilding its funding transaction and
hashing to its txid. The [compiler](compiler.md) now refuses, at build time, any
predicate that reads a sibling balance without that backtrace.

---

## The honest limit

The claim is not that Script computes every computable predicate. It is
deliberately bounded: no unbounded loops, no arbitrary mutable memory, no network
calls, no clock beyond the block. Computation must fit inside one transaction's
script evaluation. What lifts the ceiling is that so much of what *looks* like it
needs a loop is really a **structural** property, expressible without one:

- iteration → a chain of UTXOs (above);
- deep history → bounded witnesses + inductive network verification (above);
- large state → carried forward in `scriptCode`, one fixed-width field at a time
  ([registry](predicates.md#registry), [sovereign](predicates.md#sovereign));
- "trust this external fact" → a signed attestation the script checks
  ([oracle](predicates.md#oracle));
- "trust this sibling's value" → a backtrace, not a push ([token](predicates.md#token)).

Within that envelope, the predicates get very expressive — the
[sovereign](predicates.md#sovereign) covenant conserves a balance, gates ownership,
*and* proves descent to a genesis, over a divisible mint→split→merge lifecycle, in
one 1420-byte script.

---

## The reframing

Once Script is a predicate over a state transition, the question worth asking is
not *"what smart-contract features does Bitcoin have?"* — it has none, and needs
none. The question is:

> **What predicate must the next state satisfy? Then construct it from the
> primitives.**

That is what this whole bench is: forty-five worked answers, each measured against
the real consensus interpreter and [most spent on mainnet](mainnet-log.md), and a
[compiler](compiler.md) that turns the construction into spec assembly — with the
rules the bench paid for in real broadcasts (a covenant must commit to its whole
transaction; a self-draining one needs an exit; conservation needs a backtrace;
authenticity needs descent; ownership needs a signature) enforced *before a byte is
emitted*.

Bitcoin is a distributed state-transition machine. UTXOs hold the state,
transactions propose the transitions, and Script is the predicate a transition must
satisfy. Everything else in this repository is a consequence.
