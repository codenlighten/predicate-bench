# Cross-input reasoning, and the limit of it

A single covenant validates a single input. This document is about what one input
can and cannot learn about the *other* inputs of its spending transaction — the
question underneath UTXO tokens, batch clearing, and every "the contract sums the
inputs" claim. The short answer: a covenant can bind its siblings' **identity**
for free, and their **value** only with a backtrace. The naive design that skips
the backtrace mints money from nothing, and this is demonstrated against the real
interpreter in [`tools/token-merge-analysis.js`](../tools/token-merge-analysis.js)
(`npm run analysis:merge`).

---

## What one input can see

When input *i* is validated, its OP_PUSH_TX preimage is the BIP-143 sighash for
*that input*. Of the eleven components, exactly two say anything about other
inputs:

- **`hashPrevouts`** (item 2) — `HASH256` of every input's outpoint,
  concatenated. This names *which coins* are being spent.
- **`hashSequence`** (item 3) — `HASH256` of every input's sequence number.

That is the whole window. Critically, there is **no field for another input's
value or locking script**. Item 7 is the value of *this* input's prevout; nothing
names input *j*'s value. So a covenant can prove *who its siblings are* and prove
*nothing about what they hold* — not directly.

[`companion`](predicates.md#companion) is exactly the identity half: it checks the
spender-supplied outpoint set against `hashPrevouts`, which binds which inputs are
present and how many. It makes no claim about their balances, and that restraint
is the honest boundary this document explains.

---

## The naive merge, and why it fails

A UTXO token stores its balance in its own `scriptCode` — the same self-carried
state as [`titled`](predicates.md#titled) and
[`registry`](predicates.md#registry). To merge two tokens with balances `a` and
`b` into one output carrying `a + b`, the obvious covenant has every input assert:

```
own_balance + <pushed sibling balance> == <total on output 0>
```

Two of those three terms a covenant can enforce honestly:

- `own_balance` it reads from its **own** `scriptCode` (`selfChunk`).
- `<total>` it binds to output 0 via `hashOutputs`, and under `SIGHASH_ALL` every
  input sees the **same** output set — so all inputs agree on one total.

The third, `<pushed sibling balance>`, it **cannot**. No preimage field names a
sibling's balance, so that number is whatever the spender pushes. And that is the
whole game.

### The inflation attack, measured

With `a = 100`, `b = 50`, an honest merge produces total `150` and both inputs
accept. Now the attacker declares total `1,000,150` and hands each input the lie
that balances *its own* sum:

```
input 0 (balance 100): told the sibling holds 1,000,050  →  100 + 1,000,050 = 1,000,150  ✓
input 1 (balance  50): told the sibling holds 1,000,100  →   50 + 1,000,100 = 1,000,150  ✓
```

Both inputs pass. The output carries 1,000,150 tokens; 1,000,000 were minted from
nothing. The demonstration runs this exact arithmetic on the consensus
interpreter and both inputs verify `true`.

The isolation is faithful. Authentication constrains `own`, output-binding
constrains `total`, but **neither touches the pushed sibling balance** — so the
fully plumbed covenant is exploitable precisely because this three-line predicate
is. Adding more machinery around `own` and `total` cannot help; the free variable
is elsewhere.

This is why "the contract sums the input balances and enforces conservation" is
not something `hashPrevouts` delivers on its own. Every input agreeing on the
same *total* is not conservation — the totals can agree on a lie.

---

## What closes it: the backtrace

A sibling's balance is not in the preimage, but it *is* provable, because the
sibling's **outpoint names the transaction that created it**. A txid is
`HASH256(rawtx)`, and the outpoint (`txid ‖ vout`) is inside the `hashPrevouts`
vector the covenant already verifies. So:

1. The spender pushes the sibling's **raw funding transaction**.
2. The covenant computes `HASH256(rawtx)` and requires it to equal the sibling's
   txid — which `hashPrevouts` has already pinned. This binds the pushed tx to the
   real sibling; a wrong tx hashes to a different id and fails.
3. The covenant parses that tx's `vout`-th output and reads the **real** balance
   out of its `scriptCode`.

Now the sibling balance is authenticated, not asserted, and `own + sibling ==
total` becomes a genuine conservation check. The `HASH256(rawtx) == txid` binding
is verified in the demonstration.

This is "back-to-genesis" in miniature — the recursive version of the same idea
that the [reftx](preimage.md) literature replaces with a SNARK to avoid walking
the whole ancestry. One hop of it is cheap and sound; the cost is that every merge
carries its siblings' funding transactions as witness data, and the size grows
with the fan-in.

### The merge covenant, built

The backtrace is now implemented as [`token`](predicates.md#token), with the
inflation attack above as a **passing refusal** in the suite: claiming the
sibling holds more than it does is rejected because the rebuilt funding
transaction no longer hashes to its real txid.

Parsing an arbitrary funding transaction in script — variable-length inputs,
varint counts — would have been the large, fragile part. `token` sidesteps it
with a stated constraint: **a token transaction has one output (a mint or merge)
or two (a split), each a fixed-stride token output.** The funding is rebuilt with
its ends pinned (version, an output count *derived* from the output section's
length, the locktime after) and the opaque input section is never walked; the
sibling's output is extracted at `vout × stride`, so both shapes are handled
without a branch. The balance lives in the `scriptCode` and the satoshi value is a
fixed dust constant, so a balance lie is invisible to the miner and only the
backtrace catches it — which is the whole point. `mint → split → merge` therefore
round-trips with the balance conserved at every hop.

What `token` proves is **conservation**, not **authenticity**: the merged total
equals the sum of the inputs' real balances, but nothing rules out an input that
is a look-alike script rather than a descendant of a legitimate issuance.

That residual gap — authenticity — is closed by [`lineage`](predicates.md#lineage),
and it turns out *not* to need a SNARK or an O(N) ancestry walk. A `lineage` token
carries its genesis outpoint and, on each spend, re-proves only its *immediate*
parent was a genuine token of the same genesis; induction over the network's own
validation of each prior spend does the rest, at a bounded two-transaction witness
per spend. A counterfeit can be minted but never spent. The recursion the reftx
literature compresses with a SNARK is, for a self-recreating token, discharged one
hop at a time on chain. `lineage` isolates the mechanism (no balance, no owner);
composing it with `token` and `asset` — a conserved, owned, provably-authentic
asset — is the natural next build.

---

## The rule

> `hashPrevouts` binds *which* coins are co-spent. It never binds *what they hold*.
> Any covenant that reasons about a sibling's value must authenticate that value
> by backtrace — anything less is an inflation bug that both inputs will sign off
> on.

See also [companion](predicates.md#companion),
[pitfall 23](pitfalls.md#23-hashprevouts-reverses-the-txid-and-a-symmetric-test-hides-it)
for the txid-reversal trap in reconstructing outpoints, and
[the preimage map](clauses.md#the-preimage-map) for where these fields sit.
