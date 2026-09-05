# Predicates

A locking script is a predicate. The only question ever asked of it is whether
`unlockingScript || lockingScript` leaves a true value on the stack under
current consensus rules. Everything below is an answer to that question.

Each predicate is judged twice: by what it accepts, and — the half that matters
— by what it refuses. Every entry lists both.

| predicate | lock size | cases | what it enforces |
|---|---|---|---|
| `p2pkh` | 25 B | 2 | hold the key behind this hash |
| `hashlock` | 35 B | 2 | know a preimage of this hash |
| `multisig` | 105 B | 12 | m-of-n, in key order, with an empty dummy |
| `htlc` | 488 B | 11 | claim with a secret, or refund after a floor |
| `merkle` | 62 B | 8 | prove a leaf is in a committed tree |
| `lineage` | 509 B | 4 | prove unbroken descent from a genesis mint |
| `provenance` | 588 B | 6 | owner-signed transfer of a provably-authentic token |
| `sovereign` | 1420 B | 9 | conserved, owned, authentic — composed (transfer live, merge proven) |
| `rpuzzle` | 44 B | 6 | sign with this committed nonce, under any key |
| `companion` | 395 B | 6 | spendable only beside a named sibling input |
| `token` | 692 B | 14 | a balance conserved across merge and split, any shape |
| `asset` | 1001 B | 19 | an owned token: transfer, split, merge, atomic swap |
| `ticket` | 599 B | 17 | capped resale, an enforced venue cut, burnt at the door |
| `oracle` | 634 B | 11 | claim on an oracle's Rabin-signed value, or refund after a deadline |
| `settlement` | 660 B | 11 | an oracle value splits a pot between two parties, forced by hashOutputs |
| `quorum` | 577 B | 10 | m-of-n independent oracles must attest the same value |
| `resolution` | 1128 B | 16 | an OPEN→RESOLVED market outcome gated by an m-of-n oracle quorum; the transition authority is a threshold of attestations, not a key |
| `market` | 1153 B | 17 | a fully-collateralised two-party binary prediction market: an m-of-n oracle quorum decides the outcome and the pot goes to the winner, or both parties reclaim their half after a deadline |
| `marketN` | 1232 B* | 14 | a fully-collateralised N-outcome (categorical) market: the quorum names the winning outcome and the whole pot goes to its owner, or an equal K-way refund after a deadline (*K=3; grows with K) |
| `marketScalar` | 1178 B | 12 | a fully-collateralised two-party scalar market: the quorum attests a value and the pot is split piecewise-linearly between LONG and SHORT, or a 50/50 refund after a deadline |
| `bulletin` | 1091 B | 8 | a reusable, quorum-established outcome fact: OPEN→RESOLVED once, then recreates itself on every read so any number of positions can settle against it without consuming it |
| `position` | 581 B | 7 | a fully-collateralised binary option: co-spend the bulletin, read the committed outcome, release the collateral to the owner if they called it right, else the counterparty |
| `descentbulletin` | 1351 B | 5 | a counterfeit-proof reusable oracle fact: carries its genesis outpoint and proves, one hop at a time, that it descends from the unique genesis — even across the OPEN→RESOLVED state change |
| `descentmarket` | 1373 B | 6 | the unification: a counterfeit-proof descent bulletin that also carries a pTail of position payouts, so a whole batch of positions co-settles against it in one transaction while every hop proves descent from the genesis |
| `positionv2` | 533 B | 6 | a binary option that identifies its market by the descentmarket covenant-script hash (committing to the genesis), so it can be written before resolution and settle against any genuine descentmarket of that market |
| `ticker` | 700 B | 10 | self-recreating oracle mirror; advances only on a fresher signed value |
| `journal` | 598 B | 8 | append-only hash-linked authenticated log; head commits to history |
| `lifecycle` | 631 B | 13 | a status machine with an immutable core and a terminal state; issuer-signed |
| `delegation` | 811 B | 15 | a divisible, inductive authority budget; delegate, exercise, revoke; Σ ≤ root |
| `witness` | 502 B | 7 | release gated on a named sibling coin being co-spent with a required flag |
| `conserve` | 1025 B | 10 | a conserved, uncounterfeitable two-body pair: rebalance moves quantity, sum fixed, descent proven |
| `guarded` | 1151 B | 8 | conserve ∧ witness: a conserved pair whose rebalance is gated on a named oracle coin's flag |
| `pool` | 1171 B* | 8 | conserve for N bodies: a group whose balances always sum to a constant (*N=3; grows with N) |
| `audited` | 1202 B | 8 | conserve ∧ journal: a conserved pair whose every rebalance is appended to an embedded audit chain |
| `ledger` | 1410 B* | 9 | pool ∧ journal: an N-body conserved treasury that logs every rebalance (*N=3; grows with N) |
| `turns` | 665 B | 8 | a two-player turn-based game: the current player moves, the turn alternates, both settle |
| `vesting` | 675 B | 10 | a grant that vests linearly over time; withdraw the vested part, the rest recreates |
| `timelock` | 372 B | 5 | nLockTime ≥ floor, properly |
| `covenant` | 384 B | 4 | pay exactly this output set |
| `perpetual` | 385 B | 9 | recreate this exact script, minus a fee |
| `composed` | 422 B | 12 | several clauses ANDed on one preimage |
| `metered` | 488 B | 18 | carry a counter; expire into a settlement |
| `titled` | 506 B | 14 | carry an owner; only they transfer or cash out |
| `royalty` | 603 B | 17 | pay the creator a share of every hand-off |
| `registry` | 554 B | 18 | carry a multi-field record with per-field rules |

---

## p2pkh

The baseline. Uninteresting as a predicate, essential as a control: if this does
not verify, the harness is wrong and nothing below it can be trusted. A real
`OP_CHECKSIG` over a real BIP-143 FORKID sighash cannot be faked by a
simulator, so its passing is what proves the bench evaluates rather than
pretends.

**Refuses:** a signature from the wrong key (`SCRIPT_ERR_EQUALVERIFY`).

## hashlock

```
OP_SHA256 <hash> OP_EQUAL
```

The smallest thing that is genuinely a predicate: knowledge alone is the
spending condition. No key, no identity. The secret becomes public the moment it
is spent — that is inherent, not a flaw, and it is what makes hash locks useful
for atomic swaps.

**Refuses:** any other preimage (`SCRIPT_ERR_EVAL_FALSE_IN_STACK`).

## multisig

The oldest way of splitting authority in Bitcoin, and the only predicate here
that is not a covenant. Included because a bench claiming to cover locking
scripts should not skip it, and because its refusals surprise people.

```
<m> <pk1> ... <pkn> <n> OP_CHECKMULTISIG
```

**Signatures must appear in the same relative order as their keys.**
`OP_CHECKMULTISIG` walks the signature and key lists together in a single pass;
a signature that does not match the key it is currently looking at is not
retried against the others. Two valid signatures from two named owners, in the
wrong order, do not spend — and nothing in the error says so.

**The leading dummy element must be empty.** `OP_CHECKMULTISIG` pops one item
more than it uses, an off-by-one kept from the original implementation. NULLDUMMY
requires it be empty; measured on mainnet, a non-empty dummy is refused with
`Dummy CHECKMULTISIG argument must be zero`.

**`m` and `n` must use `OP_1`..`OP_16`, not a one-byte data push.** A data push
of `0x02` where `OP_2` exists is non-minimal. This was caught by the bench's own
policy flags: every happy path failed `SCRIPT_ERR_MINIMALDATA` before reaching
the signature check.

**Refuses:** two valid signatures in the wrong order; one signature short; the
same key twice; an outsider substituted for a signer; a non-empty dummy; 3-of-3
presented with two.

**Accepts SIGHASH_NONE**, unlike every covenant here — a bare multisig
constrains no outputs, so it has no reason to care which sighash type was used.
Asserting a refusal there was a wrong premise on my part, not a missing guard.

## rpuzzle

Move the secret out of the key and into the *nonce*. Every ECDSA signature
carries `r = (kG).x` in the clear; this script slices it out of the DER bytes and
insists it equals a value fixed at lock time. Forty-four bytes, and it never
mentions a public key:

```
OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP <r> OP_EQUALVERIFY OP_CHECKSIG
```

`OP_3 OP_SPLIT OP_NIP` steps over the DER header (`0x30 <len> 0x02`); the next
byte is the length of `r`, and feeding it straight back to `OP_SPLIT` cuts
exactly that many bytes off. The lock builder grinds `k` until `r`'s top bit is
clear so DER encodes it as exactly 32 bytes — the script handles 33 either way,
but then the committed value has to match the zero-padded form, and grinding is
cheaper than carrying both.

### Signing is a proof about the transaction, not about identity

`OP_CHECKSIG` here validates against a public key the **spender supplies**. That
looks like a hole and is the entire point: knowledge of `k` is the spending
condition, and who signs is nobody's business. Two cases pin this down — an
unrelated key spends successfully, and the same case restated from the
attacker's side spends successfully too.

### And the cost is worse than "keep k secret"

The obvious hazard is that an `r` is single-use: once `k` is recoverable, anyone
can sign with it. That is true and it is not the real problem.

WP1605's **Claim 2** says the public key must be fixed in the locking script,
and gives the reason constructively. Given any valid `(r,s)` and any message
`m'` you like, solve

```
u' = z'/s,   v = r/s,   P' = (R - u'G) / v
```

and `(r,s)` verifies against `P'` on `m'`. `P'` is a curve point nobody knows the
discrete log of — and `OP_CHECKSIG` never asks for one. An R-puzzle floats the
public key by design, so this applies directly.

The consequence, in the suite as a **passing** case: an attacker who sees the
honest spend in the mempool replays that exact signature into their own
transaction under a solved-for key. They never learn `k`, never learn `d`, and
hold no private key at all. Both candidate `R` points work, so there is not even
a parity gamble.

So the theft window does not open when `k` is disclosed. It opens the moment the
honest spend is broadcast. A bare R-puzzle is safe only while nobody has ever
spent one under that `r` — which is to say, it is a one-shot instrument that is
also a race. Anything holding real value should be an R-puzzle **and** a
signature check against a fixed key, so that solving for `P'` does not help.

### The spend can release a secret

This is what makes R-puzzles interesting beyond novelty. Rearranging the
signing equation:

```
s = k⁻¹(e + r·d)     ⟹     k = s⁻¹(e + r·d)
```

Everything on the right is public once the spend is broadcast — except `d`. So
**publish a throwaway `d`** and the nonce falls out of the signature for anyone
watching. Encrypt a media segment under `SHA256(k)`, lock the payment to `r`,
and the server cannot take the money without handing over the decryption key. No
DRM licence server, and no trusted release step: settlement and delivery are the
same event.

Note what is *not* true. A passive observer who does not know `d` learns `r` and
nothing more — recovering `k` from `r` is the discrete log, and `s` leaves two
unknowns in one equation. "The player intercepts the transaction and extracts
`k`" is false for a plain R-puzzle; the disclosure has to be engineered, by
publishing `d`.

### LOW_S breaks the naive version half the time

BSV enforces `LOW_S` as **mandatory** — see [pitfalls.md](pitfalls.md#22-low_s-normalisation-negates-a-recovered-nonce).
The signer rewrites `s` to `N - s` whenever it lands in the upper half, and that
negates the recovered nonce with it. Both `k` and `N - k` produce the same `r`,
so the signature offers no way to tell which one you have. Deriving the content
key from `min(k, N-k)` on both sides is the fix; `npm run selftest:nonce` walks
nonces until it has seen both branches and checks recovery in each, so the check
cannot pass vacuously.

**Refuses:** a signature made with a different nonce; a public key that did not
produce the signature.

**Accepts, and should worry you:** any unrelated key that knows `k`; and one
observed signature replayed onto an entirely different transaction.

## companion

Every other covenant here reasons about its *own* spending transaction. This one
reaches sideways: it refuses to be spent unless a specific *other* input is
present in the same transaction.

The only window Script has onto sibling inputs is `hashPrevouts` — item 2 of the
preimage, `HASH256` of every input's outpoint concatenated in order. A covenant
cannot invert a hash to read the set out, but the spender can push the set and
the covenant checks it:

```
HASH256(prefix ‖ <companion> ‖ suffix) == hashPrevouts
```

`<companion>` is a 36-byte outpoint fixed at lock time. If the equality holds,
the transaction's real input set genuinely contains it, because nothing else
hashes to the true `hashPrevouts`. `prefix` and `suffix` are supplied by the
spender and need no validation of their own — a lie about either changes the
hash and the spend dies. An optional `groupSize` adds `OP_SIZE … OP_EQUALVERIFY`
to pin the exact number of inputs, so the batch cannot be padded.

### What it binds, and what it cannot

This binds the **identity** and **count** of the sibling inputs. It is enough for
atomic bonding (two coins that only move together), forced batching (spendable
only in a transaction of exactly N inputs), and a dead-man companion (release A
only when B is also spent).

It deliberately does **not** read a sibling's **value** or **script**. Those live
in the sibling's own preimage, not this one's — a covenant sees item 7 (its own
input value) but has no field naming any other input's value. So the popular
"sum the input balances in-script and enforce conservation" — the UTXO
token-merge claim — does **not** follow from `hashPrevouts` alone.

What the token designs actually do is put each coin's balance in its own
`scriptCode` (as [titled](#titled) and [registry](#registry) carry state) and
have every input run the *same* covenant, so each independently checks the
outputs against its own state. Convincing input *i* of input *j*'s balance still
needs more — a backtrace to *j*'s funding transaction, or a shared commitment
both can read — because `hashPrevouts` commits to *where* the siblings came from,
never to *what they hold*. `companion` is the primitive that is real; the merge
is a construction on top of it that this bench does not yet claim.

The full argument — the inflation attack the naive merge admits, measured against
the interpreter, and the backtrace that closes it — is in
[cross-input.md](cross-input.md).

### The reversal that hides behind a symmetric txid

The 36 bytes are `reverse(txid) ‖ vout` — bsv holds `prevTxId` in display order
and reverses it into the sighash. A test using a palindromic txid (all `0x07`)
passes whether or not you reverse, then the covenant fails on the first real
outpoint. See [pitfall 23](pitfalls.md#23-hashprevouts-reverses-the-txid-and-a-symmetric-test-hides-it).

**Refuses:** a transaction spending a different sibling than the one named; a
spender lying about the prefix/suffix layout; a padded input set when `groupSize`
is fixed.

## token

A fungible token whose balance is **conserved** in both directions, a two-branch
covenant:

- **merge** — two token UTXOs (balances `a`, `b`) into one carrying exactly
  `a + b`;
- **split** — one token (balance `c`) into two carrying `x` and `y`, with
  `x + y = c`.

This is the construction [cross-input.md](cross-input.md) specified as future
work, now built and tested against the interpreter.

Split is the easy direction: one input, so there is no sibling and no backtrace —
the covenant reads its own balance and requires the two outputs it builds to sum
to it, bound through `hashOutputs`. Minting from nothing (`300 → 300+300`),
destroying balance (`300 → 300+199`), and declaring one split while emitting
another are all refused.

Merge is the hard one, and the reason is the one cross-input.md names: a covenant
cannot read a sibling's balance from its own preimage, so the naive merge — trust
a pushed sibling balance — lets both inputs sign off on an inflated total. `token`
closes it by **backtrace**.

### The backtrace

A sibling's balance lives in the sibling's own `scriptCode`, and its outpoint
names the transaction that created it. A txid is `HASH256(rawtx)`. So the
covenant rebuilds the sibling's funding transaction — splicing the *claimed*
balance into the sibling's script — and requires the rebuild to hash to the
sibling's real txid (which `hashPrevouts` has already pinned):

```
HASH256( VERSION ‖ <opaque input section> ‖ countByte ‖ outsBlob ‖ locktime ) == txid_sibling
```

`outsBlob` is the sibling funding tx's whole output section, supplied by the
spender and pinned by the hash. If the claim is a lie, the sibling's slice of it
carries the wrong balance, the bytes differ, and the hash misses. The sibling's
balance is therefore *proven*, not trusted, and the merged output — whose balance
the covenant computes itself as the sum — is bound to `hashOutputs`. The inflation
attack, the output over-claim, and even an output that *destroys* balance are all
refused; conservation is exact.

### One or two outputs, no branching

A sibling funding tx is single-output (a mint or a merge) or two-output (a
split). The backtrace handles both without a branch, because every token output
is a **fixed stride** — `value(8) ‖ varint ‖ script`, the script a constant
length since the balance is fixed-width. So the sibling's output sits at
`vout × stride` inside `outsBlob`, extracted with one `OP_SPLIT` pair, and the
output count is `size(outsBlob) / stride` (required to divide exactly and to be 1
or 2). The stride is read from the covenant's own chunk at runtime — hard-coding
it would be circular, since the constant lives in the script whose length it
measures.

- **The output count is derived, not trusted.** `countByte` is
  `size(outsBlob) / stride` re-encoded, so a spender cannot claim a shape the
  bytes do not have; the hash then binds `outsBlob` to the real funding tx.
- **Every token carries a fixed `DUST` value in satoshis**, with the balance in
  the `scriptCode`, decoupled from satoshis. That decoupling is exactly what
  makes a balance lie invisible to the miner's own value check — and so is the
  whole reason the backtrace is needed rather than free.

### What it proves, and what it does not

It proves **conservation**: the merged total equals the sum of the inputs' real
balances. It does **not** prove **authenticity** — that the inputs descend from a
legitimate issuance rather than a look-alike script. That is the unbounded
back-to-genesis problem, the province of reftx/SNARKs, and it is out of scope by
design. See [cross-input.md](cross-input.md).

The vector check is symmetric (it accepts the sibling in either position via
`OP_BOOLOR` of both arrangements), so the same script validates whichever input
it runs as. The covenant is authored with a small stack-tracking assembler
([`src/stackasm.js`](../src/stackasm.js)) — a dozen live values is past what is
safe to pick-and-roll by hand, and a wrong depth is a silent security bug.

### The full cycle closes

Because the backtrace reads a one- *or* two-output funding, a split-produced
token is mergeable, not just splittable — so `mint → split → merge` returns to
where it started with the balance conserved at every step. The suite merges a
split-sourced sibling at both `vout 0` and `vout 1`, and refuses a lie about its
balance exactly as for a mint-sourced one. The stride-addressed extraction (no
nested branch) is what let this be built to the same adversarial standard as the
rest rather than left as a caveat.

**Refuses:** (merge) a lie that the sibling holds more — the inflation attack; an
output claiming more than the true sum; an output claiming less; a sibling not
committed to by `hashPrevouts`. (split) a split that mints from nothing; one that
destroys balance; a declared split that does not match the emitted outputs.

## asset

An owned fungible token — the composition of two primitives this bench already
has, and the demonstration that they compose without either one changing.
[`token`](#token) conserves a balance across merge and split; [`titled`](#titled)
gates a spender-chosen owner behind that owner's signature. `asset` carries
`owner ‖ balance` in its scriptCode and offers three branches, each requiring the
current owner to sign:

- **transfer** — 1 → 1, same balance, a new owner the current one chooses;
- **split** — 1 → 2, balance divided, an owner for each half;
- **merge** — 2 → 1, balances summed, and *each* input's owner must sign — so a
  merge happens only when both holders consent;
- **swap** — two assets change hands in one transaction, each output pinned by
  its own owner: an atomic peer-to-peer trade.

### Composition, not modification

Nothing in the conservation logic or the ownership logic had to change. The merge
branch is `token`'s two-output backtrace with the owner spliced into the chunk
alongside the balance; the authorisation is `titled`'s exact pattern — read the
owner out of `selfChunk`, require `HASH160(pubkey)` to equal it, then
`OP_CHECKSIGVERIFY` the owner's signature over the spend. The two concerns sit
side by side in each branch: authorise first, then conserve.

That each input enforces *its own* owner is what makes the merge a two-party
handshake for free — no cross-input signature logic is needed, because input 0's
covenant checks owner A signed and input 1's checks owner B signed, and the merge
is invalid unless both do. The merged output's owner is spliced by the spender,
but both owners sign over it (through `hashOutputs`), so both consent to where it
lands.

### Atomic swap, for free

The swap branch is a transfer that pins only *its own* output among a
spender-supplied set, instead of requiring its output to be the only one. Each
side's covenant checks that its outgoing asset — new owner, balance preserved —
sits at its declared index within the transaction's output section, and that the
whole section hashes to `hashOutputs`. Everything else in the set is opaque to it;
the counterparty's covenant checks that.

Atomicity needs no cross-input logic at all. Each owner signs under `SIGHASH_ALL`,
which commits to *every* output — so signing is consenting to the entire trade,
including the asset you receive — and the transaction is all-or-nothing: neither
asset moves unless both owners sign. It is the same two-party property the merge
has, and for the same reason (each input enforces its own owner independently),
now put to a peer-to-peer exchange. The output is located by the same
fixed-stride arithmetic the merge backtrace uses: `outsBlob[myIndex × stride]`,
the stride read from the covenant's own chunk.

The four-branch dispatch is a one-byte selector, `swap` added ahead of the other
three. The two-owner atomicity is proven on chain by the [merge](mainnet-log.md)
(a merge and a swap relay by the same mechanism); the swap branch itself is
verified against the interpreter under full relay policy, with an on-chain
demonstration left for a wallet refill.

### Three branches on one authentication

The covenant authenticates the preimage once, parks it on the altstack, then
dispatches on a one-byte selector (`OP_DUP <n> OP_EQUAL OP_IF …`) — a cleaner
three-way split than nesting `OP_IF` around the preimage, since the preimage is
out of the way on the altstack while the selector is examined. It is authored
with the [stack-tracking assembler](../src/stackasm.js), a fresh symbolic stack
per branch seeded with the parked preimage.

**Refuses:** (all) a signature from anyone but the current owner. (transfer) a
changed balance. (split) minting from nothing; a declared split that does not
match the emitted outputs. (merge) a lie about the sibling's balance *or* owner;
an inflated output; a sibling not committed to by `hashPrevouts`. (swap) a
changed balance, or an output redirected to an owner the signer did not choose.

## lineage

The one hard problem the bench had scoped but not solved: **authenticity**. The
token covenants conserve balance and gate ownership, but a counterfeiter can mint
a raw output whose bytes are the covenant with any state — conservation is not
descent. `lineage` closes that, without a SNARK, for a self-recreating token.

Every token carries its **genesis outpoint** `G` in its scriptCode, and on every
spend it proves — by a bounded backtrace — that its *immediate* parent was a
genuine `lineage` token with the same `G`. It never re-verifies the whole
ancestry; it verifies one hop and relies on induction.

### The check

To spend token `T`, the covenant requires **either**:

- **(a) genesis** — `T`'s funding transaction spent the outpoint `G` directly.
  That is the mint, and it can happen exactly once, because `G` is a UTXO; or
- **(b) parent** — the token `T`'s funding transaction spent was itself a
  `lineage` token with the same `G`, proven by rebuilding that parent's
  single-output funding transaction (its output is `DUST ‖ lineage+G`, identical
  to `T`'s own script) and hashing it to the parent's txid.

`T`'s own outpoint comes from preimage item 4; its funding transaction is pushed
and pinned by `HASH256(raw) == txid`; the parent outpoint sits at a fixed offset
in that funding tx (input 0, just past the version and a one-byte input count),
because the token is always input 0 of its spend.

### Why one hop is enough

The soundness is inductive, and it turns on `T` being spendable only if its
funding transaction is a *real, network-validated* one. If that transaction spent
parent `P`, then `P`'s covenant ran and enforced `P`'s **own** descent check when
the transaction was mined. So `P` is authentic, and by the same argument so is
`P`'s parent, back to the single spend of `G`. The covenant re-proves only the
last link; the network already proved the rest, once, at each step. The witness
is two parent transactions per spend — **bounded, not O(N)** — which is what
makes it feasible on chain where a full back-to-genesis walk is not.

### The counterfeit

A counterfeit is lineage bytes with a real `G`, minted by spending a plain UTXO.
It can be *created* — the bytes are valid — but never **spent**: its funding
transaction did not spend `G`, and its "parent" output is a plain script, not
`lineage+G`, so the rebuild misses. Both branches of the check fail. An
unspendable coin never enters circulation, so it can never be transferred or
counted. The suite mints exactly such a counterfeit and confirms it is refused.

### What it is and is not

It proves **authenticity** — unbroken descent from a unique genesis — and nothing
else: no balance, no owner. Those are `token` and `asset`, deliberately kept
separate so this isolates the lineage mechanism; composing all three (a
conserved, owned, provably-authentic asset) is the natural next build. The two
constraints it rests on: a token transaction is single-output (the token
self-recreates unchanged, which keeps the parent backtrace free of the sliding
attack, as in [token](#token)), and the token is always input 0 of its spend.

**Refuses:** a counterfeit minted from a plain UTXO — and, by the same rebuild,
any parent that is not a `lineage` token of the same genesis.

## provenance

The composition of the two mechanisms `lineage` and `titled` isolate: a token that
proves **unbroken descent from its genesis** *and* requires the **current owner's
signature** to move. It carries `genesis ‖ owner` — the genesis immutable, the
owner spliced on each transfer — and transfers 1 → 1, the balance-less analogue of
an NFT with verifiable lineage.

Every spend does two independent things, side by side:

- **authorise** — read the owner out of `scriptCode`, require
  `HASH160(pubkey) == owner`, `OP_CHECKSIGVERIFY` the owner's signature (this is
  [titled](#titled)'s exact pattern);
- **prove descent** — show the immediate parent was a `provenance` token of the
  same genesis, by rebuilding the parent's single-output funding tx and hashing it
  to the parent's txid ([lineage](#lineage)'s exact mechanism).

### The one new wrinkle

`lineage` self-recreates *identically*, so a token could rebuild its parent's
output from its own bytes. Here the owner changes each hop, so the parent's output
is not a copy of mine — its owner differs. The parent's owner is therefore
supplied by the spender and **pinned by the descent hash**: splice it into the
template with *my* genesis, rebuild the parent tx, and if the claim is wrong the
bytes differ and the hash misses. The genesis and the logic are shared and taken
from my own chunk, so a parent of a *different* genesis misses too. A lie about
the parent owner is a refused case in the suite.

Nothing in either primitive changed to compose them — the authorisation and the
descent proof sit in the same script, each doing its own job, exactly as
conservation and ownership do in [asset](#asset). The chain is exercised over
three hops with the owner rotating at each, and the counterfeit — provenance bytes
minted from a plain UTXO — is unspendable just as in `lineage`.

**Refuses:** a signature from anyone but the current owner; a counterfeit minted
from a plain UTXO; a lie about the parent's owner (or a parent of another genesis).

## sovereign

The three mechanisms at once — the capstone. A `sovereign` token **conserves** a
balance, is **owned**, and proves its own **authenticity**, all in one covenant.
Its state is `genesis ‖ owner ‖ balance`, and every spend runs the three checks
side by side, each lifted unchanged from the predicate that isolated it:

- **authorise** — `HASH160(pubkey) == owner`, then `OP_CHECKSIGVERIFY` the owner's
  signature ([titled](#titled));
- **conserve** — a merge sums the two balances ([token](#token));
- **prove descent** — the immediate parent was a `sovereign` of the same genesis,
  by the single-output backtrace ([lineage](#lineage)).

Two branches: **transfer** (1 → 1, new owner, balance carried) and **merge**
(2 → 1, balances summed). A merge takes *both* holders' signatures — each input
enforces its own owner — and each input both proves its own descent and, through
the conservation backtrace, proves the *other* input was a genuine `sovereign` of
the same genesis. So a counterfeit can be neither transferred nor merged: every
path re-checks descent.

### Now divisible — the multi-output descent

The earlier version of this covenant stopped at transfer and merge, and merge was
unreachable: two same-genesis tokens only arise from a **split**, and split makes a
two-output transaction, so a split-produced token's parent funding is two-output —
the descent backtrace would have to reconstruct the parent's whole output section
and pin the parent by `vout`.

That is now built. The descent uses [token](#token)'s multi-output backtrace,
checking the parent's slice at its vout is a sovereign of *my* genesis, and the
genesis case (the mint spent `G` directly) is an `OP_IF`/`OP_ELSE` alternative to
it — which needed the [stack assembler taught to model a branch](authoring.md).
With split reachable, so is merge: the suite runs the whole **mint → split →
merge** lifecycle, and separately a *grandchild of a split* — a token whose parent
was a split child, whose spend therefore backtraces through a two-output parent —
to exercise the multi-output path directly.

### Composition without modification

Nothing in the three mechanisms changed to combine them. The descent proof is a
shared helper called by both branches; the ownership check and the conservation
backtrace sit beside it, each doing its own job. That the whole thing —
authorise, conserve, prove descent, in one 944-byte script — assembled correctly
from the three parts is the strongest evidence that the bench's primitives are
genuinely composable, not just individually sound. See
[asset](#asset) (conservation + ownership) and [provenance](#provenance)
(authenticity + ownership) for the pairwise steps.

**Refuses:** (all) a non-owner's signature; a counterfeit that cannot prove
descent. (transfer) a changed balance. (merge) a lie about the sibling's balance;
an inflated output; a redirect to an owner the signer did not choose.

## ticket

An event ticket with two branches: `resell` hands it on under a price ceiling
while paying the venue its cut, and `checkin` destroys it at the door.

It exists to test three claims that get made about ticketing covenants — a
price cap enforced by consensus, a mandatory creator royalty, and a one-time
check-in nullifier. Two of them hold. The third holds mechanically and fails at
the thing it is actually for, which is the most useful result here.

### A number the script cannot compute

`royalty` derives its cut from the coin's own value, so there is nothing to
bound. A resale price is different: the seller picks it, so the covenant is
handed a figure it cannot derive and has to bound it in script.

```
OP_DUP <maxPrice> OP_LESSTHANOREQUAL OP_VERIFY
```

The declared price then drives everything else — the venue's cut is a fixed
proportion of it, and output 2 pays exactly it to the holder named in the
script. Declaring one number while paying another does not work: the
declaration is what the script reasons about, `hashOutputs` is what it must
match, and they have to agree.

### The free tail

A covenant that fixes `hashOutputs` exactly also forbids the buyer a change
output — [pitfall 17](pitfalls.md#17-a-covenant-that-dictates-outputs-also-dictates-the-fee).
That matters more here than anywhere else in the bench, because a real resale is
funded by the *buyer*, whose input needs change.

So the covenant pins a **prefix** instead. It builds outputs 0..2, concatenates
a tail the spender pushes, and hashes the whole thing:

```
OP_ROT OP_CAT      # append whatever the spender says the rest of the outputs are
```

The tail is unconstrained and needs no checking. Bytes that are not the
transaction's real remaining outputs simply hash to something else, and nothing
spends — the constraint is self-enforcing because `hashOutputs` already covers
every output. This is the technique that makes an introspective covenant usable
alongside ordinary funding inputs, and it costs two opcodes.

### The cap is not a price

The last resale case passes, and is named for what it is:

> `ticket: a 10-satoshi declared price clears the cap (the rest settles off-chain)`

Ten satoshis is under the ceiling. A tenth of ten is one, so the venue is paid
precisely what the contract demands. The other £400 moves by bank transfer, and
the covenant signs off.

This is not a bug in the script — every check does exactly what it says. It is
the ceiling on the whole idea. Script binds what a transaction *says*, and a
resale price is not something a transaction can be made to say. A covenant can
enforce an accounting identity between outputs it can see; it cannot enforce a
price, because the price is a fact about the world.

What survives is narrower and still real: the venue's cut is unavoidable *on
the declared amount*, the ticket cannot be transferred without recreating
itself, and the seller cannot pocket the declared proceeds. An honest market
gets cheap settlement. A dishonest one under-declares, exactly as it does with
stamp duty.

### The nullifier is the part that fully works

`checkin` requires output 0 to be a constant the script carries: zero satoshis,
`OP_FALSE OP_RETURN <sha256(event|seat)>`. Provably unspendable by consensus, so
admission consumes the ticket in the same act that records it, and the record is
legible on chain without an off-chain index. One case checks in to a spendable
P2PKH instead and is refused — a nullifier that leaves the coin spendable
nullifies nothing.

This branch is also the covenant's exit
([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)),
which is why it is the only terminal path.

**Refuses:** a price over the cap; a declared price the transaction does not
pay; a short-changed, misdirected or missing venue output; the right outputs in
the wrong order; proceeds paid to anyone but the named holder; a changed ticket
value; a buyer other than the declared one; a stranger's signature on either
branch; a burn under another seat's tag; a check-in to a spendable output.

## oracle

Every predicate before this one decides a spend from two kinds of fact: a key the
spender holds, or the shape of the spending transaction (its outputs, its
nLockTime, its sibling inputs). `oracle` adds the third kind — a fact about the
*outside world*, attested by a named third party. It is the foundation of every
parametric contract: a bet, an insurance payout, a price-triggered release.

The obstacle is that `OP_CHECKSIG` is no help here. It verifies an ECDSA
signature against *this transaction's* sighash, which the interpreter computes
itself — it cannot be aimed at a free message an oracle signed off-chain, and BSV
has no `OP_CHECKDATASIG`. So the oracle signs with a **Rabin signature**, which a
covenant verifies with nothing but arithmetic Script already has:

```
    s² mod N  ==  H(message ‖ padding) mod N
```

`N = p·q` is the oracle's public key, hard-coded in the covenant. Only the holder
of the factorisation can find an `s` for a given message (it is a modular square
root); anyone can check one with `OP_MUL` and `OP_MOD`. The message hash `H` is
expanded to the width of `N` by concatenating four `OP_SHA256` blocks — the same
construction the signer runs in [src/rabin.js](../src/rabin.js).

### A binary option, in two branches

`oracle` is a complete option, not just the verifier:

- **CLAIM** (selector 1): the winner takes the coins once the oracle attests a
  value at or above `THRESHOLD` for the named `FEED`. It requires *both* the
  winner's signature — because the attestation is public data, and without a key
  binding any bystander who saw it could grab the payout — and a valid Rabin
  signature over `FEED ‖ value` with `value ≥ THRESHOLD`. The value is read out of
  the signed message itself, so the oracle's signature binds the number, not just
  the fact that it signed *something*.

- **REFUND** (selector 0): if the event never happens the funder must recover, or
  the coins are a one-way trap. After `DEADLINE` the funder reclaims with their
  signature, gated by the [timelock](#timelock) done properly — preimage bound,
  sequence non-final, sign-padded. This is the whole reason the option is safe to
  fund.

The two branches read entirely different unlocking stacks (a Rabin proof on one
side, a preimage on the other), so the [stack assembler](authoring.md) models each
branch from its own declared layout rather than a shared one.

### Why the value is bound, not just the signature

The sharp test is the forged-value refusal: take the oracle's real signature for
`6000`, and present it in a message that claims `9999`. The threshold check passes
(9999 ≥ 6000) and the signature is genuinely the oracle's — but it was a square
root of `H(FEED ‖ 6000)`, and the covenant recomputes `H(FEED ‖ 9999)`, so
`s² mod N` and `H mod N` disagree and the spend dies at `OP_NUMEQUALVERIFY`. A
covenant that checked only "the oracle signed a value ≥ threshold" without
rebuilding the hash over the *presented* value would be forgeable this way; this
one is not.

### Honest limits

The demo oracle key is 512-bit (`src/predicates/oracle-key.json`) — the
**mechanism** is the artifact, not the key size. Production uses 2048+ bits, which
only widens the pushes and the one `OP_MUL`; the Script is identical in shape. And
nLockTime is a floor, never a ceiling (see [timelock](#timelock)), so REFUND opens
at the deadline and never closes: a claim that has not happened by then can still
happen after. A real option races the two paths with a pre-signed settlement — the
two mechanisms here are isolated and composed, in the bench's usual style, not
welded into a single race-free instrument.

Deployed and claimed on mainnet with a real attestation — the full
`s² mod N == H(m) mod N` verification, four `OP_SHA256` blocks and a 128-byte
`OP_MUL`, ran under consensus and relay policy and the node accepted it. See the
[mainnet log](mainnet-log.md#oracle).

**Refuses:** (claim) a value below the threshold; a forged value presented against
a signature for another; an attestation for a different feed; a bystander without
the winner's key. (refund) a premature reclaim below the deadline; a reclaim with
a final sequence that would make nLockTime inert; a stranger's signature.

## settlement

Where [`oracle`](#oracle) uses the attested value as a *gate* — spend or don't —
`settlement` uses it as a *dial*. The oracle's number decides **how much** each of
two parties receives. This is the numeric-payout instrument: a contract for
difference, a ranged insurance payout, a parametric escrow.

Two parties, a **long** (L) and a **short** (S), lock a pot. At settlement the
oracle attests a value `v`, and the covenant pays L a piecewise-linear share:

```
    v ≤ LOW          L gets 0,                S gets the pot
    v ≥ HIGH         L gets the pot,          S gets 0
    LOW < v < HIGH   L gets pot·(v−LOW)/RANGE,  S gets the rest      (RANGE = HIGH−LOW)
```

computed in Script with `OP_SUB`, `OP_MAX`/`OP_MIN` for the clamp, then
`OP_MUL`/`OP_DIV`. `payoutS = pot − payoutL`, so conservation is exact. The pot is
read from the covenant's **own input value** — item 7 of the preimage — minus a
fixed fee, so it settles whatever it was funded with rather than a hard-coded
amount.

### No signature, one possible spend

`settlement` takes **no spender signature**. The payout is a deterministic
function of a value only the oracle can sign, and both destinations are fixed at
lock time — so any party may broadcast the settlement, and there is exactly one
settlement they can broadcast. A fair forced clearing that no party can skew:
whoever submits it, the money splits the same way.

### Three mechanisms, composed unchanged

- the **Rabin verifier** of [`oracle`](#oracle), now a shared clause
  (`src/rabinscript.js`), supplies the external value;
- **output-binding** via `hashOutputs`, as in [`covenant`](#covenant), forces the
  two exact payments — the covenant builds `value ‖ P2PKH` for L and for S,
  hashes the pair, and compares to the preimage's commitment;
- **conserved integer arithmetic**, as in [`token`](#token), makes the split sum
  to the pot with no leak.

Unlike `oracle`'s refund branch, this one **asserts `SIGHASH_ALL`** — it binds
outputs, and `hashOutputs` is zeroed under `NONE`/`SINGLE`, so the assertion is
load-bearing here. It is the same distinction [pitfall 8](pitfalls.md#8-the-sighash-flag-decides-what-the-covenant-commits-to)
draws: a covenant asserts the flag exactly when it commits to outputs.

Deployed and settled on mainnet: an attestation of `6000` (with `LOW=4000`,
`HIGH=8000`) drove the on-chain spend to two 350-satoshi outputs — a 50/50 split
computed inside the locking script. See the [mainnet log](mainnet-log.md#settlement).

Honest limit: like `oracle` it isolates the mechanism and has no timeout, so an
un-attested pot is stuck; a complete instrument composes it with `oracle`'s refund
branch.

**Refuses:** a forged value presented against a signature for another; an
attestation for a different feed; any payout the covenant did not compute — the
long paid too much, a split that mints value above the pot, or a payout redirected
to a stranger.

## quorum

The honest weakness of every oracle covenant so far is that its one oracle is
trusted absolutely — it can lie, or vanish, and the coins move on its word alone.
`quorum` splits that trust the way [`multisig`](#multisig) splits *spending*
authority: across a panel of `n` independent oracles, each with its own Rabin key,
requiring a threshold `m` of them to attest the same value.

The mechanism is the **non-aborting** Rabin check. Where the asserting `verify`
kills the spend on a bad signature, `check` (the other export of
`src/rabinscript.js`) leaves `1` or `0` on the stack. The covenant runs it once per
panel member over the *same* message, sums the booleans, and requires the sum ≥ m:

```
    Σ  valid_i( sig_i over FEED‖value  under N_i )   ≥   m
```

Two properties fall out of the construction, both load-bearing and both tested:

- **Distinct oracles.** Slot `i` hard-codes oracle `i`'s modulus `N_i`. A signature
  counts for slot `i` only if it is a square root mod `N_i`, so one oracle's
  attestation replayed into another's slot fails the arithmetic and counts zero.
  The suite proves it: oracle 0's signature placed in slots 0 and 1 tallies `1`,
  not `2`, and a 2-of-3 spend is refused.
- **The same value.** Every check reads one shared `msg`, so the `m` agreeing
  oracles must agree on the *same* feed and value — not merely each sign something.

Like [`oracle`](#oracle) this is the claim half: the winner's key gates who may act
on the (public) attestations, and it isolates the split-trust mechanism — a
complete instrument adds a refund path as `oracle` does. The example panel is
2-of-3; the same code takes any `m ≤ n`.

Deployed and claimed on mainnet with two of the three panel oracles attesting —
two independent Rabin verifications, summed and thresholded in Script, accepted
under consensus and relay policy. See the [mainnet log](mainnet-log.md#quorum).

## resolution

Every oracle covenant so far let the quorum *authorise a spend*. `resolution` makes
the quorum *change an object's state* — it is the keystone of a [prediction market](roadmap.md#2-prediction-markets--a-polymarket-style-framework),
the first covenant whose transition authority is a **threshold of external
attestations rather than a signature**. It is a [`lifecycle`](#lifecycle) state
machine — an immutable core, a bounded status, a terminal state — whose one
transition is gated by [`quorum`](#quorum):

```
    state = question(32) ‖ status(1) ‖ outcome(1) ‖ resolver(20)

    resolve   OPEN → RESOLVED,  where  Σ valid_i( sig_i over question‖outcome under N_i ) ≥ m
    sweep     RESOLVED → (resolver sweeps the dust; the exit)
```

The transition is sound because the two halves reinforce each other:

- **The outcome is the one the oracles signed, for this question.** The covenant
  builds the oracle message from its *own* `question` field spliced with the
  presented outcome, then runs the quorum count over it. A resolver cannot record
  an outcome the panel did not attest (a forged outcome is refused), and an
  attestation for a *different* question fails the arithmetic — the market cannot be
  resolved with another market's oracle signatures.
- **A settled market cannot be flipped.** `RESOLVED` is terminal on the resolve
  path: the status guard requires `OPEN`, so an already-resolved market can never be
  re-resolved to a different outcome. The immutable core (`question`, `resolver`) is
  spliced unchanged into the successor and bound by `hashOutputs`, so a resolve
  cannot quietly rewrite either.

Because the `RESOLVED` fact is recorded in the transaction that produces it —
immutable history — a position elsewhere can prove descent from that transaction to
learn the outcome, and the resolver may later `sweep` the remaining dust without
erasing anything. One resolution object can therefore settle many positions. The
example panel is 2-of-3; the same code takes any `m ≤ n`.

Interpreter-verified under consensus and relay policy across 16 cases — 4 accepts
(each valid quorum and the exit) and 12 refusals (sub-quorum, a replayed oracle, a
forged or out-of-range outcome, a foreign question, a tampered core, a re-resolve,
an early or unauthorised sweep). This is the reusable-bulletin form of a market's outcome;
[`market`](#market) below is the direct, end-to-end two-party form.

## market

`market` is the first END-TO-END prediction market on the bench: a question in, an
oracle-agreed outcome out, the winner paid — settled entirely in one covenant, with a
refund path so it cannot strand funds. It is [`settlement`](#settlement) — whose oracle
value *decides* the payout rather than merely gating it — applied to a **binary**
outcome under [`quorum`](#quorum) split trust. Two parties fully collateralise a pot on
a yes/no question and it offers two branches:

```
    settle   Σ valid_i( sig_i over question‖outcome under N_i ) ≥ m,  o ∈ {0,1}
             → the whole pot (own input value − fee) is paid to  o==1 ? YES owner : NO owner
    refund   nLockTime ≥ deadline  ∧  input non-final
             → the pot is split 50/50 back to both owners (no oracle, no signature)
```

The `refund` branch is the honest completion of the instrument: if the oracle panel
all vanishes, either party may, after the baked deadline, force the pot back to both
of them in equal halves — so no one's collateral is trapped by an oracle that never
speaks. It is a proper preimage timelock ([`timelock`](#timelock)): `nLockTime` is
read from the preimage and required `≥ deadline`, the input is required non-final —
without which `nLockTime` would be inert ([pitfall 6](pitfalls.md#6-op_checklocktimeverify-does-not-work-on-bsv)) —
and, because a losing party would gain from refunding *early*, the check also pins the
BIP-65 **domain**: a height deadline demands a height `nLockTime`, not a past timestamp
that is numerically larger but final immediately ([pitfall 27](pitfalls.md#27-a-preimage-nlocktime-check-must-pin-the-domain-not-just-the-magnitude)).
The refund's two halves need only cover the fee and stay positive — BSV removed the
dust limit from node policy, so even small outputs relay ([pitfall 13](pitfalls.md#13-client-side-checks-that-are-not-the-networks)),
and the `DUST` constant here is just the conservative amount the bench *funds* its demo
coins with, not a floor either output must clear.

It inherits `settlement`'s soundness, sharpened by the quorum and tested by what it
refuses:

- **The outcome is the oracles', for this question.** The oracle message is built
  from the *baked* question spliced with the presented outcome, and the quorum count
  runs over it, so a settlement can only pay the side m oracles actually attested. A
  forged outcome, a sub-quorum, a replayed oracle, or an attestation for a different
  question is refused.
- **The payout is forced and unskewable.** The pot is read from the covenant's own
  input value and both owners are baked at lock time, so any party may broadcast the
  settlement and there is exactly one payout it can broadcast — paying the loser, or
  short-paying the winner, fails the `hashOutputs` bind.
- **It asserts `SIGHASH_ALL`.** Because it binds outputs, a `SINGLE|ANYONECANPAY`
  core is refused ([pitfall 8](pitfalls.md#8-the-sighash-flag-decides-what-the-covenant-commits-to)).

Interpreter-verified across 17 cases — 4 accepts (YES wins, NO wins, unanimous, and
the deadline refund) and 13 refusals (sub-quorum, replayed oracle, forged/out-of-range
outcome, foreign question, paying the loser, skimming the pot, a `SINGLE|ANYONECANPAY`
core, a refund before the deadline, a refund with a final sequence, an uneven refund
split, and a refund with a timestamp-domain `nLockTime` beating the height deadline). Winner-take-all is the binary case; a graded payout is `settlement`'s
piecewise line. This is the framework's complete end-to-end two-party market; the
reusable [`resolution`](#resolution) object with witnessing positions is the path to
markets of many positions, and [`marketN`](#marketn) below is the same instrument for
more than two outcomes.

## marketN

`marketN` generalises [`market`](#market) from a yes/no question to a field of `K`
mutually-exclusive outcomes — *which* candidate wins, *which* team takes the title, the
roadmap's multiple-choice market. Everyone stakes one pot; when the quorum attests the
winning outcome **index**, the whole pot (minus a fee) is forced to that outcome's owner:

```
    settle   Σ valid_i( sig_i over question‖outcome under N_i ) ≥ m,  o ∈ [0, K)
             → the whole pot goes to owner[o]
    refund   after the deadline, the pot splits into K equal shares, one per owner
```

The one new mechanism over the binary market is the **K-way winner selection**: the
covenant carries `K` baked payout scripts and, from the single attested index `o`, picks
exactly one with a nested `OP_IF` cascade — `o==0 ? owner0 : o==1 ? owner1 : … : owner_{K-1}`.
A **range guard** (`0 ≤ o ≤ K-1`) runs first, so the fall-through arm (the last outcome)
cannot be reached by a forged out-of-range index. Everything else is `market`'s, unchanged:
the outcome is the oracles', bound to *this* question; the pot and every owner are fixed at
lock time; it binds outputs so it asserts `SIGHASH_ALL`; and the refund pins the BIP-65
domain ([pitfall 27](pitfalls.md#27-a-preimage-nlocktime-check-must-pin-the-domain-not-just-the-magnitude)),
splitting the pot into `K` exact shares (the last owner takes the remainder, so the sum is
exact to the satoshi).

Interpreter-verified across 14 cases at `K=3` and `K=4` — 5 accepts (each outcome wins,
including the cascade fall-through, and the K-way refund) and 9 refusals (sub-quorum, a
replayed oracle, a forged or out-of-range index, a foreign question, paying a losing owner,
a `SINGLE|ANYONECANPAY` core, an early refund, and an uneven K-way split). The script grows
with `K` (1232 B at K=3, 1301 B at K=4). Binary [`market`](#market) is the `K=2`
specialisation with a single `OP_IF`; a *graded* rather than winner-take-all payout is
[`marketScalar`](#marketscalar) below.

## marketScalar

`market` and `marketN` pay winner-take-all; `marketScalar` pays a **graded amount that is
a function of the number the oracles attest** — a contract for difference, a ranged
insurance payout, a parametric bet. It is exactly [`settlement`](#settlement)'s piecewise-
linear split, lifted from a single oracle to `m`-of-`n` [`quorum`](#quorum) split trust.
Two parties, LONG and SHORT, collateralise the pot; the quorum attests a value `v` for the
question, and the pot is divided by the same rule `settlement` uses:

```
    v ≤ LOW          → LONG gets 0,               SHORT gets all
    v ≥ HIGH         → LONG gets the whole pot,    SHORT gets 0
    LOW < v < HIGH   → LONG gets pot·(v−LOW)/RANGE, SHORT gets the rest       (RANGE = HIGH−LOW)
    refund           → after the deadline, the pot splits 50/50 back to both
```

Conservation is exact by construction — `payShort = pot − payLong`, computed with the same
integer clamp/multiply/divide in Script as in JS. The value is the oracles' to attest and is
bound to *this* question (a forged value, a sub-quorum, or a value signed for another
question is refused), both destinations are fixed at lock time, and the split is bound by
`hashOutputs` so no party can skew it — paying LONG a satoshi more than the rule fails. Like
the other markets it binds outputs (so it asserts `SIGHASH_ALL`) and its refund pins the
BIP-65 domain ([pitfall 27](pitfalls.md#27-a-preimage-nlocktime-check-must-pin-the-domain-not-just-the-magnitude)).

Interpreter-verified across 12 cases (1178 B) — 4 accepts (a mid-range split, a quarter
split, and both clamped extremes) and 8 refusals (sub-quorum, a replayed oracle, a forged
value, a foreign question, a skewed split, a `SINGLE|ANYONECANPAY` core, an early refund).
This completes the market trilogy: binary [`market`](#market), categorical [`marketN`](#marketn),
and scalar `marketScalar` — winner-take-all on a bit, on an index, and a graded payout on a
number, each under an oracle quorum with a refund.

## bulletin

Every market so far settles a *single* pot. A market of **many independent positions** needs
the outcome to be a fact that any number of coins can read without any of them consuming it —
and that is `bulletin`. It is [`resolution`](#resolution) made **persistent**: the quorum moves
it from `OPEN` to `RESOLVED` exactly once, and thereafter it **recreates itself, unchanged, on
every spend**:

```
    resolve   OPEN → RESOLVED,  Σ valid_i(sig_i over question‖outcome under N_i) ≥ m
    read      RESOLVED → RESOLVED, the whole coin re-emitted at output 0 (minus a fee)
```

The `read` branch is permissionless and binds only output 0 to the bulletin recreated
byte-for-byte; a **tail** of arbitrary trailing outputs is allowed ([pitfall 26](pitfalls.md#26-a-fixed-output-count-backtrace-strands-a-coin-whose-parent-has-change)),
so a whole batch of position payouts can ride behind it in one transaction. Because the coin's
own covenant runs on every hop, the committed outcome can never change once resolved — a coin
that co-spends the bulletin and reads output 0 is reading a fact the chain guarantees, not one
the spender asserts. Verified across 8 cases (1091 B): the quorum resolves it (and a sub-quorum,
a forged outcome, or a wrong-question attestation cannot), a resolved bulletin recreates itself
on a read, an `OPEN` one cannot be read, and a read may not alter the outcome.

## position

`position` is a fully-collateralised **binary option** that settles by **reading** a shared
[`bulletin`](#bulletin), not by consuming it — which is exactly what lets many of them settle
against one resolution. A position stakes a side of a yes/no question; when the bulletin is
resolved, it pays out:

```
    outcome == side   →  the OWNER called it right and may take the collateral
    outcome != side   →  the COUNTERPARTY takes it
```

Soundness is the [`witness`](#witness) cross-coin mechanism, unchanged: the position bakes the
bulletin's outpoint, requires (via `hashPrevouts`) that this exact coin is **co-spent now**,
rebuilds the bulletin's source transaction and requires it to hash to the baked txid, and reads
the outcome straight out of the bulletin's committed state at output 0 — a fact the bulletin's
own covenant, running on the co-spent input, guarantees. The state's question must equal the
position's own, so it cannot be settled against another market's bulletin; and the winner signs
to take the coin, which of the two being the winner not the spender's to choose. Verified across
7 cases (581 B): the owner claims when right, the counterparty when the owner was wrong, and a
loser, a stranger, or a different-question bulletin are all refused.

Together they scale: a `tools/manypositions-selftest.js` demonstration settles **three
independent positions against one reusable bulletin in a single transaction**, each interpreter-
verified — the bulletin recreates at output 0 while each stake is paid to whoever was right.

**Honest scope.** A position references its bulletin by a specific outpoint (as `witness` does
its sibling), so a batch settles against a live, resolved bulletin. Writing a position *before*
the outcome is known, against a bulletin that has since been read many times, needs the bulletin
to carry a **descent** proof back to its genesis — [`descentbulletin`](#descentbulletin) below is
that mechanism. A single atomic settlement of N covenant inputs still needs the coordinated
multi-input `OP_PUSH_TX` grind [`pool`](#pool) and [`ledger`](#ledger) pay at deploy time — a
cost, not a soundness gap.

## descentbulletin

`bulletin` is reusable but not yet *counterfeit-proof*: nothing stops someone funding a raw
output whose bytes are a RESOLVED bulletin with a forged outcome, so a position that trusts any
coin carrying the market's identity could be fooled. `descentbulletin` closes that the way
[`lineage`](#lineage) closes it for a token — it carries its **genesis outpoint** `G`, and on
*every* spend proves, by a bounded one-hop backtrace, that its immediate parent was either the
genesis mint of `G` or another descent-bulletin of the same `G`:

```
    state = genesis(36) ‖ status(1) ‖ outcome(1)
    resolve   OPEN → RESOLVED, quorum-gated, proving descent from G
    read      RESOLVED → RESOLVED, recreated unchanged, proving descent from G
```

The novel part over `lineage` is **descent across a state change**. A `lineage` token recreates
its coin byte-for-byte, so a parent output is literally its child's; a bulletin's parent may be
`OPEN` while the child is `RESOLVED`, so the parent check compares the parent's chunk to the
child's *except the mutable status and outcome bytes* — same covenant, same `G`, any state — and
each of those comparisons is **non-aborting**, combined as `isMint ∨ isChild`, so the genuine
mint hop (where the child-checks are legitimately false) still passes.

Soundness is inductive, exactly as `lineage` argues: a spend is valid only if its funding
transaction is real and network-validated; if that funding spent a parent bulletin, then the
parent's covenant ran and enforced *its own* descent when the funding was mined — so authenticity
chains back to the one spend of `G`. A counterfeit — a RESOLVED bulletin minted from a plain UTXO
— carries the genesis bytes but did not descend from `G`, so it can be created but **never read
or resolved**: its parent is a plain output, not a same-`G` bulletin, and the backtrace misses.

Interpreter-verified across 5 cases (1351 B): the quorum resolves the genesis-minted bulletin (a
sub-quorum and a wrong-genesis attestation cannot), a RESOLVED bulletin is read with its parent
proven the same-`G` OPEN bulletin (the state-change hop), and the counterfeit is refused. This is
what a market of positions written *before* resolution rests on: a position commits to `G`, and
may trust the outcome of any bulletin that carries `G` and can still be spent — because one that
did not descend from the unique genesis cannot be. Kept single-output here to isolate the descent
mechanism; [`descentmarket`](#descentmarket) below carries the `pTail` of position payouts.

## descentmarket

`descentmarket` is the **unification** — the single deployable coin a market of positions written
*before* the outcome is known rests on. It is [`descentbulletin`](#descentbulletin)'s counterfeit-
proof descent **and** [`bulletin`](#bulletin)'s `pTail` co-settlement in one covenant: on every
hop it proves it descends from the genesis `G`, and it recreates itself at output 0 while a tail
of arbitrary trailing outputs — the position payouts — rides behind it.

```
    resolve   OPEN → RESOLVED, quorum-gated, proving descent from G, recreated at output 0 (+ pTail)
    read      RESOLVED → RESOLVED, recreated unchanged at output 0 (+ pTail), proving descent from G
```

Two generalisations over `descentbulletin` make the tail possible, and both are load-bearing:

- **The recreate binds output 0, not the whole output set.** `HASH256(output0 ‖ myPTail)` must
  equal `hashOutputs`, so the coin is forced to persist unchanged at output 0 while the position
  payouts are free in the tail — a tampered tail fails the bind.
- **The descent backtrace rebuilds a *multi-output* parent.** A read that co-settled positions is
  itself a multi-output parent for the next read, so the parent rebuild folds the output count into
  `iblob2` and presents the parent's own trailing outputs (`parentPTail`), exactly as
  [`conserve`](#conserve)'s parent backtrace does ([pitfall 26](pitfalls.md#26-a-fixed-output-count-backtrace-strands-a-coin-whose-parent-has-change)).
  The suite exercises this directly: a `read-of-read` whose parent's funding was a two-output
  co-settlement still verifies.

Interpreter-verified across 6 cases (1373 B): the quorum resolves the genesis-minted coin, a read
carries a position payout in its tail, a `read-of-read` backtraces a multi-output parent, and the
guards still bite — a sub-quorum, a counterfeit minted from a plain UTXO, and a tampered payout
tail are all refused. This closes the many-positions architecture into one coin, and
[`positionv2`](#positionv2) is the position that spends against it.

## positionv2

[`position`](#position) bakes the specific coin it settles against, so it can only be written after
that coin exists. `positionv2` bakes the market's **identity** instead — the [`descentmarket`](#descentmarket)
covenant-script hash with the mutable status and outcome blanked, which commits to the genesis `G`,
the oracle panel, and the logic but *not* the state — so it can be written **before the outcome is
known** and settle against *any* genuine `descentmarket` of that market it later co-spends:

```
    co-spend a descentmarket, rebuild its source, and take output 0 as the market coin;
    require HASH256(its script, status+outcome blanked) == the baked market id;
    require it RESOLVED, read the outcome;
    outcome == side ? the OWNER takes the collateral : the COUNTERPARTY does.
```

The soundness rests on `descentmarket`'s own guarantee. The identity check pins the co-spent coin to
the exact covenant of this market (a coin from a *different* market — a different `G` — hashes to a
different id and is refused), and because that coin is **co-spent**, its own covenant runs and enforces
descent from `G` when the transaction is validated. A counterfeit carrying `G`'s bytes with a forged
outcome either fails the identity check or, if it wears the real covenant, cannot be spent at all — so
the outcome this position reads is one the chain, not the spender, guarantees.

Interpreter-verified across 6 cases (533 B): a YES/NO stake pays the owner or the counterparty by the
resolved outcome, and a loser, a stranger, and a coin from a different market are all refused. Together
with `descentmarket` this makes the market of many positions **turnkey**: write positions against a
market's identity before it resolves, resolve the one coin by quorum, and settle every position against
it — none consuming it, none forgeable.
**Refuses:** fewer than `m` genuine signatures; one oracle stuffed into several
slots; a value below the threshold; a forged value; attestations for another feed;
a claimant without the winner's key.

## ticker

Every oracle covenant so far consumed an attestation and then *terminated*.
`ticker` consumes one and **recreates itself**, carrying the attested value
forward in its own scriptCode — an on-chain mirror of a signed feed that anyone
can advance with a fresh attestation, and that no single spend can revert. It is
the [`metered`](#metered) self-recreation fed by an [`oracle`](#oracle) instead of
an internal `+1`, and it forces a problem the stateless oracle covenants never
faced.

### Why freshness is the whole problem

An oracle attestation is public, reusable bytes. A stateful oracle covenant that
accepted *any* valid attestation could be handed an **old** one to roll its state
backwards — yesterday's price replayed over today's. So each attestation carries a
**round**, the covenant records the current round in its own state, and an update
is refused unless the new round strictly exceeds it:

```
    state (in scriptCode) = round(4) ‖ price(4)
    oracle message        = TAG(8) ‖ round(4) ‖ price(4)
    update requires         newRound > oldRound        (read from own scriptCode)
```

The new `round‖price` are lifted straight out of the *signed* message, so the
spender cannot choose them (bound by Rabin) and cannot replay an old one (the round
must rise). This monotonicity guard, checked by the script against its own past, is
the piece that only appears once state and an oracle meet — neither `metered` (no
external input) nor `oracle` (no state) needs it.

### Two branches, and the exit that must exist

`OP_1` **update** takes a fresher attestation and recreates the ticker with the new
state spliced into its own bytes — the [`metered`](#metered) trick, but the mutated
field comes from outside. `OP_0` **redeem** lets the funder sign and sweep the
remainder. That exit is not optional: each update pays a fee out of the coin, so
without an off-switch the remainder would strand at dust
([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)). This is
also the covenant where the shared-preimage `authenticateThenBranch` earns its
keep — both branches bind an output and so both authenticate, once.

Deployed on mainnet as a full lifecycle: **deploy (round 0) → update (round 1) →
update (round 2) → redeem**, each update carrying a strictly-higher round, the
recreated script's embedded state advancing `6000 → 6300 → 6100` in its own bytes,
every hop byte-for-byte reproducible. See the [mainnet log](mainnet-log.md#ticker).

**Refuses:** an attestation whose round does not exceed the current one — a replay
of the same round, or a rollback to an older one; a forged price; an attestation
for another feed; a successor whose spliced state is not the signed one; any skim
of the carried value; a redeem without the funder's key.

## journal

The state covenants so far ([`metered`](#metered), [`ticker`](#ticker)) carry a
value and advance it. `journal` carries a **hash chain** — and with it, the chain
stops merely *storing* a sequence of records and starts *enforcing the progression
between them*. It is an append-only, authenticated log:

```
    state = seq(4) ‖ head(32) ‖ publisher(20)

    append   seq += 1 ;  head = HASH256(head ‖ recordHash) ;  recreate
    close    the publisher sweeps the remainder and stops
```

The `head` is a rolling commitment to the log's entire history: each append folds
the new record's hash into it. Reorder a past entry, delete one, or substitute one,
and every subsequent `head` changes — so the log is **append-only and tamper-evident
by construction**, checked on chain rather than trusted to a server. The sequence
must advance by exactly one (no skips, no repeats), and the publisher — fixed in the
state — signs every transition.

### The record stays off chain

Only a record's *hash* enters the chain, not the record. So the covenant enforces
the **structure and provenance** of a stream whose payload it never sees — the chain
guards the envelope; authorised parties hold the contents. That separation is what
makes an authenticated private data stream possible on a public ledger: an audit
log, a document lifecycle, a message queue, a software-release chain — anything whose
*ordering and authorship* must be provable while its *content* stays opaque.

The `close` branch is the exit a fee-draining self-recreating covenant must have
([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)); it sweeps
the remaining value to the publisher, whose P2PKH output the script builds at runtime
from the PKH in its own state.

Deployed on mainnet as a full lifecycle — deploy an empty log, **append two records,
close** — the head advancing `0…0 → HASH256(0…0 ‖ H(r₁)) → HASH256(head₁ ‖ H(r₂))`,
each recreated script reproducing `buildScript` exactly. See the
[mainnet log](mainnet-log.md#journal).

**Refuses:** an append by anyone but the publisher; a successor `head` that is not
`HASH256(head ‖ record)`; a sequence that skips, repeats, or moves backward; a close
by anyone but the publisher.

## lifecycle

Every state covenant to here advances a *value* — a counter, a round, a hash head —
along a single axis. `lifecycle` carries a **state machine**: a status that may move
only along an allowed set of transitions, an immutable core that no transition may
rewrite, and a **terminal** state from which nothing follows. It is a predicate
*object* with a constitution.

```
    state = genesis(32) ‖ status(1) ‖ issuer(20)

    transition   status: old → new, where (old, new) ∈ the allowed set ;
                 genesis and issuer spliced UNCHANGED into the successor
    retire       the issuer sweeps the remainder and stops
```

The demo is a certificate — `ISSUED → ACTIVE`, `ACTIVE ⇄ SUSPENDED`, any state
`→ REVOKED`, and `REVOKED →` nothing. The allowed pairs are baked into the script as
a set the move must be a member of, checked on chain.

### The move cannot lie about where it starts

The spender presents the move as two bytes, `old ‖ new`. Pushed whole it sidesteps
the small-integer `MINIMALDATA` trap a bare status byte would hit — but the
load-bearing part is that its **first byte must equal the object's real current
status**, read from the covenant's own state. So a spender cannot present a move out
of a state the object is not in. That is exactly what makes `REVOKED` **terminal**:
no allowed pair begins with it, and the move is not free to claim it begins
elsewhere. Terminality is not detected after the fact — the transaction that would
leave the terminal state cannot be constructed to verify at all.

### The constitution

`genesis` and `issuer` are spliced into every successor from the object's **own
state**, never from the spender. No transition can rewrite them — not even one the
issuer signs. The object's foundational terms (what it is, who governs it) are fixed
for its whole life, while its status moves within bounds. Authority itself is *state*:
the issuer is a field, and the covenant refuses any transition or retire not signed
by the key hashing to it. The `retire` branch is the exit a fee-draining
self-recreating covenant must have
([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)); it builds
the issuer's P2PKH output at runtime from the PKH in the object's own state.

Deployed on mainnet as a full lifecycle — `ISSUED → ACTIVE → SUSPENDED → ACTIVE →
REVOKED`, then a proof on chain that **every** move out of `REVOKED` refuses, then
`retire`. Each recreated script reproduces `buildScript` exactly, carrying the
untouched `genesis` and `issuer` forward. See the
[mainnet log](mainnet-log.md#lifecycle).

**Refuses:** a move not in the allowed set; any move out of a terminal state; a move
whose claimed `old` disagrees with the object's real status; a successor that rewrites
the immutable `genesis` or `issuer`; a transition or retire by anyone but the issuer.

## delegation

`token` conserved a *value* across a merge; `lifecycle` made *authority* a field.
`delegation` composes them into the [`token`](#token)-style conservation law applied
to **authority itself** — a capability carrying a quantitative budget, divisible into
a tree of sub-capabilities whose budgets can never, on any path, sum to more than the
root's.

```
    state = root(32) ‖ budget(4) ‖ owner(20)

    delegate   split off a child of budget b (1 ≤ b ≤ budget): self recreates with
               budget − b, a new node carries b under a delegate's key (two outputs)
    exercise   consume c units (1 ≤ c ≤ budget); the node recreates with budget − c
    revoke     the owner sweeps the remainder and stops
```

### Conservation, not trust

On a `delegate`, the covenant reads its own budget `P`, takes the child's budget `b`
from the spender (bounded `1 ≤ b ≤ P`), and **computes the remainder `P − b` itself**,
forcing its own successor to carry exactly that. The spender never gets to write the
parent's new budget — so `self_budget + child_budget = (P − b) + b = P`, always. A
split that tried to keep more than it gave away builds outputs the covenant did not
compute, and they miss `hashOutputs`. Apply this at every hop and the whole tree
conserves by induction: **Σ of all budgets ≤ root**, enforced on chain, no accounting
authority anywhere.

### An inductive line of descent

`root` is spliced from the node's **own state** into every successor — parent and
child alike — so every node in the tree proves descent from the same authority, the
[`lineage`](#lineage) immutability carried through a branching structure rather than a
line. A child cannot forge a different root; a node cannot rewrite its own. Authority,
identity, and budget are all *state*, and only the `owner` key — itself a field — can
move any of them.

`exercise` is the capability being **used**: the budget decrements as a use-counter,
and the leaf case (a token that permits N actions, spent to zero) falls straight out.
`revoke` is the exit a fee-draining self-recreating covenant must have
([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)); it builds
the owner's P2PKH at runtime from the PKH in the node's own state.

Deployed on mainnet as a two-level tree — deploy a **budget-100 root**, `delegate 40`
(self keeps 60, child gets 40 — `60 + 40 = 100`, on chain), `exercise 15` on the
child (→ 25), then `revoke` both leaves. See the
[mainnet log](mainnet-log.md#delegation).

**Refuses:** delegating zero or more than the budget; a non-conserving split (a self
that keeps more than `budget − b`); a child or successor that rewrites the immutable
`root`; exercising zero, more than the budget, or by the wrong amount; any delegate,
exercise, or revoke not signed by the node's owner.

## witness

Every covenant so far reasons about its OWN state, or — [`companion`](#companion),
[`token`](#token) — a sibling's identity or value. `witness` reads a sibling's **state**
and gates on it: a payment that releases only inside a transaction that also spends a
SPECIFIC other coin, and only when that coin carries a required value in its script. One
contract's spendability conditioned on another contract's on-chain state — the two-body
invariant, kept sound.

The sibling is a *tagged coin* — `<flag,4> OP_DROP <P2PKH>`, an ordinary spendable output
that also commits a value. The witness makes three checks, each one the honest version of
its claim:

```
    1. companion  — the baked sibling outpoint is genuinely an input of THIS tx
                    (HASH256(prefix ‖ sibling ‖ suffix) == hashPrevouts)
    2. backtrace  — the sibling's SOURCE tx, rebuilt and hashed, is that outpoint's txid;
                    its output 0 is the tagged coin, so its flag is read straight out
    3. signature  — the beneficiary signs, so only they trigger the release
```

### Why each check is load-bearing

The **outpoint is baked**, not chosen by the spender — so the witness names *one specific
coin*, not "some coin that happens to carry the flag." A spender who supplies a different
coin fails the companion check (the reassembled prevouts miss the real `hashPrevouts`). The
**backtrace** ties the flag to that exact coin: the source transaction the spender presents
must hash to the baked txid, and only the coin's real bytes do — a forged source claiming a
different flag hashes to a different txid and is refused. And because the coin is required as
a live *input* (check 1), its state is **current**, not merely historical. Together: the
witness releases only when *this* coin, *now* being spent, carries *this* value. What it
does not claim — honestly, like [`companion`](#companion) — is anything about coins the
transaction does not spend.

This is the sound floor under "cross-object invariant." Full numerical *conservation* across
two independent covenants (`A.qty + B.qty` fixed) additionally needs each side to prove the
other is a canonical, non-counterfeit member — which is what [`lineage`](#lineage) and
[`sovereign`](#sovereign) supply; `witness` is the piece that reads and gates on the state.

Deployed on mainnet: a **tagged coin** was minted carrying flag 1, a witness was deployed
watching it, and a single transaction spent **both** — the witness releasing its 5000 sat to
the beneficiary because, and only because, the named coin was co-spent showing flag 1. See
the [mainnet log](mainnet-log.md#witness).

**Refuses:** a sibling carrying the wrong flag; a transaction that does not spend the demanded
sibling at all; a forged source transaction that cannot hash to the real coin's txid; a
release triggered by anyone but the beneficiary.

## conserve

The capstone. `witness` gated on another coin's state; this goes the whole distance — a
**conserved, uncounterfeitable two-body pair**. Two coins, side 0 and side 1, born together
from one genesis; a rebalance spends BOTH and recreates BOTH, moving quantity between them
while `side0.balance + side1.balance` stays fixed — and no counterfeit pair can ever spend, so
the conserved total is real, not a number anyone can mint. It fuses three mechanisms the bench
proved one at a time:

- [`token`](#token)'s backtrace — to read a sibling's balance without trusting the spender;
- [`companion`](#companion) — to pin the sibling as a genuine co-input;
- [`lineage`](#lineage)'s descent — so only coins descending from the genesis can spend.

```
    state = G(36) ‖ side(1) ‖ balance(4) ‖ owner(20)

    rebalance   spend the pair (side0, side1) → recreate (side0', side1'),
                a + b == a' + b', G and owners carried forward, both owners sign
```

### One backtrace does everything

The insight that makes it tractable: a genesis or rebalance transaction creates **both** coins
together — side 0 at output 0, side 1 at output 1. So each coin's unlock backtraces the single
**shared parent** transaction, and that one rebuild yields everything at once:

- the parent's txid equals this coin's own funding txid — it *is* my real parent;
- the parent's two outputs are the side-0 and side-1 coins — their balances `a`, `b` read
  straight out, and my own script is one of them;
- the sibling's outpoint is `(parentTxid, other side)` — pinned and required co-spent, so the
  canonical partner is consumed, never a fake;
- the parent descends from genesis — it spent the genesis outpoint `G` directly, or *its* parent
  was a genuine pair coin ([`lineage`](#lineage)'s induction, one hop, the rest by network
  validation).

Then `a + b == a' + b'`, and the two successors — `G` and owners unchanged, balances updated —
are bound to `hashOutputs`. The script is **side-agnostic**: both coins run identical logic and
differ only in state, so neither embeds the other's bytes (no circular self-reference); each
reads the other's script from the shared parent and splices the new balance in.

### Why the total is real

A counterfeit pair — coin bytes minted from a plain UTXO — can be *created* but never *spent*:
its parent did not spend `G`, and no forged ancestor both hashes to what the parent spent and
carries a genuine pair coin at output 0. So counterfeits never enter circulation, and every
spendable pair traces to the one genesis, whose `a₀ + b₀` is the total every later `(a, b)` sums
to — conservation that means something because supply cannot be inflated. This is what
separates `conserve` from [`token`](#token) (which conserves locally but does not bound supply)
and completes what [`sovereign`](#sovereign) began, across *two* coins instead of one.

Deployed on mainnet: a genesis minted the pair `(60, 40)`, then a rebalance spent both and
recreated them as `(25, 75)` — the sum held at 100 on chain, the new balances readable straight
from the coins' bytes. See the [mainnet log](mainnet-log.md#conserve).

**Refuses:** a rebalance that does not conserve the sum; a counterfeit pair never minted from the
genesis; a spend signed by the wrong owner; a spend that leaves the canonical partner un-spent; a
successor that rewrites the genesis or an owner. (And a hard-won lesson:
[pitfall 26](pitfalls.md#26-a-fixed-output-count-backtrace-strands-a-coin-whose-parent-has-change).)

## guarded

Two cross-object relationships in **one** covenant: `conserve ∧ witness`. A conserved pair
(everything [`conserve`](#conserve) does) whose rebalance is *also* gated on a named oracle coin
carrying a required flag (everything [`witness`](#witness) does). To move the pair you must
conserve the sum, prove descent, co-spend the partner — and, on top of all of it, co-spend a
specific oracle coin in the required state.

```
    state = G(36) ‖ side(1) ‖ balance(4) ‖ owner(20)          (+ oracle outpoint & flag, baked)

    rebalance   the conserve rebalance, AND: a baked oracle outpoint must be input 2,
                its source tx backtraced, its committed flag equal to the required value
```

This is not a new mechanism — it is the *composition* of two proven ones, and the point is that
the composition holds. The oracle gate reuses the pair's already-verified `suffix` (the outpoints
after the pair) to pin the oracle at input 2, then runs a [`token`](#token)-style backtrace of the
oracle's source transaction to read its flag — the [`witness`](#witness) construction, spliced into
[`conserve`](#conserve)'s rebalance. Every conserve check still bites (conservation, descent,
ownership, the co-spent partner); the oracle gate is added on top, so the pair simply cannot move
while the oracle is absent or in the wrong state.

`guarded` is the predicate the [constraint-graph compiler](relational.md#the-constraint-graph)
*specified* before it existed: an object that both `conservesWith` a partner and `dependsOn` an
oracle. The graph printed its obligation union and named the composition needed; building it turned
that name into a byte-identical lowering — the graph now emits `guarded` for exactly that role-set.

Deployed on mainnet: an oracle coin (flag 1), a genesis pair `(60, 40)` baking that oracle, then a
rebalance to `(25, 75)` spending **four** inputs — the two coins, the oracle, and a fee — the sum
held at 100 and the oracle gate enforced (input 2). See the [mainnet log](mainnet-log.md#guarded).

**Refuses:** everything `conserve` refuses, plus a rebalance where the oracle is not co-spent, or is
co-spent carrying the wrong flag.

## pool

[`conserve`](#conserve) fixed a total across *two* coins; `pool` fixes it across **N**. A group of
coins whose balances always sum to the same constant, rebalanced by a transaction that spends ALL of
them and recreates ALL of them — a treasury split into buckets (Treasury, Operations, Research, …)
that may move quantity between buckets but can never change the total, and cannot be counterfeited
into existence. A **distributed conserved state system**.

```
    state = G(36) ‖ index(1) ‖ balance(4) ‖ owner(20)

    rebalance   spend the N members (inputs 0..N−1, in index order), recreate the N members,
                Σ balanceᵢ preserved, G and owners carried forward, every owner signs, every
                member descends from the genesis
```

It is `conserve`'s machinery with 2 replaced by a **baked N**. The same shared-parent insight scales:
one backtrace of the transaction that created all N members reads *every* balance at once, confirms
the whole group is co-spent in index order, checks the sum, proves descent, and binds the N
successors — the codegen simply unrolls each per-member step N times. The script stays index-agnostic:
every member runs identical logic, differing only in its state, so no member embeds another's bytes.
`N` is a build parameter (2..16); the coin grows about 170 bytes per member.

Deployed on mainnet as an **N=3 treasury** — a genesis minting three buckets `(50, 30, 20)`, then a
rebalance to `(40, 40, 20)` spending **four** inputs (the three buckets and a fee) — the total held at
100 on chain, each bucket's new balance readable from its bytes. The [relationship
compiler](relational.md#the-constraint-graph) lowers a `conservedGroup` declaration straight to it,
byte-identical. See the [mainnet log](mainnet-log.md#pool).

**Refuses:** a rebalance that changes the total; a group with any member not co-spent; a counterfeit
group never minted from the genesis; a spend signed by a member's wrong owner.

## audited

The first **cross-class** composition — [`conserve`](#conserve) (relational) ∧
[`journal`](#journal) (temporal) in one covenant. A conserved two-body pair whose every rebalance
is *also* appended to an embedded, tamper-evident audit chain. A treasury that is both **balanced
and auditable**: it cannot change its total, and it cannot move without recording the move.

```
    state = G(36) ‖ side(1) ‖ balance(4) ‖ owner(20) ‖ seq(4) ‖ head(32)

    rebalance   the conserve rebalance, AND for each coin: seq += 1 and
                head = HASH256(oldHead ‖ recordHash), sharing one recordHash per rebalance
```

Every conserve invariant still holds (sum preserved, descent proven, partner co-spent, owner
signs). On top, each coin carries the [`journal`](#journal) audit chain: the `head` is a rolling
commitment to the coin's whole rebalance history, so reordering, deleting, or forging a past
rebalance changes every later `head`. The two coins share the one `recordHash` for a rebalance —
they log the same event — and advance in lockstep. Only the record's *hash* enters the chain; the
record itself stays off-chain, so the covenant enforces the ordering and authorship of the
treasury's history while the entries stay private.

A subtlety the state size forces: at 97 bytes the state no longer fits a single-byte push, so it is
pushed with `OP_PUSHDATA1` — a two-byte push-op — and the chunk header is `varint(3) ‖ pushop(2)`,
not `‖ pushop(1)`. Get that wrong and every field offset is off by one (a close cousin of
[pitfall 21](pitfalls.md#21-fixed-width-state-or-the-offsets-move)).

Deployed on mainnet: a genesis pair `(60, 40)` at audit seq 0, then a rebalance to `(45, 55)` that
advanced both coins to seq 1 with `head = HASH256(0…0 ‖ recordHash)` — balances conserved and the
audit chain extended, in one transaction. See the [mainnet log](mainnet-log.md#audited).

**Refuses:** everything `conserve` refuses, plus a successor that fails to advance the audit `seq`,
or whose `head` is not the correct `HASH256(oldHead ‖ recordHash)`.

## ledger

[`pool`](#pool) ∧ [`journal`](#journal): the N-body form of [`audited`](#audited). A group of N
buckets whose balances always sum to a constant **and** whose every rebalance is appended to each
bucket's own audit chain. A distributed treasury that is conserved, uncounterfeitable, *and* fully
auditable — the buckets can be re-allocated, but never inflated, and never moved without recording
the move.

```
    state = G(36) ‖ index(1) ‖ balance(4) ‖ owner(20) ‖ seq(4) ‖ head(32)

    rebalance   spend the N members, recreate the N members, Σ balanceᵢ preserved, descent
                proven, every owner signs — AND for each member: seq += 1 and
                head = HASH256(oldHead ‖ recordHash), sharing one record per rebalance
```

`ledger` is what the [composition-safety checker](relational.md) *predicted*: before it existed, the
checker judged `conserve ∧ journal` (for N) safe to build — disjoint writes (`balance` vs `seq, head`),
one output-set claimant — and here it is, built and deployed exactly as predicted. The
[graph](relational.md#the-constraint-graph) now emits it for the role-set
`conservedGroup ∧ journal`, byte-identical.

Deployed on mainnet as an **N=3 audited treasury** — a genesis minting three buckets `(50, 30, 20)` at
audit seq 0, then a rebalance to `(40, 40, 20)` that advanced all three to seq 1 with a shared
`head = HASH256(0…0 ‖ recordHash)` — the total held at 100 and the audit chain extended, in one
four-input transaction. See the [mainnet log](mainnet-log.md#ledger).

**Refuses:** a rebalance that changes the total; any member not co-spent; a counterfeit group; a
member's wrong owner; a member that fails to advance its audit `seq` or whose `head` is not the
correct chain.

## turns

A two-player, turn-based game state machine — the on-chain **referee** the game/education
layer needs. Bitcoin will not let the wrong player move, will not let a player move twice,
and forces the turn to alternate and the game state to carry forward.

```
    state = a(20) ‖ b(20) ‖ turn(1) ‖ gstate(32)

    move    the player whose turn it is (a if turn 0, b if turn 1) signs, chooses the next
            32-byte game state, and the coin recreates itself with the turn flipped
    settle  BOTH players sign to end the game and pay the pot to an agreed winner (the exit)
```

The new mechanism is **turn-bound authority**: the signer must be `a ∧ turn 0` or `b ∧ turn 1`,
so possession of the coin is not enough — the player whose turn it *is* must sign, and the
successor must flip the turn. The game state is spender-chosen (a board hash, a score
encoding — whatever the app commits to), spliced in like [`titled`](#titled), with everything
else identical. What `turns` enforces is the universal spine of every turn game; a specific
game's move legality (a square is empty, a jump is valid) composes on top — see
[roadmap.md](roadmap.md). The beginner-facing `game()` builder lowers to it, and *“I wrote a
game rule and Bitcoin refuses cheating”* is the teaching point.

Deployed on mainnet as a full game — deploy a pot, **player a moves, player b moves** (the
turn alternating on chain), then **both settle** and the pot pays the winner. See the
[mainnet log](mainnet-log.md#turns).

**Refuses:** a move by anyone but the player whose turn it is; a move that does not flip the
turn; a settle without both signatures.

## vesting

The bench can lock coins *until* a floor ([`timelock`](#timelock)) and release a
fixed set *at once* ([`covenant`](#covenant)); `vesting` releases them
**gradually**. A grant streams to a beneficiary linearly between two times — at any
moment they withdraw everything vested so far, and the covenant recreates itself
holding exactly the *unvested* remainder:

```
    unvested(T) = total · clamp(end − T, 0, end − start) / (end − start)
```

The beneficiary spends at time `T`; the script computes `unvested(T)` itself, keeps
that much in a recreated copy of itself, and pays the rest out. Because `unvested`
only falls, each withdrawal extracts exactly what vested since the last one — a
stream, settled whenever the beneficiary likes.

### Why the clock cannot be cheated

"It is at least time `T`" is not the spender's word. The withdraw reads `nLockTime`
out of the authenticated preimage *and* requires a non-final sequence — so the
transaction is unminable before `T`, the [`timelock`](#timelock) rule. A future
`nLockTime` only mines in the future, so no one can claim tomorrow's vesting today;
a low `nLockTime` merely vests less. And the amounts are **computed by the script,
never supplied** — `unvested(T)` and the payout both — so no larger withdrawal
slips past the `hashOutputs` binding. The refusal that proves it: a withdraw with a
*final* sequence, which would make `nLockTime` inert, is rejected.

### Two branches the schedule chooses

`OP_1` **withdraw** applies while `unvested ≥ DUST`: recreate self at `unvested`,
pay the beneficiary the rest. `OP_0` **finish** applies once `unvested < DUST`: the
grant is essentially complete, so pay it all out and stop recreating — the exit a
fee-draining self-recreating covenant must have
([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)). The
guards are exact complements, so the spender cannot pick the wrong one. The grant
is irrevocable; a grantor clawback is the obvious variant.

Deployed on mainnet as a full stream: **grant 8000 → withdraw @25% → withdraw @50%
→ finish**, the recreated covenant's retained value tracking `unvested` exactly at
`8000 → 6027 → 4032 → 0`, the beneficiary drawing `1673 + 1695 + 3732`. See the
[mainnet log](mainnet-log.md#vesting).

**Refuses:** a withdraw by anyone but the beneficiary; a final sequence that would
make the clock inert; retaining less than `unvested(T)`; redirecting the payout to
another address; finishing while still vesting, or withdrawing once fully vested.

## timelock

Three things must all hold, and dropping any one leaves a script that still
verifies:

1. **The preimage is bound** by OP_PUSH_TX.
2. **The input is non-final.** Otherwise nLockTime is inert — see
   [pitfalls 4](pitfalls.md#11-reading-nlocktime-without-reading-nsequence).
3. **nLockTime is read unsigned**, padded then `OP_BIN2NUM` — see
   [pitfalls 1](pitfalls.md#1-consensus-valid-is-not-relayable) and
   [5](pitfalls.md#12-the-sign-bit-in-nlocktime).

The spend grinds the **input's sequence**, not `nLockTime`. Using `nLockTime` as
the nonce moves the lock itself — one unit per attempt, which against a height
floor is one whole block per attempt and turns a one-block lock into hours. The
sequence is malleable too and must be non-final anyway, so sweeping it down from
`0xfffffffe` leaves the floor exactly where it was asked for. See
[pitfall 5](pitfalls.md#5-grinding-nlocktime-destroys-the-lock-you-asked-for).

**Refuses:** a final sequence; an nLockTime below the floor. The suite also
asserts that *removing* the sequence check makes the attack succeed, so the test
fails if anyone deletes the guard.

## covenant

Equality on `hashOutputs` — the one output constraint a preimage can express.
`hashOutputs` is a double-SHA256 over every output's amount and script, so a
script cannot read a single amount out of it, only compare the whole
commitment. The spender chooses nothing: not the address, not the amount, not
the number of outputs.

**Refuses:** a different address; one satoshi less; one satoshi more. That last
one matters — the spender cannot even choose to take a smaller fee. See
[pitfall 17](pitfalls.md#17-a-covenant-that-dictates-outputs-also-dictates-the-fee).

## perpetual

Every spend must recreate this exact script, paying `inputValue - fee` back into
it. Coins never leave the lock; they flow forward through identical UTXOs,
shrinking by the fee. (nChain WP1605, via the library's audited PELS.)

It escapes self-hash circularity by reading itself out of the preimage — see
[preimage.md](preimage.md#reading-your-own-script).

**Refuses:** paying a plain address; skimming; overpaying itself; adding a
second output; SIGHASH_SINGLE; SIGHASH_NONE.

**Properties that surprise people:**

- **No key spends it.** Anyone can push the coin forward; they just cannot
  redirect it.
- **No change output is possible**, so any extra input a spender adds is donated
  wholesale to the miner.
- **It terminates**, and without an exit branch the remainder strands forever.
  `metered` fixes this.

## composed

Clauses ANDed on one authenticated preimage, from `src/clauses.js`. The contract
between them:

> Every clause receives the stack as `[preimage]`, consumes a **copy**, and
> leaves `[preimage]` for the next one.

That invariant is the whole game. A clause that consumed the preimage would work
perfectly alone and silently break whatever followed — and the symptom is a
script that still verifies, just not for the reason you think.

The suite therefore tests **clause order**, not just clause behaviour. Three
different orders all spend, and a reordered script still refuses a wrong
destination. Passing under several permutations is evidence the invariant holds;
passing under one hand-checked arrangement is not.

It also omits each clause in turn and asserts the matching attack *succeeds*,
proving every clause is load-bearing.

## metered

A covenant carrying mutable state in its own script.

```
<4-byte counter> OP_DROP OP_IF <hop> OP_ELSE <redeem> OP_ENDIF
```

Once a covenant can read its own bytes, it can rebuild itself with one field
changed and demand the result be what the spend pays to. Self-reference plus a
single mutation is a state machine in a UTXO.

The counter is pushed and immediately dropped — it never executes. It exists to
occupy bytes at a findable offset. **Fixed width is load-bearing**: it keeps the
script's length, its varint, and every offset identical across hops. Verified by
diffing: exactly one byte differs between counter 0 and 1, out of 913.

The script computes the successor itself, so "incremented by exactly one" is not
a condition a spender could satisfy some other way — there is only one value to
build.

The two guards are exact complements (`counter < max`, `counter >= max`), so
every counter value admits exactly one branch. No state is stuck; none opens
both paths.

**Refuses:** leaving the counter unchanged; skipping it forward; winding it
back; stripping the state; raising `maxHops` in the successor; lowering the hop
fee; redirecting the settlement address; skimming value; hopping past the limit;
redeeming early; redeeming elsewhere; redeeming the wrong amount; SIGHASH_NONE.

**What it is.** A bearer instrument with a provable transfer limit that then
settles to a known party. The transfer count is a fact about the chain, not a
number tracked alongside it.

## titled

A transferable title: a coin carrying its current owner in its own script.

```
<owner hash160, 20B> OP_DROP OP_IF <transfer> OP_ELSE <redeem> OP_ENDIF
```

The counter in `metered` was state the script could **compute** — one possible
successor, so nothing had to be trusted. An owner is different: the next owner
is chosen by the current one, so the script is handed a value it cannot derive.
That is the interesting case, and the shape of the answer is:

> Splice the supplied value into your own bytes, and force everything else to
> stay identical.

The script replaces exactly the 20 bytes of the owner field with the 20 it was
given, and demands the spend pay to the result. The new owner is free; the fee,
the logic and the branches are not. Verified by diffing two owners: bytes 1..20
differ and nothing else, out of 931.

Both branches require the current owner's signature, so **possession of the
UTXO is not authority** — the key named inside it is. Anyone can see the title
and nobody but its owner can move it.

The redeem branch is the exit that keeps it from stranding: a title can always
leave the covenant, but only to the key that currently holds it.

**Refuses:** a stranger transferring; a stranger redeeming; rewriting the fee in
the successor; escaping to a plain address; claiming a successor the payment
does not match; skimming value; redeeming to somebody else; redeeming the wrong
amount; SIGHASH_NONE; and — after a transfer — the *previous* owner doing
anything at all.

### On the claimed-vs-paid distinction

The unlocking script names the next owner, and the transaction pays it. Those
are two separate things, and a test that varies both at once tests nothing: it
is just a legitimate transfer to a different person. The real question is
whether they can *diverge* — and they cannot, because the owner signs with
SIGHASH_ALL, which commits to the outputs. A third party cannot redirect a
transfer in flight.

## royalty

A title that pays its creator on every hand-off. `titled` proved a covenant can
accept state it cannot compute; this adds the piece that makes it an
instrument.

Every spend must produce **two outputs, in order**: the recreated title under
its new owner, then a royalty payment to an address fixed when the title was
minted.

### Ordering is the mechanic

`hashOutputs` is a hash over the outputs concatenated **in sequence**. So the
covenant builds both, in the right order, and hashes the pair. One output in the
wrong position is a different hash and a dead spend. There is no way to add a
payment afterwards and no way to drop one — the suite asserts both, and asserts
that the *same two outputs in the wrong order* fail.

### The rate is proportional and travels with the title

The royalty is `value * bps / 10000`. `OP_MUL` and `OP_DIV` are available
post-Genesis and division truncates toward zero, so the royalty **rounds down**
and the rounding favours the seller. A rate that truncates to zero is refused
outright: a title whose royalty rounds away has stopped being this instrument,
and failing is more honest than silently paying nothing.

The beneficiary and the rate live in the logic half of the script, which every
hop copies verbatim. Neither can be edited by a spender, and neither needs to be
extracted — only the owner field is spliced.

### Cashing out is a sale too

The redeem branch pays the royalty as well. Without that, a seller dodges the
royalty by cashing out and settling with the buyer off-chain.

**Refuses:** dropping the royalty output; the same two outputs in the wrong
order; underpaying; overpaying; paying the royalty elsewhere; skimming the
remainder; lowering the rate in the successor; redirecting future royalties;
escaping to a plain address; a stranger transferring; a stranger cashing out;
cashing out without paying; SIGHASH_NONE; and the previous owner, after a
transfer.

### Where it terminates

Value falls by royalty plus fee each hop, and the redeem branch shrinks it too,
so the instrument has a floor: below `royalty + transferFee` nothing spends and
the remainder strands. That is the same termination property as `perpetual` —
see [pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch) —
except the exit here has a price rather than being free.

## registry

A covenant carrying a **record**, not a field.

`titled` splices one value. Once a script carries several, hand-counted byte
positions stop being viable: every offset depends on the widths before it, and
an offset wrong by one produces a successor that hashes to nothing — a coin that
silently cannot be spent, with no error to read.

So the schema is the source of truth. It generates the offsets, the splitting
sequence in script, the reassembly order, and the JS encoder and decoder.

```js
const SCHEMA = [
  { name: 'owner',        bytes: 20, rule: 'replace'   },
  { name: 'edition',      bytes:  4, rule: 'keep'      },
  { name: 'transfers',    bytes:  4, rule: 'increment' },
  { name: 'maxTransfers', bytes:  4, rule: 'keep'      }
]
```

### Four mutation rules in one script

| rule | field | meaning |
|---|---|---|
| `replace` | owner | the spender supplies it; only the current owner may |
| `keep` | edition | immutable for the life of the coin |
| `increment` | transfers | computed by the script, `+1` exactly |
| `keep` + guard | maxTransfers | immutable, and `transfers < maxTransfers` enforced |

`maxTransfers` living in the **record** rather than in the logic is the
difference from `metered`: the limit is data, so one script serves every limit,
and anyone holding the UTXO can read it.

### The altstack ordering falls out of the traversal

Fields are pushed to the altstack as each is finished, processed last-to-first.
Because the altstack is LIFO, popping them back reassembles the record in schema
order. The ordering is a consequence of the traversal rather than something
maintained by hand — which is the point, since a hand-maintained order is
exactly what goes wrong when a field is added.

### Verifying the schema actually drives the layout

Two checks, because "derived from the schema" is a claim, not a fact:

1. Vary one field at a time and confirm the bytes that move sit inside the range
   the schema declares. All four do.
2. **Change two field widths** (edition 4→6, transfers 4→5) and re-run the
   suite. It passes with no other edits, and a 6-byte field round-trips at its
   maximum value of 281474976710655.

The second check found a real hole: `Buffer.writeUIntLE` caps at 6 bytes, so the
schema permitted widths the encoder could not produce — and it failed with a raw
`ERR_OUT_OF_RANGE` from inside Node, naming no field. The schema is now
validated at load, with a message that names the field and the limit.

**Refuses:** advancing at `maxTransfers`; leaving transfers unchanged; skipping
transfers forward; editing the edition; raising maxTransfers; rewriting the fee;
a stranger transferring; claiming an owner the payment does not match; escaping
to a plain address; skimming value; SIGHASH_NONE; a stranger cashing out; and,
after a transfer, the previous owner.

Cashing out is allowed at the limit — the guard blocks advancement, not the exit.

## htlc

A hash time-locked contract — the primitive behind atomic swaps and payment
channels. Two ways out, and only one can ever be taken:

- **claim** — the recipient reveals a preimage and signs. Available immediately.
- **refund** — the sender signs, but only after a locktime floor.

### On BSV this cannot be built the usual way

`OP_CHECKLOCKTIMEVERIFY` **does not work**. Genesis reverted it to `OP_NOP2` for
every output created after 2020, which the
[BSV wiki states directly](https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script):
the old semantics apply only to "UTXOs that pre-date genesis".

The consequences are worse than "unsupported", and were measured rather than
assumed:

```
script: ffc99a3b OP_NOP2 OP_DROP OP_1      a floor of 999999999

consensus (as verify() defaults)   SPENDS (the lock enforces nothing)
+ CHECKLOCKTIMEVERIFY              SPENDS (the lock enforces nothing)
our policy set                     refused (SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS)
```

A floor of 999,999,999 spends with `nLockTime` at **0**. Setting the
`CHECKLOCKTIMEVERIFY` flag does not help, because `isAfterGenesis()`
short-circuits it. And on mainnet the same script is refused outright:

```
deployed  9b45f720…
CLTV run  refused: 64: non-mandatory-script-verify-flag (NOPx reserved for soft-fork upgrades)
recovered 53004fc4…      (via the escape branch — the probe cost only fees)
```

So a CLTV timelock on BSV is **both unenforced and unrelayable** — it looks
correct and is neither. The wiki and the measurement agree and describe
different layers: consensus ignores the opcode, relay policy refuses it.

### What it costs

The refund branch therefore reads `nLockTime` out of an OP_PUSH_TX-authenticated
preimage, the same construction as [`timelock`](#timelock). The two branches end
up wildly lopsided:

| branch | chunks | needs a preimage |
|---|---|---|
| claim | 5 | no |
| refund | 298 | yes — the whole OP_PUSH_TX apparatus |

That is roughly 340 bytes the Bitcoin version does not pay. Keeping the preamble
*inside* the refund branch rather than hoisting it means the common path stays
cheap: a claim never carries the cost of the escape hatch.

**Refuses:** a wrong secret; the sender taking the claim path; a stranger
claiming even with the secret; the recipient taking the refund path; refunding
below the floor; refunding with a final sequence; SIGHASH_NONE on the refund
path.

**Accepts a claim regardless of the floor** — the locktime gates only the
refund, which is what makes the contract work.

## merkle

Spend by proving a leaf belongs to a committed tree. No introspection, no
signature — the coin moves for whoever can produce an inclusion proof against a
root fixed at lock time.

It is here because every other predicate reasons about the *transaction*, and a
bench covering locking scripts should also show Script reasoning about a *data
structure*. `OP_CAT` and `OP_HASH256` are all it takes. Seven bytes per level:

```
OP_ROT OP_IF OP_ELSE OP_SWAP OP_ENDIF OP_CAT OP_HASH256
```

### The direction bits are half the proof

With the stack as `[sibling, current]`, `OP_CAT` already yields
`sibling || current`. So the **empty** `OP_IF` branch is the "sibling on the
left" case, and `OP_SWAP` is needed only for the other. Written the obvious way
round, every hash is still valid and the proof lands on a *different root* —
which is the classic Merkle bug, and why one of the cases flips a single
direction bit while keeping all the siblings correct.

### Depth is fixed at lock time

Not a limitation of Merkle proofs but of Script: there are no loops, so every
level is unrolled. A script can check membership at depth *n*, never at "some
depth". That is the bounded-iteration ceiling again — the same one
`registry`'s `maxTransfers` runs into.

**Refuses:** a leaf not in the tree; the right leaf with another leaf's path; the
same siblings with one direction bit flipped; a truncated path.
