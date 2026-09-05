# Mainnet log

> Every txid below is checked, not asserted. `npm run verify:chain` fetches each
> recorded output, confirms it exists, confirms its bytes match what the ledger
> recorded, and reports whether the current code still reproduces them. A
> documented txid is otherwise just a claim.
>
> ```
> checked            116
> reproduced exactly 73
> earlier generation 37   (expected: the core was hoisted and trimmed)
> unbuildable         6   (stateful covenants params alone don't reconstruct)
> stranded            2   (script-valid, refused by policy, unspendable)
> ledger disagrees    0
> not on chain        0
> ```
>
> The 37 "earlier generation" entries are the size history, visible in the chain
> itself: registry 979 → 592 → 554 B, perpetual 423 → 385 B, timelock 409 → 372 B.
> They are not failures — anything deployed before the preamble was hoisted and
> the core trimmed is *expected* to differ. What matters is that the difference
> is known rather than discovered later by someone trusting a stale example.

Every predicate here was proven twice: against the interpreter offline, then on
BSV mainnet with real satoshis. Local verification is necessary and not
sufficient — two of the entries below only failed once they met a node.

Funding wallet: `1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS`

## redeployed to current code

Five predicates were improved *after* their first deployment: the two-branch sizing
optimisation shrank [`metered`](predicates.md#metered), [`titled`](predicates.md#titled)
and [`royalty`](predicates.md#royalty) by 425 B each and [`covenant`](predicates.md#covenant)
by 38 B, and [`asset`](predicates.md#asset) grew 141 B when its atomic-swap branch was
added. Their first coins (below) were therefore an *earlier generation* than the code — a
drift nothing checked until `npm run check:rebuild` rebuilt every deployed coin from its
receipt and found it. Each was then redeployed with the current code and spent, so the coin
on chain is byte-identical to today's predicate again; `verify:chain` reports all five
`on chain = ledger = current code`.

| predicate | deploy (current bytes) | spent | size |
|---|---|---|---|
| covenant | `1a0fcb044efa…`:0 | `ca6c16cc726f…` | 384 B |
| metered | `6b636a565924…`:0 | `c801fdc496f7…` | 488 B |
| titled | `6302f16515a5…`:0 | `8441c871eb49…` | 506 B |
| royalty | `04b15757a203…`:0 | `5b146a519ba5…` | 603 B |
| asset | `df32544994e7…`:0 | `9ed42e4ba7bc…` | 1001 B |

The earlier coins remain in the per-predicate sections below as real, spent history — the
size story is in the chain itself. Reproduced by `scripts/redeploy-drifted.js`, which
verifies every spend against the interpreter before it broadcasts.

## vesting

Value released **continuously over time**: a [`vesting`](predicates.md#vesting)
grant streamed to a beneficiary, each withdrawal taking the vested portion and
recreating the covenant holding exactly the unvested remainder.

| step | txid | retained (unvested) | to beneficiary |
|---|---|---|---|
| deploy — grant 8000 | `968583970f65…`:0 | 8000 | — |
| withdraw @25% | `4a28de298a86…`:0 | 6027 | 1673 |
| withdraw @50% | `f4ef5751b736…`:0 | 4032 | 1695 |
| finish (fully vested) | `b952c80b107d…` | 0 | 3732 |

The schedule ran 2025-01-01 → 2026-01-01, so the withdrawals' `nLockTime`
timestamps are already in the past and mine at once; the covenant computed
`unvested(T) = 8000·(end−T)/dur` at each spend and kept exactly that — `8000 →
6027 → 4032 → 0`, verified on chain, each recreated script reproducing
`buildScript`. The soundness rests on the [`timelock`](predicates.md#timelock)
rule: the withdraw reads `nLockTime` from the preimage and demands a non-final
sequence, so no one can draw future vesting early. The beneficiary received the
vested value in three tranches; the fees were the only leakage.

## journal

An append-only **hash chain**: a [`journal`](predicates.md#journal) covenant whose
`head` is a rolling commitment to its whole history, advanced one record at a time.

| step | txid | state |
|---|---|---|
| deploy — empty log | `e2abb92944db…`:0 | seq 0, head `0000…` |
| append record 1 | `8a22cc873a78…`:0 | seq 1, head `011dffc4…` |
| append record 2 | `59e3f9931ce1…`:0 | seq 2, head `7e58b20d…` |
| close — publisher sweeps | `37874f4d82bf…` | (closed) |

Each append spent the previous log and paid a new one carrying `seq+1` and
`head = HASH256(oldHead ‖ recordHash)` — verified on chain: `head₁` is exactly
`HASH256(0…0 ‖ H(record₁))` and `head₂` is `HASH256(head₁ ‖ H(record₂))`, each
recreated script reproducing `buildScript`. Only the record *hashes* went on chain,
not the records; the covenant enforced the ordering and authorship of a stream whose
contents never appeared. A skipped, repeated, or reversed sequence, or a `head` that
is not the correct chain of the last one, is refused — append-only, on chain.

## lifecycle

A **state machine** with a constitution: a [`lifecycle`](predicates.md#lifecycle)
certificate carrying an immutable core, a bounded status, and a terminal state, walked
end to end on chain.

| step | txid | status |
|---|---|---|
| deploy | `92957b4fb3cf…`:0 | ISSUED (8000 sat) |
| transition | `b31fa25ac547…`:0 | ACTIVE |
| transition | `db0c35be4eb6…`:0 | SUSPENDED |
| transition | `f3dca19febaf…`:0 | ACTIVE — reinstated |
| transition | `d9de09042f3d…`:0 | REVOKED — terminal |
| retire — issuer sweeps | `81d38124a10c…` | swept 6750 sat → funding |

Each transition spliced the untouched `genesis` and `issuer` into the successor —
the constitution held for the object's whole life. At `REVOKED`, every attempted move
(`→ ACTIVE`, `→ SUSPENDED`, `→ REVOKED`) was checked on chain and refused: no allowed
pair begins with the terminal state, and the two-byte move cannot lie about where it
starts, so the leaving transaction cannot be built to verify. `retire` then built the
issuer's P2PKH at runtime from the object's own state and swept the remainder to it —
confirmed paying `1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS`.

## delegation

Authority conserved like a token: a [`delegation`](predicates.md#delegation) capability
carrying a budget, split into a tree whose budgets can never exceed the root's — proven
across a two-level tree on chain.

| step | txid | budget | sats |
|---|---|---|---|
| deploy — root | `1be06b63236a…`:0 | 100 | 8000 |
| delegate 40 — self ‖ child | `324f77a88190…`:0 / :1 | 60 ‖ 40 | 6450 / 1200 |
| exercise 15 on the child | `ea482449d467…`:0 | 25 | 850 |
| revoke — child leaf | `18efa3b7411e…` | — | 500 → funding |
| revoke — parent | `744c9baf00ca…` | — | 6100 → funding |

The `delegate` produced two covenant outputs in one transaction — the parent recreated
with budget 60 and a new child with budget 40 — the covenant computing the parent's
remainder itself, so `60 + 40 = 100` held on chain and no output could inflate it. The
child was then a delegation covenant in its own right: `exercise` spent 15 of its 40
down to 25, and `revoke` swept each leaf's remainder to the owner's P2PKH — built at
runtime from the PKH in the node's own state, confirmed paying
`1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS`. Every node carried the same `root` spliced from
its own bytes, an unbroken line of descent through a branching tree.

## witness

One contract's release gated on another's on-chain state: a [`witness`](predicates.md#witness)
paid out only because a specific tagged coin was co-spent carrying the required flag.

| step | txid | what |
|---|---|---|
| mint the tagged coin (flag 1) | `e050176cc151…`:0 | `<flag,4> OP_DROP <P2PKH>`, 2500 sat |
| deploy the witness watching it | `1754a80d1091…`:0 | releases iff that coin shows flag 1, 5000 sat |
| co-spend both → release | `3f6a1c8b99e3…` | 2 inputs, 7000 sat → beneficiary |

The release transaction spent **two** inputs — the witness (input 0) and the tagged coin
(input 1) — and paid the beneficiary. The witness verified, on chain, that its input set
contained the coin's baked outpoint (`hashPrevouts`), that the source transaction the spend
presented hashed to that outpoint's txid (the backtrace), and that the coin's output-0 flag
was 1 — then checked the beneficiary's signature. Change any of it — a different coin, a
forged source, a wrong flag, another signer — and the reconstruction misses its target and
the spend dies. A cross-object condition, executed on mainnet.

## conserve

The capstone: a conserved, uncounterfeitable two-body pair, walked from genesis through a
rebalance on chain.

| step | txid | side 0 | side 1 |
|---|---|---|---|
| genesis — mint the pair | `54c95002ebe5…`:0 / :1 | 60 | 40 |
| rebalance — spend both, recreate both | `83fc9d515f3d…`:0 / :1 | 25 | 75 |

The rebalance transaction spent **three** inputs — side 0, side 1, and a fee input — and
produced side 0′ and side 1′ with the quantity moved between them: `60 + 40 → 25 + 75`, the sum
**held at 100 on chain**, the new balances readable straight from the coins’ bytes. Each coin’s
unlock backtraced the shared genesis transaction: proving it was their real parent, reading both
balances from its two outputs, pinning the partner as a co-input, and proving descent from the
genesis outpoint `G`. A rebalance that broke the sum, a counterfeit pair, a wrong signer, or a
partner left un-spent would each fail one of those checks. The pair’s earlier genesis `63c88505…`
is a **stranding**: it carried a `.change()` output the coins’ covenant did not expect, so its
4000 satoshis sit behind coins no transaction can spend —
[pitfall 26](pitfalls.md#26-a-fixed-output-count-backtrace-strands-a-coin-whose-parent-has-change),
kept on chain beside the success.

## guarded

Two cross-object relationships in one covenant — `conserve ∧ witness` — the composition the
constraint-graph compiler specified, run on chain.

| step | txid | detail |
|---|---|---|
| oracle coin (flag 1) | `32d852535d3c…`:0 | a tagged coin the pair is gated on |
| genesis pair | `3925d43893ae…`:0 / :1 | side 0 = 60, side 1 = 40, baking the oracle |
| guarded rebalance | `f9531b4815c1…` | 4 inputs → side 0 = 25, side 1 = 75 |

The rebalance spent **four** inputs — side 0, side 1, the oracle coin (input 2), and a fee — and
produced `(25, 75)`: the sum held at 100 (the `conserve` half) **and** the move happened only
because the specific oracle coin was co-spent carrying flag 1 (the `witness` half). Every conserve
check still bit — conservation, descent, ownership, the co-spent partner — with the oracle gate
added on top. Change the oracle coin, omit it, or give it the wrong flag, and the pair cannot move.
The composition the graph named as a frontier is now a coin on chain, byte-identical to the one the
graph emits.

## pool

`conserve` for N bodies: a distributed conserved state system, walked as an N=3 treasury on chain.

| step | txid | buckets (Σ = 100) |
|---|---|---|
| genesis — mint three buckets | `31e8e3802840…`:0/:1/:2 | 50, 30, 20 |
| rebalance — spend all three | `a09cc353f112…` | 40, 40, 20 |

The rebalance spent **four** inputs — the three buckets and a fee — and recreated the three buckets
with quantity moved between them: `50+30+20 → 40+40+20`, the total **held at 100 on chain**, each
bucket’s balance readable from its bytes. Every member backtraced the single genesis transaction that
created all three (reading all three balances at once), confirmed the whole group was co-spent in
index order, checked the sum, and proved descent — the two-body `conserve` generalised to N, one
covenant per member.

## audited

The first cross-class composition — `conserve` (relational) ∧ `journal` (temporal): a conserved pair
whose every rebalance is appended to an embedded audit chain. A balanced *and* auditable treasury.

| step | txid | balances / audit |
|---|---|---|
| genesis — mint the pair | `5befa96b9f1e…`:0/:1 | 60, 40 · seq 0 · head 0…0 |
| rebalance — conserve + log | `f658252584f4…` | 45, 55 · seq 1 · head 7c08e709… |

The rebalance conserved the sum (`60+40 → 45+55 = 100`) **and** advanced each coin's audit chain:
seq `0 → 1`, head `→ HASH256(0…0 ‖ recordHash)` — verified on chain, both coins sharing the one
record so they log the same event and stay in lockstep. Only the record's hash entered the chain; the
entry stayed off-chain. Every `conserve` check still bit, and on top a successor that failed to
advance the seq, or whose head was not the correct chain of the last, is refused — the treasury
cannot move without recording the move.

## ledger

`pool ∧ journal` — the N-body form of `audited`: a conserved AND auditable treasury, walked as an
N=3 group on chain. The composition the safety checker predicted safe, then built and deployed.

| step | txid | buckets (Σ 100) / audit |
|---|---|---|
| genesis — mint three buckets | `04ac5de34968…`:0/:1/:2 | 50, 30, 20 · seq 0 · head 0…0 |
| rebalance — conserve + log | `f49f8980d507…` | 40, 40, 20 · seq 1 · head 8fa5d888… |

The four-input rebalance (three buckets + a fee) preserved the total (`50+30+20 → 40+40+20 = 100`)
**and** advanced every bucket's audit chain to seq 1 with a shared `head = HASH256(0…0 ‖ recordHash)`
— all verified on chain. Every `pool` check still bit (conservation, descent, whole group co-spent,
per-member owner) and, on top, a member that failed to advance its seq or chained a wrong head is
refused. This is the correct-by-construction loop closed on chain: `conserve ∧ journal` was judged
safe by the composition checker *before* the predicate existed, and the deployed bytes are exactly
what the graph emits for `conservedGroup ∧ journal`.

## turns

A two-player turn-based game, played end to end on chain: Bitcoin as the referee.

| step | txid | turn / state |
|---|---|---|
| deploy — the pot | `665d81bfbe83…`:0 | turn 0 (a to move), pot 4000 |
| move — player a | `73aa516b5c9f…`:0 | → turn 1, state s1 |
| move — player b | `8bd290403c3c…`:0 | → turn 0, state s2 |
| settle — both sign | `a553e7258a21…` | pot → winner (3100 sat) |

Player a moved on turn 0 and the coin recreated itself at turn 1; player b moved on turn 1 and it
flipped back — each move signed by the player whose turn it actually was, the turn alternating on
chain. A move by the wrong player, or one that failed to flip the turn, would have been refused. The
game ended only when **both** players signed the settle, paying the pot to the agreed winner. Every
transition was verified under relay policy before broadcast.

## ticker

Oracle-driven **state**: a [`ticker`](predicates.md#ticker) covenant recreated
itself on each spend, carrying an oracle-signed value forward in its own scriptCode
and advancing only on a strictly-higher round — the full lifecycle on chain.

| step | txid | recreated state |
|---|---|---|
| deploy | `e786ec40330f88…`:0 | round 0, price 6000 |
| update | `cc0cecd4d01366…`:0 | round 1, price 6300 |
| update | `c13b35678c8e8b…`:0 | round 2, price 6100 |
| redeem — funder sweeps | `3f60143ae0788b…` | (terminated) |

Each update spent the previous ticker and paid a new one carrying the next round —
`e786… ← cc0c… ← c13b… ← 3f60…`, verified on chain. The embedded `round‖price`
advanced inside the recreated script's own bytes, and every recreated script
reproduces `buildScript` exactly. A replay of the same round, or a rollback to a
lower one, is refused by the script reading its own current round out of scriptCode
and demanding the new one exceed it — the anti-replay guard that state plus a
public, reusable attestation makes mandatory. The redeem is the exit a
fee-draining self-recreating covenant must have.

## quorum

Split trust: a [`quorum`](predicates.md#quorum) covenant required **two of three**
independent oracles to attest the same value before the winner could claim — two
separate Rabin verifications, summed and thresholded inside the locking script.

| step | txid |
|---|---|
| deploy → 2-of-3 quorum (panel of 3 Rabin keys, feed BSVUSD) | `37e209f28b3f71…`:0 |
| claim — oracles 0 and 1 attest 6543, winner signs | `fa345a32d83d2b…`:0 |

The claim's unlocking script carried genuine attestations from panel members 0 and
1 (a dummy in slot 2), and the node accepted it — so summing two `s² mod N == H mod N`
checks and comparing the tally to `m` is consensus- and policy-valid. No single
oracle can move these coins, and replaying one oracle into two slots is refused
(slot 2 hard-codes a different modulus). The current bytes on chain reproduce
`buildScript` exactly.

## settlement

The oracle value as a *dial*, not a gate: a [`settlement`](predicates.md#settlement)
covenant read its own input value, verified an oracle attestation, and split the
pot between two parties by a formula computed inside the locking script — no
spender signature, the payout forced by `hashOutputs`.

| step | txid |
|---|---|
| deploy → settlement pot (LOW 4000, HIGH 8000, feed BSVUSD) | `40bbc122a0365e…`:0 |
| settle — oracle attests 6000 → 50/50 | `ecf1316aff21ab…`:0 and :1 |

With `v = 6000` halfway between the bounds, the covenant computed `pot·(6000−4000)/4000`
and paid **two 350-satoshi outputs** (pot = 1000 − 300 fee = 700, split 350/350),
each bound by `hashOutputs`. Change the attested value and the split moves; change
the payout without changing the value and the spend is refused. The current bytes
on chain reproduce `buildScript` exactly.

## oracle

The first spend the bench has ever gated on an *external* fact: a binary option
claimed by verifying an oracle's [Rabin signature](predicates.md#oracle) inside the
locking script — `s² mod N == H(FEED ‖ value) mod N`, computed with `OP_MUL`,
`OP_MOD` and four `OP_SHA256` blocks, no `OP_CHECKSIG` involved.

| step | txid |
|---|---|
| deploy → oracle option (feed BSVUSD, threshold 6000) | `5a108163539913…`:0 |
| claim — winner signs, oracle attests 6543 ≥ 6000 | `e6541307f6ac2a…`:0 |

(A first deploy+claim, `b984a079ca295e…` / `203dd3583fffec…`, proved the same
mechanism at 631 B; it was superseded by the 634 B version once a code review
found the attested value was read as a signed int32 — a 0x00 pad now reads it
unsigned, so a uint32 above 2³¹ can claim — leaving the current bytes on chain a
byte-for-byte match for `buildScript`.)

The claim's unlocking script carried a genuine Rabin signature over `BSVUSD ‖ 6543`
produced by the demo oracle key, plus the winner's ECDSA signature over the spend.
The node accepted it — so the whole modular-arithmetic verification, a 128-byte
`OP_MUL` and a `mod` by a 65-byte modulus, is valid under both consensus and relay
policy, not merely against the offline interpreter. This is the on-chain proof
that BSV can verify signed off-chain data with no special opcode. The refund branch
(funder reclaims after a deadline, timelock enforced the proper way) is proven in
the suite; only the claim path was taken on chain.

## All three at once, divisible: mint, split, merge

The capstone, on chain, and now genuinely divisible. A [`sovereign`](predicates.md#sovereign)
carries `genesis ‖ owner ‖ balance` and runs conservation, ownership and
authenticity in one covenant — over the full lifecycle.

| step | txid |
|---|---|
| genesis `G` | `5fec93b1a5424b…`:0 |
| mint → sovereign(O0, 500) | `f98c0b53d16b9e…`:0 |
| split → sovereign(O1, 300) + sovereign(O2, 200) | `1e52ea03c81d23…`:0 and :1 |
| merge → sovereign(O1, 500) | `1dfc49a1d9d727…`:0 |

The split divided 500 into 300 and 200 to two owners (owner O0 signing,
conservation `300+200==500`, descent from the mint proven); the merge summed them
back to 500, with **both** O1 and O2 signing, each input proving its own descent
and — through the sibling backtrace — that the other was a sovereign of the same
genesis. Every output is byte-identical to `buildScript`. The balance is conserved
across the entire cycle, on chain.

The merge is what the earlier single-output version could not reach: two
same-genesis tokens only arise from a split, and a split-produced token has a
two-output parent, so descent had to become multi-output — [token](predicates.md#token)'s
backtrace, plus an `OP_IF`/`OP_ELSE` the [stack assembler learned to model](authoring.md).
A counterfeit — sovereign bytes minted from a plain UTXO — remains unspendable in
every branch.

## All three at once: a sovereign transfer

The capstone composition on chain — [`sovereign`](predicates.md#sovereign) carries
`genesis ‖ owner ‖ balance` and runs conservation, ownership and authenticity in one
covenant. The reachable transfer path:

| step | txid |
|---|---|
| genesis outpoint `G` | `f41d299b71ecab…`:0 |
| mint — spend `G`, create sovereign(owner O0, balance 500) | `3fbc1a2732934…`:0 |
| transfer, O0 signs → sovereign(owner O1, balance 500) | `aa47dc25f353ab…`:0 |

The transfer output is `buildScript(genesis, O1, 500)` byte-for-byte — the balance
carried, the owner changed, and the spend both proved O0's signature and proved
descent from the genesis mint. The three mechanisms compose in one 944-byte script.

The `merge` branch is proven in the suite but not shown live here: two same-genesis
tokens only arise from a `split`, and split is the multi-output-descent frontier —
see [predicates.md](predicates.md#sovereign) for the reachability finding. The
transfer path is what a single-output sovereign can reach, and it is on chain.

## An owned, authentic token: transferred down a chain, owner rotating

The composition of authenticity and ownership on chain — [`provenance`](predicates.md#provenance):
a token proving descent from its genesis *and* gated by the current owner's
signature, transferred three hops with the owner changing at each.

| step | txid | owner after |
|---|---|---|
| genesis outpoint `G` | `c3eeee0ee27ea9…`:0 | — |
| mint — spend `G`, create token0 | `8ab45100e9a9f1…`:0 | O0 (`1C6Rc3w2…`) |
| transfer, O0 signs → token1 | `d7ed185e1a6045…`:0 | O1 (`1NVYv5jm…`) |
| transfer, O1 signs → token2 | `166b4bc3e987c5…`:0 | O2 (`16yH2E12…`) |

Each output is `buildScript(genesis, owner)` with the owner a *different* address
at every hop, and each spend did two things at once: verified the current owner's
signature (`titled`'s pattern) and re-proved the immediate parent was a
`provenance` token of the same genesis (`lineage`'s backtrace), with the parent's
own — different — owner supplied by the spender and pinned by the descent hash.
Neither mechanism changed to compose with the other, exactly as
[`asset`](predicates.md#asset) composed conservation with ownership. Authenticity,
ownership, and (in `asset`) conservation are now each demonstrated on chain, and
composed pairwise.

## Authenticity: an unbroken chain to genesis, and a counterfeit that cannot spend

The hardest result in the bench, on chain: a [`lineage`](predicates.md#lineage)
token proving descent from a unique genesis on every spend, without a SNARK.

| step | txid |
|---|---|
| genesis outpoint `G` (the mint spends this) | `37c136867d1cd4…`:0 |
| mint — spend `G`, create token0 | `eb04c82fb99b95…`:0 |
| spend token0 (genesis case) → token1 | `4b169c83b79628…`:0 |
| spend token1 (parent case) → token2 | `8c9a79c0ec7f52…`:0 |
| counterfeit — lineage bytes from a plain UTXO | `a626ad0dd1c894…`:0 |

Every token output is byte-identical to `buildScript(genesis)`, and the inputs
form the chain: token2 ← token1 ← mint ← `G`. The mint's input 0 is the genesis
outpoint, so its spend passes the **genesis** branch; token1's spend passes the
**parent** branch by rebuilding the mint's single-output funding tx and hashing
it to the mint's txid; token2 does the same one hop deeper. Each spend re-proves
only its immediate parent — the network already validated the rest, once, at each
prior spend.

The counterfeit is the point. `a626ad0d…` is a genuine on-chain output whose bytes
are `lineage` with the real genesis `G` — minted by spending a plain UTXO. It
exists. It simply **cannot be spent**: its funding tx did not spend `G`, and its
parent output is a plain script, not `lineage+G`, so both branches of the descent
check fail. Verified under the node's own relay policy (`SCRIPT_ERR_VERIFY` on the
`OP_BOOLOR` of the two branches). An unspendable coin never enters circulation, so
the counterfeit can never be transferred or counted — which is exactly what
authenticity requires.

## The foundational predicates, on chain

The five that had lived only in the suite are now deployed and spent, so every
predicate in the bench has a mainnet round-trip. Each was broadcast twice — a
deploy that locks 1000 sat behind the predicate, and a spend that satisfies it.

| predicate | deploy | spend | what the spend proves |
|---|---|---|---|
| `p2pkh` | `bddc9c8ce466b9…` | `a5785d60…` | a real key over a real FORKID sighash |
| `multisig` | `bf22105b1805be…` | `9aff4c94…` | 2-of-3, signatures in key order, empty dummy |
| `merkle` | `7003fa047a1d2f…` | `ffb8cd2e…` | leaf 5 of a 16-leaf tree with its sibling path |
| `composed` | `83b9c1b52664cf…` | `587a36c4…` | outputs AND locktime AND non-final, on one preimage |
| `htlc` | `a44620335652ad…` | `bf261c28…` | the claim branch: reveal the secret, recipient signs |

Two details worth the broadcast. `composed` is a covenant that also has to be
*final* to relay, so it was deployed with its locktime floor set to a past height
and spent at exactly that height — non-final sequence, but a locktime the tip had
already passed. And `htlc`'s claim reveals the preimage of its hash on chain, in
the clear, exactly as the design intends: the secret is public the instant the
funds move, which is what makes a hash lock usable for an atomic swap.

## hashlock

| | txid | |
|---|---|---|
| deploy | `c3dd681e590da977b3737aeaf6a0bb8d17e28def8c0ccea78b2d8df0867c08cb` | 1000 sat locked |
| spend | `a3dbe6e991ac5d100da92787270c4980a4c21540c4a83791d334215d4c082827` | preimage revealed |

## timelock

| | txid | |
|---|---|---|
| deploy (v1) | `865288a8d4a9a7498bd7b8b732c37a3d3360f9ea45ed2721095874408f7a80a5` | **stranded** |
| deploy (v2) | `6bb7c6b8e325b9ab179b57ee8dc82b3bbb90125345ca4133942a91fe81df772f` | |
| spend (v2) | `7b87ffe3cff70458c68f6fc7e787a9ca272786b8e2f050a83390b419c3f2f286` | locktime 964280, seq `0xfffffffe` |

v1 verified locally and was refused by the network for a non-minimally encoded
script number. Its locking script is immutable, so no spend can avoid producing
that same number: 1000 satoshis unreachable through normal relay until 2038.
See [pitfall 1](pitfalls.md#1-consensus-valid-is-not-relayable).

The v2 spend carries `nLockTime 964280` — ground 280 upward from the 964000
floor by the OP_PUSH_TX nonce search — and the non-final sequence the script
demands.

## timelock, proven end to end

The earlier timelock entries used a floor already in the past, which proved the
script logic and never the consensus timing. This one used a floor **two blocks
in the future**.

| | txid | |
|---|---|---|
| deploy | `fbed3bee81acbbb446a18fd466601c8a1049740cec8f9e8a1170a9dbb242151b` | 1000 sat, floor = height 965010 |
| spend | `bd427165cb0cd8c48d29466b8821e544b4412a2a1a4b6025e2ad0063cb5fd873` | accepted at tip 965008, held, released at 965010 |

```
15:23:59  tip 965008  floor 965010  2 block(s) to go  |  conf 0  coins back: false
15:26:01  tip 965009  floor 965010  1 block(s) to go  |  conf 0  coins back: false
15:28:06  tip 965010  floor 965010  FLOOR REACHED     |  conf 0  coins back: true
```

The spend was **accepted** at tip 965008 and held unmined in BSV's non-final
pool, entering the normal mempool the moment the chain reached the floor. Both
halves of the mechanism are now demonstrated rather than assumed: the script
enforces `nLockTime >= floor`, and consensus enforces that a transaction with a
future `nLockTime` cannot be mined.

The spend carries:

```
nLockTime : 965010      exactly the floor
sequence  : 0xffffffee  non-final, and the field that carried the grind
```

Note `conf 0` at the moment of release. `confirmations` stays undefined until a
block is found, so it is **not** a release signal — only the second, independent
check (had the coins become spendable?) caught the transition. A watcher relying
on confirmations alone would have missed it by however long the next block took.

See [pitfall 4](pitfalls.md#4-bsv-holds-non-final-transactions-it-does-not-reject-them)
and [pitfall 5](pitfalls.md#5-grinding-nlocktime-destroys-the-lock-you-asked-for).

## covenant

| | txid | |
|---|---|---|
| deploy | `1c95b40ca248093be8c692b3a4c7cc1a095e8d02912e591f01cc3917a1b1c1c7` | commits to 900 sat |
| spend | `c82922df2d320bf06d2e37b2067ce6de2a84beb84d353c2470a78ea67bebe1eb` | 900 sat, as committed |

Re-tested adversarially against its own deployed 422 bytes:

```
pay 900 to the committed address : SPENDS
pay 900 to a stranger            : refused (SCRIPT_ERR_EQUALVERIFY)
pay 899 to the committed address : refused (SCRIPT_ERR_EQUALVERIFY)
pay 950 to the committed address : refused (SCRIPT_ERR_EQUALVERIFY)
```

## perpetual

Four linked UTXOs, identical 423-byte script, 150 sat per hop:

| hop | txid | value |
|---|---|---|
| 0 | `a2b79eac8f8f986996ee0c2a0a990461580d53c5e8e76f0db62cdd3c8888c4a0` | 1000 sat |
| 1 | `eb3646c6adf0d50bcae11430531f07f148b3dec719bb87f3596811dbe927626e` | 850 sat |
| 2 | `f24fbc9652e7d306541257d9580be87c4612460c77ceb752a1ae6b9b06f9cb1f` | 700 sat |
| 3 | `a7c20ed9951b6b54190e453a59bb111336d7996d7281ffb632d27e6d027d75a3` | 550 sat |

Each output's script is byte-identical to its parent's and each spends the
previous. The hop-3 UTXO is still live and has no exit branch — anyone may push
it forward, nobody may redirect it, and it dies when 150 stops covering the fee.

Adversarial run against the live UTXO:

```
recreate itself at 400 (550-150) : SPENDS
steal all 550 to an address      : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
recreate, but skim 50 extra      : refused
recreate, underpaying the fee    : refused
recreate 400 + pocket 100 change : refused
```

## metered

Full lifecycle, `maxHops=2`, `hopFee=250`, settling back to the funding wallet.
The counter is readable in the script bytes of each output:

| stage | txid | value | script |
|---|---|---|---|
| deploy | `61aea3a1d0b4f3df51a7f7a15d7d98d9a01fbe0c763c51ff57eb950f7c9ce33d` | 1200 sat | covenant, counter=0 |
| hop 1 | `ed8bf1834c08224de52c72462149c5284bf3c66499a156e82220fb89ef9b3d07` | 950 sat | covenant, counter=1 |
| hop 2 | `bde5fbeae69eb87a0731ef6f5e281637a6d0e32c1b669442858a3797a318e8fe` | 700 sat | covenant, counter=2 |
| redeem | `7f8ec168d9e05df24c836c79577f9a01326c0842dd67b08666ea9c81e72cfcbc` | 450 sat | P2PKH |

Nothing stranded. Against the live counter=2 UTXO:

```
hop branch at maxHops     : refused (SCRIPT_ERR_VERIFY)
redeem branch at maxHops  : SPENDS
redeem to a stranger      : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
redeem keeping 50 extra   : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
```

The hop-1 transaction broadcast successfully and was then lost from the local
ledger by a ReferenceError in the bookkeeping that ran *after* the broadcast.
Recovery meant refetching the raw transaction and rebuilding the predicted
successor script to identify the output. See
[pitfall 15](pitfalls.md#15-decide-what-you-will-record-before-the-irreversible-step).

## titled

Deploy, transfer, cash out. The owner is readable directly from each output's
script bytes at offset 1.

| stage | txid | value | script | owner |
|---|---|---|---|---|
| deploy | `697ad63cc84965e0cb4a3b663593a29c57cf2f4e65db1903003b8ec946dfa8c5` | 1500 sat | title, 931 B | alice |
| transfer | `03b20d41b471eecaf1d8d7994228bc8a5a5acafc3a9b731377dca5fc98413eb2` | 1200 sat | title, 931 B | bob |
| redeem | `7106e028cce6d23860e9568213ed7cb825871bd3b55ea07edbc4f712cc595516` | 900 sat | P2PKH | bob |

Against the live title after the transfer:

```
bob (current owner) transfers on   : SPENDS
bob redeems to his own key         : SPENDS
alice (previous owner) transfers   : refused (SCRIPT_ERR_EQUALVERIFY)
alice redeems to bob               : refused (SCRIPT_ERR_EQUALVERIFY)
mallory transfers to herself       : refused (SCRIPT_ERR_EQUALVERIFY)
```

Alice deployed the title and holds the funding wallet. After the transfer she
cannot move it. That is the whole point.

## royalty

Three hand-offs, each paying the creator, then an exit that pays as well.
`royaltyBps=250` (2.5%), `transferFee=400`.

| stage | txid | output 0 | output 1 |
|---|---|---|---|
| mint | `595fd52ea48616a969052a684d34587259a8a369ae37e8ee79dda592777154e0` | 8000 sat title → alice | change |
| alice → bob | `2546bc7b3fba40421f9f8e1feb413037b0e7bff276b6a6db67a83b6657fa8bd8` | 7400 sat title → bob | **200 sat → creator** |
| bob → carol | `b64e78f79ed17c9454c0a19b1cf89484f2c954ea14c0044a42ac17e737b3d998` | 6815 sat title → carol | **185 sat → creator** |
| carol exits | `a5d1bdfdafe74d8fa3fcdd36e8aaf55eedd7239a7bbe24903e40849b4733d904` | 6245 sat P2PKH → carol | **170 sat → creator** |

The creator address `18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if` holds exactly three
UTXOs — 200 + 185 + 170 = 555 sat. It never signed anything, never appeared as
an input, and was never asked. The royalty is collected by the script.

Adversarially, against the real 1028 bytes of the `bob → carol` output:

```
carol transfers, creator paid 170     : SPENDS
...same two outputs, ORDER SWAPPED    : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
...royalty output removed entirely    : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
...royalty short by one satoshi       : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
...royalty paid to mallory instead    : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
mallory transfers to herself          : refused (SCRIPT_ERR_EQUALVERIFY)
carol cashes out, creator paid        : SPENDS
...cashes out without paying          : refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
```

The second line is the one that matters: identical outputs, identical amounts,
identical destinations — only the order differs, and nothing spends.

### An accounting trap worth knowing

Counting the creator's income by scanning for its hash160 anywhere in an output
script gives the wrong answer, because the **title itself embeds that hash as a
constant**. A payment is an output whose *entire* script is the creator's
P2PKH, not one that merely contains the hash. The wrong method reported 22770
sat against an actual 555.

## registry

Two records, the second sized to reach its transfer limit on chain.

| stage | txid | value | record |
|---|---|---|---|
| mint | `0770c4ad54d25a13e4a30ee24e92aaf46c06c60686615259e19f13c47a4203c5` | 1000 sat | edition 1, transfers 0/2 |
| transfer | `81bea0bbeeda7bb04b965de86cfe352c0d4cc0ec20ccee55ca264af7f7551779` | 600 sat | owner→bob, transfers 1/2 |
| redeem | `87f5b5648905bb438e71576a34be4cbf13e3fe4d3793513896fd02a24df246ad` | 200 sat | P2PKH |
| mint | `1b59d7250ffdd6a528a2f638ab0d79ff2954f2ee97f78ccc259e383ccf950f9c` | 1000 sat | edition 2, transfers 0/1 |
| transfer | `7b6fc450cc579801619d9d3514cc92d5b5fc7adaee97a611eec2ec68e40b2f11` | 600 sat | owner→bob, **transfers 1/1** |
| redeem | `95181a0c34271fcac9b11af64c824b7092a093c727d288a16fdddcf31792b184` | 200 sat | P2PKH |

The record decodes straight from the on-chain script bytes — no index, no side
channel:

```
{"owner":"14HhuxiMHcMDPLKTstBmfYFd8wk9aeXkSz","edition":2,"transfers":1,"maxTransfers":1}
```

Against that live at-limit UTXO's real 979 bytes:

```
bob transfers on (transfers == maxTransfers)  : refused (SCRIPT_ERR_VERIFY)
...even raising maxTransfers in the successor : refused (SCRIPT_ERR_VERIFY)
...even editing the edition                   : refused (SCRIPT_ERR_VERIFY)
bob cashes out                                : SPENDS
mallory cashes out                            : refused (SCRIPT_ERR_EQUALVERIFY)
```

Rewriting `maxTransfers` in the successor does not help, because the guard reads
the value in the script being spent — the limit is checked before the record is
ever rebuilt.

## perpetual, rebuilt

The original `perpetual` used the library's PELS core. Rebuilt on the shared
primitives and the lean OP_PUSH_TX core, it is **385 B** instead of 423 B.

| hop | txid | value |
|---|---|---|
| 0 | `dea3bdb00a06dc798503371844fbdd7396958001a9c4cbbe1063a6fbeda4b69d` | 2000 sat |
| 1 | `84cc3bfe26097786d2c83585c978962ecb9d6c2c6472a5a408ac06cb6adebee4` | 1800 sat |
| 2 | `2c516afe3a016883dcc5cfaae1d0054f2a2ba3b99d4083a6f799c3eb3d033b8c` | 1600 sat |

The hop-2 UTXO is live and, having no exit branch, may be pushed forward by
anyone and redirected by nobody.

### The 2000 satoshis this cost

The first attempt at the rebuild is stranded at
`7102453e9751b88a0cae6d5d68535ad2cd20380ad0723267fe40c8d5a84818e1`.

`clauses.authenticate()` already performs the `OP_DUP` on the preimage, and the
rebuild added a second one. That leaves a stray 545-byte preimage under the
result — two stack items where standardness wants one. It passed every local
check, because `SCRIPT_VERIFY_CLEANSTACK` is policy and not consensus, and the
node refused it:

```
non-mandatory-script-verify-flag (Script did not clean its stack)
```

The extra copy is created by the **locking** script, so no unlocking script can
remove it. Those coins cannot be spent through normal relay.

See [pitfall 2](pitfalls.md#2-consensus-hides-more-than-minimaldata--cleanstack-too).
The fix was not just the missing brace-level bug but the gap that hid it: one
definition of what a node will relay, used by the harness, the tracer and the
broadcast path alike.

## An owned token: a two-party merge, both owners signing

The composition of ownership and conservation, on chain: [`asset`](predicates.md#asset)
carries `owner ‖ balance` and gates every operation behind the owner's signature.
The demonstration is a merge that needs *two* signatures.

| step | txid |
|---|---|
| mint asset(owner A, 300) | `d63657151a767d…`:0, 860 B |
| mint asset(owner B, 200) | `ccb8cae54a7ca5…`:0, 860 B |
| merge → asset(owner A, 500) | `d6eb521ef1b8db…`:0 |

Input 0 is A's asset, unlocked with **A's** signature; input 1 is B's asset,
unlocked with **B's**. Each input's covenant checks its own owner independently —
so the merge is valid only because both signed — and the balances are summed by the
same backtrace the un-owned `token` uses, now with the owner spliced into the
sibling's chunk alongside the balance. The merged output is
`buildScript(owner A, 500)`, byte-for-byte.

Nothing in either primitive changed to compose them: the authorisation is
`titled`'s `HASH160(pubkey) == owner` then `OP_CHECKSIGVERIFY`, and the
conservation is `token`'s backtrace. That two independent owners each signing their
own input yields a two-party handshake, with no cross-input signature logic, is the
property worth having proven on chain.

## The full token cycle: mint, split, merge back

The asymmetry closed. A split produces a two-output funding transaction, which the
first merge backtrace could not read; the two-output backtrace can, so a
split-produced token is now mergeable. The round-trip, on chain:

| step | txid |
|---|---|
| mint token (500) | `37fd5390c5fcf7…`:0 |
| split → (300, 200) | `41c5c09f43c689…`:0 and :1 |
| merge the two halves → (500) | `6330fd6478113b…`:0 |

The merge spends **both halves of the same split** — `41c5c09f…:0` and
`41c5c09f…:1` — and produces one output byte-identical to `buildScript(500)`.
Each input backtraces the *same* two-output split funding transaction at a
different `vout`: input 0 (300) reads its sibling at vout 1, input 1 (200) reads
its sibling at vout 0. The sibling's output is extracted at `vout × stride`, so
the one covenant handles a one- or two-output funding without branching.

At 7565 bytes it is the largest transaction here — each input carries the whole
split funding tx (which itself embeds two 692-byte token scripts) as backtrace
witness. That size is the honest cost of an on-chain backtrace, and the reason the
literature reaches for a SNARK once the ancestry runs deeper than a hop.

Adding the two-output backtrace changed the template again (634 → 692 B), so the
merge- and split-era tokens from the previous entries now read as **earlier
generation** in `verify:chain`. The v3 tokens above are the current covenant.

## A token split, conserving balance the other way

The inverse of the merge: one token divided into two, on chain.

| step | txid |
|---|---|
| mint token (balance 500) | `685bda97a16d77…`:0, 634 B, 2000 sat |
| split → two tokens (300, 200) | `99d3010fa856b1…`:0 and :1 |

The split spends the 500-token and produces exactly two outputs, byte-identical
to `buildScript(300)` and `buildScript(200)` — conserved exactly, `300 + 200 = 500`.
It needs no backtrace: with one input there is no sibling to prove, so the
covenant reads its own balance and requires its two outputs to sum to it.

A split creates two dust outputs from one, so it draws the extra 2000 sat (and
the fee) from a second, ordinary funding input; the covenant pins its two token
outputs through `hashOutputs`, which forbids a third (no change), so the funding
must be exact.

### v1 and v2 on the same chain

Adding the split branch changed the token template, so the three merge-era tokens
(`d4d92d88…`, `ceb4b8bd…`, `5acba0f3…`, all 526 B) now read as **earlier
generation** in `verify:chain` — the two-branch covenant builds 634 B. That is the
generation gap the verifier is built to name rather than fail on. The v1 merge
output (balance 500) is a single-branch token with no counterpart left to merge
with; it stands as a museum piece of the merge-only design. The v2 tokens above
are the current two-branch covenant.

## A token merge that conserves balance, verified by backtrace

The first backtrace-verified merge on chain, and the first transaction here where
BOTH inputs run the same covenant and each authenticates the other. It is the
construction [cross-input.md](cross-input.md) specified and
[predicates.md](predicates.md#token) implements.

| step | txid |
|---|---|
| fund token A (balance 300) | `d4d92d88fdfd33…`:0, 526 B, 2000 sat |
| fund token B (balance 200) | `ceb4b8bd39939d…`:0, 526 B, 2000 sat |
| merge → one token (balance 500) | `5acba0f3b2211d…` |

The merge spends both tokens and produces a single output whose script is
byte-identical to `buildScript(500)` — balance 300 + 200, conserved exactly. Each
input's covenant rebuilt the OTHER token's funding transaction with the claimed
sibling balance spliced in and required it to hash to that sibling's real txid;
neither could have lied about the other's balance without the hash missing.

Two details a local interpreter cannot exercise, both confirmed by relay:

- **Both inputs are introspective covenants at once.** input 0 backtraces input 1
  and input 1 backtraces input 0, in the same transaction. That it relayed is the
  proof a two-sided backtrace is standard.
- **A joint nLockTime grind.** Both inputs synthesise an OP_PUSH_TX signature, and
  the sighash's nLockTime is shared, so a single value had to make BOTH preimages
  low-S. It landed at nLockTime 189.

The tokens must be single-output funding transactions carrying exactly the fixed
2000-sat dust, which is what makes the backtrace's pinned reconstruction sound —
see [predicates.md](predicates.md#token). What this proves is conservation, not
authenticity; the residual gap is spelled out in [cross-input.md](cross-input.md).

## A covenant that reads its sibling inputs

The first multi-input covenant here to reach mainnet. A `companion` output can
only be spent in a transaction that also spends a named sibling, enforced by
checking the spender-supplied outpoint set against `hashPrevouts`.

| tx | txid |
|---|---|
| setup (creates the companion UTXO) | `c0faa67ca4d8a5…`:0, 400 sat |
| deploy the covenant | `49ee8adcb5f621…`:0, 395 B, 1000 sat |
| co-spend, two inputs | `3bb4e2e69f3f35…` |

The co-spend carries exactly two inputs — the covenant at index 0 and the
companion at index 1 — and both were confirmed present on chain. Input 0's
covenant verified that input 1's outpoint was in the set before allowing the
spend. That it *relayed* is the point a local interpreter cannot make: a
two-input introspective spend is the kind of thing where standardness could have
bitten, and it did not.

### The stranding that came first

The initial attempt named an existing wallet UTXO (`d46350ba…`:1) as the
companion, then called the ordinary deploy path. Coin selection **funded the
deploy with that very UTXO** — so the covenant at `0b6b0217386321…`:0 now requires
a companion that its own deployment destroyed. 1000 satoshis, script-valid,
permanently unspendable, and `verify:chain` cannot flag it because nothing about
the bytes is wrong: the coin it points at is simply gone.

The fix was explicit coin control — a setup transaction that mints the companion
and funds the deploy from *different* outputs. See
[pitfall 24](pitfalls.md#24-a-companion-covenant-must-not-let-its-deploy-spend-the-companion).

## A ticket, resold and then burnt

The full two-branch lifecycle on chain, and the first covenant here that leaves
outputs it does not control.

| step | txid |
|---|---|
| mint | `fb9a4417c8f33a…`:0, 599 B, 1000 sat |
| resell at 100 sat | `9e1ac0ac296edb…` |
| check in | `d46350ba8f0ebd…` |

The resale produced four outputs, three pinned by the covenant and one free:

```
[0] 400 sat  the ticket, recreated under its new holder   pinned
[1]  10 sat  the venue's 10% of the declared price        pinned
[2] 100 sat  the declared price, to the named seller      pinned
[3] 290 sat  change                                       free tail
```

Output 3 is the point. `hashOutputs` covers every output, so a covenant that
fixes it exactly forbids change — the script instead builds outputs 0..2, then
concatenates a tail the spender pushes and hashes the whole thing. The tail
needs no validation: bytes that are not the transaction's real remaining outputs
hash to something else and the spend dies.

The check-in is the claim that needed a node rather than an interpreter. Output
0 is zero satoshis paying `OP_FALSE OP_RETURN
e4d4da9eeda4e02f57a5c04b18052514cd23884a0285394ec0f6a66f84351426` — the
`sha256("Barbican 2026-11-04|K12")` the script carries as a constant. It relayed
and the bytes match the constant exactly. A zero-value `OP_RETURN` output being
standard on BSV is the kind of thing that has to be measured, not assumed
([pitfall 1](pitfalls.md#1-consensus-valid-is-not-relayable)); it is.

The ticket UTXO `9e1ac0ac296edb…`:0 is spent by that transaction and there is no
second gate to present it at.

What the exercise does **not** show is a price being capped. See
[predicates.md](predicates.md#ticket) — the covenant binds the declared amount,
and a declaration is not a price.

## The R-puzzle spend releases its own key

The smallest interesting thing on the chain here, at 44 bytes, and the only
deployment whose *spend* is the payload rather than the lock.

| | txid |
|---|---|
| lock, committing to `r` | `b8e54b8f4bcc09…`:0, 44 B, 1000 sat |
| spend, signed with a disclosed key | `5a8c619ab6f6e8…` |

The signing key was minted for this and published on purpose:
`KxhFcHVzAHEiLoyTFA8ibzhJ2Uhk5XXLJeK6r93JUDBeXSzZRcms`. It has never held funds
and never will; disclosing it is the mechanism, not an accident. Given `d`, the
broadcast signature yields the nonce by rearrangement:

```
recovered k  6d0f4b27eb99c8d6d9830279f02f98c10964f07fe435f60d1d9aad623c7d3e54
SHA256(k)    40fced7f38f7ebfcfe4f3d5540ee90ea939c938bdc0a16cc823bc62c2f7ee3a0
```

Recovered from the chain alone — `woc /tx/{spend}/hex` plus the published WIF —
and equal to the nonce the lock was built from. That is a media segment's
decryption key, released by the same transaction that collected payment for it,
with no licence server in the loop.

The recovery has to reduce to `min(k, N-k)`: mandatory `LOW_S` negates it about
half the time. See [pitfall 22](pitfalls.md#22-low_s-normalisation-negates-a-recovered-nonce).

## The two that can never be spent

Both stranded outputs differ from their corrected sibling by a **single byte**,
which the verifier surfaces without being told to look:

| | on chain | corrected | |
|---|---|---|---|
| timelock | `865288a8…` 409 B | `6bb7c6b8…` 410 B | missing `OP_BIN2NUM` |
| perpetual | `7102453e…` 386 B | `dea3bdb0…` 385 B | one extra `OP_DUP` |

3000 satoshis, both script-valid, both refused by node policy, both permanent —
the defect is in the *locking* script, so no unlocking script can compensate.
See [pitfall 1](pitfalls.md#1-consensus-valid-is-not-relayable) and
[pitfall 2](pitfalls.md#2-consensus-hides-more-than-minimaldata--cleanstack-too).

## resolution — an outcome the quorum names, not a key

The keystone of the prediction-market framework: a [`resolution`](predicates.md#resolution)
object begins `OPEN` and moves once to `RESOLVED`, carrying the outcome an oracle
**quorum** attested — the first covenant whose *state transition* is authorised by a
threshold of attestations rather than a signature. Deployed, resolved by two of the
three panel oracles, and swept, all in block **965313**.

| step | txid |
|---|---|
| deploy → OPEN (question, resolver, 2-of-3 panel) | `6a4aadb66b2f3a…`:0 |
| resolve — oracles 0 and 1 attest outcome 1, self-recreates RESOLVED | `dca01e60f718b9…`:0 |
| sweep — the resolver reclaims the dust (the exit) | `84e981a90b2204…`:0 |

No key authorised the resolve; the two agreeing Rabin attestations did, over the
covenant's own committed question. `RESOLVED` is terminal on the resolve path, so the
settled outcome cannot be flipped. The bytes on chain reproduce `buildScript` exactly.

## market, marketN, marketScalar — three prediction markets, end to end

The market family, each a fully-collateralised bet the oracle **quorum** decides and
`hashOutputs` forces, deployed and settled in block **965313** (every owner set to the
funding wallet, so each payout returned home — the run cost only fees):

| market | what the quorum decides | deploy | settle |
|---|---|---|---|
| [`market`](predicates.md#market) (binary) | a yes/no outcome → winner takes the pot | `2f143c9d3628f0…`:0 | `92767bbdead8ed…` (YES) |
| [`marketN`](predicates.md#marketn) (categorical, K=3) | which of 3 outcomes → its owner takes the pot | `4fc5035c2e07d0…`:0 | `37b4f6c3b4607b…` (outcome 1) |
| [`marketScalar`](predicates.md#marketscalar) (scalar) | a value → the pot splits piecewise-linearly LONG/SHORT | `1a7aef61a08fed…`:0 | `2565bf8ac021b1…` (v=6500) |

Each settlement carried genuine attestations from two panel oracles over the market's
own question; the node accepted all three, so a quorum deciding a binary outcome, a
categorical index, or a graded split — and forcing the payout on chain — is consensus-
and policy-valid. The bytes on chain reproduce each `buildScript` exactly.

## The many-positions family — a reusable fact, and descent on chain

The scalable-markets coins, deployed and proven by spending. A [`bulletin`](predicates.md#bulletin)
resolved by a quorum and then **read** — recreated unchanged — so it persists as a fact many
positions can settle against; and the two descent coins, each resolved through the **mint branch**:
the genesis is the very outpoint the deploy spends, so the resolve proves descent from `G` directly.

| coin | step | txid |
|---|---|---|
| [`bulletin`](predicates.md#bulletin) | deploy (OPEN) | `4e5879923f06…`:0 |
| | resolve — oracles 0,1 attest outcome 1 | `facc31059372…`:0 |
| | read — recreated unchanged, the fact persists | `4d636ea556d8…`:0 |
| [`descentbulletin`](predicates.md#descentbulletin) | deploy (OPEN, genesis = the funding outpoint) | `33314f0c19c8…`:0 |
| | resolve — quorum, descent from `G` (mint branch) | `764fcc62f493…`:0 |
| [`descentmarket`](predicates.md#descentmarket) | deploy (OPEN, genesis = the funding outpoint) | `c78929bbb522…`:0 |
| | resolve — quorum, descent from `G` (mint branch) | `9aca50e490cf…`:0 |

Each spend was run through the real consensus Interpreter locally before broadcast (`scripts/deploy-manypositions.js`),
and the node accepted all seven — so a reusable oracle fact that recreates itself, and a coin that proves
its RESOLVED outcome descends from a unique genesis, are both consensus- and policy-valid on chain. The two
settlers that *read* these coins, [`position`](predicates.md#position) and [`positionv2`](predicates.md#positionv2),
are interpreter-verified; their on-chain two-input co-spend is the one deploy still to come.

## The settlers — a position paid by a two-input co-spend

The two coins that *read* a market and pay whoever was right, each proven by a **two-input
co-spend**: the position and the coin it reads are spent in one transaction, the coin recreated
while the position's collateral goes to the winner. Both inputs use `OP_PUSH_TX`, so a single
shared `nLockTime` was ground clean for both, and each input was run through the real Interpreter
locally before broadcast (`scripts/deploy-settlers.js`).

| settler | step | txid |
|---|---|---|
| [`position`](predicates.md#position) | bulletin deploy → resolve (the source) | `c70b44f44acf…`, `a9f39a631579…` |
| | position deploy | `222533fc8334…`:0 |
| | **settle** — co-spend `[position, bulletin]`, owner claims the YES outcome | `32e1a2727232…` |
| [`positionv2`](predicates.md#positionv2) | descentmarket deploy (OPEN @ dust + a fee) → resolve (the source) | `0c67aa48f69e…`, `2e62637b2d0c…` |
| | positionv2 deploy | `c51e8e878eed…`:0 |
| | **settle** — co-spend `[positionv2, descentmarket]` by market *identity*, owner claims | `e3128c87dc03…` |

The node accepted both settlements — including the 18 KB identity co-spend, in which the
`positionv2` verified the co-spent coin's covenant-script hash, read its outcome, and paid the
winner while the `descentmarket` recreated itself and proved its descent, all in one transaction.
That is the whole many-positions architecture, live: **write a position before the outcome is
known, resolve one coin by quorum, and settle the position against it — none forgeable.**

With these, **all forty-five predicates are deployed and spent on BSV mainnet.**

## Cost

Roughly 1250 satoshis of fees across the earliest exercise, plus 1000 stranded in
the timelock v1 script and 550 still circulating in the perpetual covenant. The four
prediction-market predicates added ~2210 satoshis of fees for nine transactions
(deploy + prove-spend each), all confirmed in block 965313. The many-positions coins
added seven more transactions, with a few thousand satoshis parked in the live
`bulletin`, `descentbulletin` and `descentmarket` coins they left on chain.
