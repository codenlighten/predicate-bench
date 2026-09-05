# The knowledge base

A working reference for real Bitcoin (BSV) locking scripts — predicates and
covenants — every one of them built from scratch, evaluated against the actual
consensus interpreter, and most of them deployed and spent on mainnet. Nothing
here is simulated: a claim is either measured on chain or marked as not yet
tested.

The organising idea is small. **A locking script is a predicate**: the only
question ever asked of it is whether `unlockingScript ‖ lockingScript` leaves a
true value on the stack under current consensus rules. Everything below is an
answer to that question, from the 25-byte standard payment up to covenants that
read their own bytes, carry state, pay royalties, and reason about their sibling
inputs.

For the whole system as one map — the layers from Script up to a language of
interacting Predicate Objects — read **[architecture.md](architecture.md)**. For the
idea behind all of it — Bitcoin as a state-transition machine in which
UTXOs hold state, transactions propose transitions, and Script is the predicate
`Allowed(S, S', W)` a transition must satisfy — start with **[model.md](model.md)**.
The rest of this reference is that thesis, worked out and measured.

---

## Where to start

Read in this order and each document assumes only the ones before it:

1. **[preimage.md](preimage.md)** — how a script obtains its own spending
   transaction. OP_PUSH_TX, the in-script ECDSA synthesis, the WP1605 conformance
   audit, and the fields that cannot be predetermined. This is the foundation the
   covenants stand on.
2. **[clauses.md](clauses.md)** — the grammar. The reusable building blocks in
   `src/clauses.js`, the four-phase shape of every covenant, the stack contract
   that makes them compose, and the annotated preimage byte map. Write new
   covenants in this layer.
3. **[authoring.md](authoring.md)** — building the hard ones. The stack-tracking
   assembler, the two ways to check a value, reading your own script without a
   circular constant, and how three branches dispatch. Read it before the biggest
   covenants (`token`, `asset`).
4. **[predicates.md](predicates.md)** — the catalogue. Every predicate in
   ascending size, each adding one idea to the one before it, with what it
   enforces and — the half that matters — what it refuses.
5. **[pitfalls.md](pitfalls.md)** — what it cost to learn. Every entry is a real
   broadcast, a stranded output, or a bug that verified locally and failed on the
   network, ordered by how expensive it is to learn the hard way.
6. **[mainnet-log.md](mainnet-log.md)** — the receipts. Every deployment and
   spend, by txid, with what each one proved.

Reference, once the above make sense:

- **[cross-input.md](cross-input.md)** — what one input can learn about the
  others: identity for free, value only by backtrace, and the inflation attack the
  naive token merge admits.
- **[oracle.md](oracle.md)** — verifying off-chain data in Script: why
  OP_CHECKSIG cannot, Rabin signatures from first principles, and the value-binding
  forgery the check must refuse.
- **[sizing.md](sizing.md)** — where the bytes go, and the optimisations:
  hoisting the OP_PUSH_TX preamble, the lean core's two dead-code removals,
  `OP_CODESEPARATOR`, and the optimal 85-byte core.
- **[tracing.md](tracing.md)** — the debugger: attributing a script failure to
  the exact opcode and phase.
- **[compiler.md](compiler.md)** — a predicate as data: a spec that compiles to
  the deployed bytes exactly, with the bench's pitfalls enforced as compile-time
  invariants.
- **[relational.md](relational.md)** — the type ladder for cross-object predicates:
  what one coin may soundly conclude about another it is spent beside, and why a
  bounded total needs proven descent.
- **[roadmap.md](roadmap.md)** — what comes next: the near-term builders, and the
  Kaboom.js game layer and prediction-market framework planned on top.
- **[opcodes.md](opcodes.md)** — the complete opcode set of the current release,
  catalogued and reconciled against the library, with the honest NOP/trap annotations.
- **[tooling.md](tooling.md)** — the harness, the auditor, the anchor checker,
  the chain verifier, and the mainnet probe.

---

## The predicates

Forty-five. The catalogue is [predicates.md](predicates.md); the live byte counts
and case totals are kept current by `npm run audit`.

| predicate | what it enforces | new idea it introduces |
|---|---|---|
| [`p2pkh`](predicates.md#p2pkh) | hold the key behind this hash | the control: a real sighash, not a simulation |
| [`hashlock`](predicates.md#hashlock) | reveal a preimage of a fixed sha256 | knowledge alone as a spending condition |
| [`rpuzzle`](predicates.md#rpuzzle) | sign with a committed nonce, under any key | the secret in the nonce, not the key |
| [`merkle`](predicates.md#merkle) | prove a leaf is in a committed tree | Script reasoning about a data structure |
| [`lineage`](predicates.md#lineage) | prove unbroken descent from a genesis | authenticity: back-to-genesis, no SNARK |
| [`provenance`](predicates.md#provenance) | owned + authentic: transfer with lineage | composition: authenticity + ownership |
| [`sovereign`](predicates.md#sovereign) | conserved + owned + authentic, at once | the three-way composition |
| [`multisig`](predicates.md#multisig) | m-of-n, in key order, empty dummy | splitting authority (the one non-covenant) |
| [`companion`](predicates.md#companion) | spendable only beside a named input | reading *sibling* inputs via hashPrevouts |
| [`token`](predicates.md#token) | a balance conserved across merge and split | the backtrace: proving a sibling's value |
| [`asset`](predicates.md#asset) | an owned token: transfer, split, merge, swap | composition: ownership + conservation |
| [`timelock`](predicates.md#timelock) | nLockTime ≥ floor, done properly | binding a tail field of the preimage |
| [`covenant`](predicates.md#covenant) | pay exactly this output set | output-binding via hashOutputs |
| [`perpetual`](predicates.md#perpetual) | recreate this exact script, minus a fee | self-recreation by reading own bytes |
| [`htlc`](predicates.md#htlc) | a secret, or a refund after a floor | two branches on one preimage |
| [`composed`](predicates.md#composed) | outputs AND locktime AND non-final | ANDing clauses on one authentication |
| [`metered`](predicates.md#metered) | carry a hop counter; expire | computed state |
| [`titled`](predicates.md#titled) | only the named owner transfers or cashes out | spender-chosen state, spliced in |
| [`ticket`](predicates.md#ticket) | capped resale, venue cut, burnt at the door | a spender number under a ceiling; a free tail |
| [`registry`](predicates.md#registry) | a multi-field record, per-field rules | schema-driven state |
| [`royalty`](predicates.md#royalty) | a creator's share on every hand-off | ordered outputs |
| [`oracle`](predicates.md#oracle) | claim on an oracle's signed value, else refund | external data via a Rabin signature |
| [`settlement`](predicates.md#settlement) | an oracle value splits a pot between two parties | the oracle value as a dial, not a gate |
| [`quorum`](predicates.md#quorum) | m-of-n oracles must attest the same value | splitting trust across oracles |
| [`ticker`](predicates.md#ticker) | a self-recreating oracle mirror, monotonic | oracle-driven state, with anti-replay |
| [`journal`](predicates.md#journal) | an append-only hash-linked log | a hash chain: head commits to history |
| [`lifecycle`](predicates.md#lifecycle) | a status machine: bounded moves, a terminal state | a state machine + an immutable constitution |
| [`delegation`](predicates.md#delegation) | a divisible authority budget; delegate, exercise, revoke | conservation applied to authority; Σ ≤ root |
| [`witness`](predicates.md#witness) | release gated on a named sibling coin's committed state | a sound cross-object state condition |
| [`conserve`](predicates.md#conserve) | a conserved, uncounterfeitable two-body pair | conservation + descent across two coins at once |
| [`guarded`](predicates.md#guarded) | conserve ∧ witness in one covenant, oracle-gated | composing two cross-object relationships |
| [`pool`](predicates.md#pool) | conserve for N bodies: N balances that always sum to a constant | a distributed conserved state system |
| [`audited`](predicates.md#audited) | conserve ∧ journal: a conserved pair that logs every rebalance | the first cross-class composition |
| [`ledger`](predicates.md#ledger) | pool ∧ journal: an N-body conserved treasury that logs every rebalance | a predicted-safe composition, then deployed |
| [`turns`](predicates.md#turns) | a two-player turn-based game; the current player moves, turn alternates | Bitcoin as the game referee |
| [`vesting`](predicates.md#vesting) | a grant that streams linearly over time | continuous time-proportional release |

The **prediction-market framework** — an oracle quorum deciding outcomes, from a single pot to a market of many positions:

| predicate | what it enforces | new idea it introduces |
|---|---|---|
| [`resolution`](predicates.md#resolution) | an OPEN→RESOLVED outcome gated by an m-of-n quorum | transition authority as a threshold of attestations, not a key |
| [`market`](predicates.md#market) | a two-party binary market: quorum decides, pot to the winner, deadline refund | a whole prediction market in one covenant |
| [`marketN`](predicates.md#marketn) | a categorical market: the quorum names one of K outcomes | a K-way winner-selection cascade, range-guarded |
| [`marketScalar`](predicates.md#marketscalar) | a scalar market: the quorum's value splits the pot piecewise | `settlement`'s graded split under a quorum |
| [`bulletin`](predicates.md#bulletin) | a reusable outcome fact that recreates itself on every read | a fact many positions read without consuming it |
| [`position`](predicates.md#position) | a binary option settled by co-spending a bulletin | cross-covenant settlement by backtrace |
| [`descentbulletin`](predicates.md#descentbulletin) | a counterfeit-proof reusable fact: proves descent from its genesis | descent across a state change (OPEN→RESOLVED) |
| [`descentmarket`](predicates.md#descentmarket) | descent ∧ a pTail of position payouts, in one coin | the unified many-positions market coin |
| [`positionv2`](predicates.md#positionv2) | a position that identifies its market by covenant-script hash | positions written *before* the outcome is known |

---

## The pitfalls

Twenty-seven, most expensive first. Full text in [pitfalls.md](pitfalls.md).

*The costly ones — coins lost or a broadcast to discover:*

1. [Consensus-valid is not relayable](pitfalls.md#1-consensus-valid-is-not-relayable)
2. [Consensus hides more than MINIMALDATA — CLEANSTACK too](pitfalls.md#2-consensus-hides-more-than-minimaldata--cleanstack-too)
3. [Measure the flags; don't reason about them](pitfalls.md#3-measure-the-flags-dont-reason-about-them)
4. [BSV holds non-final transactions; it does not reject them](pitfalls.md#4-bsv-holds-non-final-transactions-it-does-not-reject-them)
5. [Grinding nLockTime destroys the lock you asked for](pitfalls.md#5-grinding-nlocktime-destroys-the-lock-you-asked-for)
6. [OP_CHECKLOCKTIMEVERIFY does not work on BSV](pitfalls.md#6-op_checklocktimeverify-does-not-work-on-bsv)
7. [OP_CODESEPARATOR and self-reference cannot coexist](pitfalls.md#7-op_codeseparator-and-self-reference-cannot-coexist)

*The subtle ones — correctness traps that verify locally:*

8. [The sighash flag decides what the covenant commits to](pitfalls.md#8-the-sighash-flag-decides-what-the-covenant-commits-to)
9. [Never hand-assemble era flags](pitfalls.md#9-never-hand-assemble-era-flags)
10. [nLockTime is a floor, never a ceiling](pitfalls.md#10-nlocktime-is-a-floor-never-a-ceiling)
11. [Reading nLockTime without reading nSequence](pitfalls.md#11-reading-nlocktime-without-reading-nsequence)
12. [The sign bit in nLockTime](pitfalls.md#12-the-sign-bit-in-nlocktime)
13. [Client-side checks that are not the network's](pitfalls.md#13-client-side-checks-that-are-not-the-networks)
21. [Fixed-width state, or the offsets move](pitfalls.md#21-fixed-width-state-or-the-offsets-move)
22. [`LOW_S` normalisation negates a recovered nonce](pitfalls.md#22-low_s-normalisation-negates-a-recovered-nonce)
23. [hashPrevouts reverses the txid, and a symmetric test hides it](pitfalls.md#23-hashprevouts-reverses-the-txid-and-a-symmetric-test-hides-it)
24. [A companion covenant must not let its deploy spend the companion](pitfalls.md#24-a-companion-covenant-must-not-let-its-deploy-spend-the-companion)
25. [OP_CHECKSIG verifies the transaction, not a message](pitfalls.md#25-op_checksig-verifies-the-transaction-not-a-message)
26. [A fixed output-count backtrace strands a coin whose parent has change](pitfalls.md#26-a-fixed-output-count-backtrace-strands-a-coin-whose-parent-has-change)
27. [A preimage nLockTime check must pin the domain, not just the magnitude](pitfalls.md#27-a-preimage-nlocktime-check-must-pin-the-domain-not-just-the-magnitude)

*The operational ones — infrastructure and process:*

14. [WhatsOnChain's unspent index lags and flaps](pitfalls.md#14-whatsonchains-unspent-index-lags-and-flaps)
15. [Decide what you will record before the irreversible step](pitfalls.md#15-decide-what-you-will-record-before-the-irreversible-step)
16. [Command-line parameters are strings](pitfalls.md#16-command-line-parameters-are-strings)
17. [A covenant that dictates outputs also dictates the fee](pitfalls.md#17-a-covenant-that-dictates-outputs-also-dictates-the-fee)
18. [Give a terminating covenant an exit branch](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)
19. [One explorer is a single point of failure](pitfalls.md#19-one-explorer-is-a-single-point-of-failure-that-does-not-announce-itself)
20. [`.change()` silently drops a dust-sized change output](pitfalls.md#20-change-silently-drops-a-dust-sized-change-output)

---

## What has been proven on chain

**Every one of the forty-five predicates has been deployed and spent on BSV
mainnet** — nothing here is simulated, from the 25-byte payment to the two-input
co-spend that settles a position against a market it co-spends. The tally
is on the [README](../README.md), kept accurate by `npm run audit`, with `npm run
verify:chain` confirming all recorded outputs against the chain; the full record
is [mainnet-log.md](mainnet-log.md). Highlights:

- **The two strandings** that taught pitfalls 1 and 2: coins locked behind
  scripts that are consensus-valid but refused by policy, permanently. The whole
  bench exists because of these.
- **A timelock** accepted for relay, held in the non-final pool, and confirmed
  when the chain reached its floor — script floor and consensus timing both shown.
- **An R-puzzle** whose spend releases its own nonce to anyone holding a
  published key, recovered from the chain alone.
- **A token** taken through its whole life on chain — minted, split into two,
  and the halves merged back — with the balance conserved at every hop by a
  backtrace that proves each sibling's balance.
- **An owned asset** merged by *two* parties in one transaction, each input
  carrying its own owner's signature, so the merge happens only because both
  consented.
- **A two-party handshake and a stranding, side by side**: the bench keeps its
  failures on chain next to its successes.
- **Four prediction markets settled by an oracle quorum** in one block (965313):
  a binary, a categorical, and a scalar market, plus the resolution object that
  moves its state only on the agreement of *m of n* independent oracles — an
  outcome decided by no one's permission and everyone's attestation.

---

## Running it

```
npm test              # 161 cases against the real interpreter, + self-tests
npm run audit         # documented numbers must match the code
npm run verify:chain  # every recorded txid exists and matches its bytes
npm run cli -- help   # deploy / unlock / inspect on mainnet
npm run probe         # measure a node's standardness policy, for the price of fees
```

The invariant behind all of it: documentation that quotes a number is checked
against the code, and a claim about the chain is checked against the chain. See
[tooling.md](tooling.md).
