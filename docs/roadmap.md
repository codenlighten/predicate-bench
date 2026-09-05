# Roadmap — what comes next

The bench is a working stack today: 45 predicates (all on mainnet), three type systems, four
surface languages, and a beginner-facing domain-builder API (`ledger`, `credential`,
`capability`, `game`). This file records the directions agreed for *after* the current
layer is complete, so nothing is lost. Nothing here is built yet; each is a plan.

## Near-term increments (finish the current layer first)

These round out what already exists and should land before the larger platforms below.

- **Grow the expression compiler** ([expressions.md](expressions.md), `src/expr.js`) — the
  frontend can now AUTHOR a new predicate from a condition (`assert(a + b == this.total)`),
  not just reproduce curated covenants. Ownership authors from a condition
  (**`checkSig(sig, pubkey)`** over the spending context — a real P2PKH in two lines), and
  **compile-time-bounded loops** unroll to Script (a real Merkle membership proof authors from
  `for i in 3 { … if(dir[i], …) … }`, 97 B). Extend the surface, keeping the real-interpreter,
  refusal-first bar: **named structs** over the existing fixed-width fields (field names, not
  positions). A real TypeScript-AST front end (the `typescript` package) is the eventual
  upgrade for a richer subset; the hand-written parser is the deliberate, zero-dependency start.
- **More domain builders** (`src/highlevel.js`) — `escrow()` (→ [witness](predicates.md#witness)/htlc),
  `stream()` (→ [journal](predicates.md#journal)), `treasury()` (→ [pool](predicates.md#pool)/[ledger](predicates.md#ledger)),
  `asset()` (→ [asset](predicates.md#asset)). Same shape as the four that exist: business
  vocabulary in, deployed-identical bytes out, plain-English guarantees and errors.
- **~~Extend the `@contract` TypeScript frontend~~ (done)** (`src/tslang.js`) — the frontend
  now covers **branch and dispatch** method bodies (`if/else`, selectors) as well as linear
  ones, with `@field` declarations the compiler turns into offsets and push-encoding. All four
  named targets compile from `@contract` classes byte-identical to the deployed predicate:
  `metered` and `token` (branches), `asset` and `sovereign` (dispatch), and now
  [`lifecycle`](predicates.md#lifecycle) and [`turns`](predicates.md#turns) — the two
  state-machine covenants, each a two-method `@branch('asm')` class. Their branch bodies were
  lifted into `src/covsteps.js` so the predicate and the compiler emit from one source and
  cannot drift.
- **More graph compositions** — register the remaining predicted-safe combinations
  (`guarded ∧ journal`, `pool ∧ witness`) as they are built, so the graph emits them
  byte-identical, and keep the composition-safety checker ahead of them.

## Then: the two platforms

Agreed to build *when the current layer is complete*.

### 1. Kaboom.js — a visual game + teaching layer

A browser game framework (Kaboom.js) as the front end over the [`game`](#) builder and the
[`turns`](predicates.md#turns) predicate. The split:

```
   Kaboom.js  →  graphics, input, sprites, scenes, animation, sound   (local, 60 FPS)
   turns/game →  who may move, whose turn, legal transition, payout    (BitCoin-enforced)
```

Only *meaningful* state transitions go on chain (a move accepted, a score change, a wager,
a round result, game completion) — never per-frame animation. The teaching arc:

```
   Rock-Paper-Scissors  →  commit / reveal
   Tic-Tac-Toe          →  turn-based state machine   (turns, today)
   Checkers             →  richer move predicates
   Trivia wager         →  oracle + answer reveal + payout
   Collectible battle   →  ownership + stats + game state
```

An SDK (`@smartledger/game`) would let a student write a normal-feeling Kaboom game whose
rules Bitcoin refuses to break: *“I wrote a game rule in TypeScript, and Bitcoin refuses
cheating.”* Per-game move legality (a square is empty, a jump is valid) composes on top of
`turns`, which already enforces the universal spine — authority, alternation, succession.

### 2. Prediction markets — a Polymarket-style framework

> **Status (in progress).** Two pieces are built and interpreter-verified:
> [`resolution`](predicates.md#resolution) — an `OPEN → RESOLVED(outcome)` object gated by an
> m-of-n oracle quorum, the first covenant whose transition authority is a *threshold of
> attestations rather than a key*; and [`market`](predicates.md#market) — the first complete END-TO-END
> market, a fully-collateralised two-party winner-take-all binary pot the quorum settles
> directly, now with a deadline **refund** branch (both parties reclaim their half if the panel
> vanishes) so it cannot strand funds. All four are now deployed and spent on BSV mainnet
> (block 965313). **Markets of MANY positions are built too:** [`bulletin`](predicates.md#bulletin)
> — a reusable, quorum-established outcome that recreates itself on every read — and
> [`position`](predicates.md#position) — a binary option that co-spends the bulletin, reads the
> committed outcome, and releases its collateral to whoever called it right. A `manypositions`
> demonstration settles three independent positions against one bulletin in a single
> interpreter-verified transaction. **And the frontier is closed:** [`descentbulletin`](predicates.md#descentbulletin)
> makes the reusable fact counterfeit-proof by proving descent from its genesis on every hop (even
> across the OPEN→RESOLVED state change), [`descentmarket`](predicates.md#descentmarket) unifies that
> descent with the position-payout tail into one deployable coin, and [`positionv2`](predicates.md#positionv2)
> lets a position be written *before* the outcome is known by identifying its market with a covenant-
> script hash. All of it is exposed at the beginner tier — `predictionMarket({...})` for single-pot
> markets (binary/categorical/scalar) and `positionMarket({...})` + `writePosition(...)` for a market
> of many positions. All of it is now deployed and spent on BSV mainnet — the entire 45-predicate catalogue is on chain, including the two-input co-spend that settles a position against the market it reads.

A prediction market is a constraint graph over the primitives the bench already has:

```
   Market
     ├── Collateral pool        →  conserve / pool
     ├── YES / NO positions     →  asset (ownership) + lineage (no counterfeits)
     ├── Resolution oracle      →  quorum + ticker (authenticated, fresh)
     └── Audit stream           →  journal / audited
   settlement: dependsOn(resolution) ∧ conservation ∧ freshness ∧ output-binding
```

A readable surface:

```ts
predictionMarket({
  question: 'Will Candidate A win?',
  outcomes: ['YES', 'NO'],
  collateral: USDToken,
  resolution: quorum({ oracles: [o1, o2, o3], required: 2 }),
  closeAt: marketClose,
  settle({ outcome }) { redeemWinningShares(outcome) }
})
```

The compiler infers the required composition: canonical positions + conservation + ownership
+ oracle quorum + freshness + market state + settlement binding + audit history. Model it as
a **graph** (Market / Positions / Collateral / Resolution / Payouts), not one monolithic
script — one resolution object can settle thousands of positions. Start with fully
collateralised binary markets; then multiple-choice, scalar, and conditional. Atomic trading
reuses the [`asset`](predicates.md#asset) swap; an AMM pricing layer is a much harder,
separate arithmetic/economic design. Also applicable as private/internal information markets.

## The through-line

Both platforms are the same thesis at the application layer: **people describe the rules in
their own domain, the compiler emits the exact deployed Script, and Bitcoin enforces them.**
Neither needs a new predicate primitive the bench lacks — they need the surface, the SDK, and
the graph wiring on top of what is already proven on mainnet.
