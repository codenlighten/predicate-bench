# Predicate Bench

*A mainnet-proven laboratory and compiler for Bitcoin (BSV) Script predicates.*

[![test](https://github.com/codenlighten/predicate-bench/actions/workflows/test.yml/badge.svg)](https://github.com/codenlighten/predicate-bench/actions/workflows/test.yml)

A bench for writing custom Bitcoin SV locking scripts and proving them before
they touch the chain.

A locking script is a predicate. The only question ever asked of it is whether
`unlockingScript || lockingScript` leaves a true value on the stack under
current consensus rules. This repo makes that question cheap to ask, and makes
the *other* half — what a predicate refuses — impossible to skip.

## Quick start

```bash
npm install
npm test                       # every predicate against the interpreter, offline
npm run probe                  # check the policy probes isolate one rule each
npm run probe -- --broadcast   # measure mainnet policy (free: refusals cost nothing)
npm run verify:chain           # check every documented txid against the chain
npm run audit                  # documented numbers derived from code, not transcribed

node bin/cli.js wallet:create  # or wallet:import <WIF>
node bin/cli.js balance
node bin/cli.js predicates

node bin/cli.js deploy hashlock secret="open sesame"
node bin/cli.js unlock <txid> secret="open sesame"
```

`--dry-run` on either shows the raw transaction without sending it.
`BSV_NETWORK=testnet` moves the wallet, endpoints and address prefixes.

## Documentation

**Start at [docs/index.md](docs/index.md)** — the map of the whole knowledge
base, with a reading path and an index of every predicate and pitfall. The
individual documents:

- **[model.md](docs/model.md)** — the thesis: Bitcoin as a state-transition
  machine, Script as the predicate `Allowed(S, S', W)`, grounded in the catalogue.
- **[preimage.md](docs/preimage.md)** — the BIP-143 preimage, why offsets are
  measured from the end, OP_PUSH_TX, and how a script reads its own bytes.
- **[clauses.md](docs/clauses.md)** — the grammar: the reusable building blocks,
  the four-phase shape of every covenant, and the annotated preimage byte map.
- **[authoring.md](docs/authoring.md)** — building the hard covenants: the
  stack-tracking assembler, the two ways to check a value, and branch dispatch.
- **[predicates.md](docs/predicates.md)** — every predicate: what it enforces,
  how, and what it refuses.
- **[sizing.md](docs/sizing.md)** — why script size *is* the fee, and the two
  restructurings that cut every stateful covenant by ~40%.
- **[tracing.md](docs/tracing.md)** — how a failing case reports which opcode
  stopped it, in which branch, with the stack going in.
- **[compiler.md](docs/compiler.md)** — a predicate as data: it compiles to the
  deployed bytes exactly, and refuses specs that reproduce the pitfalls.
- **[tooling.md](docs/tooling.md)** — the verification apparatus, and the rule
  underneath it: a check you have not seen fail is not a check.
- **[pitfalls.md](docs/pitfalls.md)** — twenty-five things that cost a real
  broadcast, a stranded output, or a bug that verified locally and failed on the
  network.
- **[mainnet-log.md](docs/mainnet-log.md)** — the on-chain record, every txid
  verified against the chain rather than asserted.

## What is here

```
src/harness.js        run a predicate against the real consensus interpreter
src/trace.js          locate a failure: which opcode, which branch, what stack
src/pushtx.js         a leaner OP_PUSH_TX core, with the dead steps removed
src/probe.js          measure what the network enforces, instead of guessing
tools/anchors.js      keep doc cross-references honest when sections move
tools/verify-chain.js check every documented txid against the chain
src/clauses.js        composable clauses that AND on one authenticated preimage
src/stackasm.js       a stack-tracking assembler for authoring large covenants
src/predicates/       the predicates themselves
src/onchain.js        deploy a predicate, spend it back
src/wallet.js         funding key; local spent-outpoint and output tracking
src/woc.js            WhatsOnChain client
bin/cli.js            wallet / balance / deploy / unlock / deployments
```

## Three rules this bench is built on

**Use the consensus interpreter, not a simulator.** The harness uses
`bsv.Script.Interpreter` — the same evaluator that validates blocks — with a
real BIP-143 FORKID sighash over a real spending transaction. The `p2pkh`
predicate exists as the control: a fake evaluator cannot produce a valid
`OP_CHECKSIG`.

The library also ships `SmartContract.simulateScript`, which is a stack tracer
rather than a validator. Established rather than assumed:

- it takes only an opcode list — **no transaction**, so `OP_CHECKSIG` cannot be
  evaluated against a real sighash at all;
- it **throws on data pushes** (`Unknown opcode: 3045022100aa`), so it cannot
  process an unlocking script that contains a signature;
- it returns `{finalStack, finalAltStack, history}` and **no verdict** — the
  caller judges truthiness. (The library's own `QUICK_START.md` documents a
  `simulation.success` field that does not exist.)

It is genuinely useful for watching a stack evolve. It cannot tell you whether a
spend is valid.

**Never hand-assemble era flags.** Omitting the `flags` argument makes the
interpreter resolve current mainnet itself. Assembling a flag word from named
constants is how you end up testing pre-Genesis limits by accident — see
[pitfall 9](docs/pitfalls.md#9-never-hand-assemble-era-flags).

**Every predicate carries refusal tests.** A predicate that accepts the right
answer is half-proven. `shouldFail: true` inverts a case, so the suite asserts
what a script *rejects*. Several cases go further and assert that removing a
guard makes the corresponding attack succeed — those fail if anyone deletes the
guard.

## Verify against policy, not just consensus

`clauses.policyFlags()` is the one definition of what a node will actually
relay, used by the harness, the tracer and the broadcast path alike so they
cannot drift:

```
consensus | MINIMALDATA | CLEANSTACK | SIGPUSHONLY | LOW_S | NULLFAIL
        | DISCOURAGE_UPGRADABLE_NOPS | NULLDUMMY
```

Consensus alone is not a smaller check, it is a different one, and each missing
bit cost a broadcast to discover — 1000 satoshis for MINIMALDATA, 2000 for
CLEANSTACK. So the list is now **measured** rather than reasoned about: see
[pitfall 3](docs/pitfalls.md#3-measure-the-flags-dont-reason-about-them) and
`npm run probe`. All seven bits are measured, and the measurement turned up two things reasoning
had missed: BSV treats **SIGPUSHONLY, LOW_S and NULLFAIL as mandatory** while
`currentConsensusFlags()` contains none of them, and
**`DISCOURAGE_UPGRADABLE_NOPS` and `NULLDUMMY` were enforced but absent** from
the list.

## Status

450 cases, forty-five predicates, all green.

<!-- audit:deployment -->
All forty-five predicates have been deployed and spent on BSV mainnet. Every
documented txid is verified against the chain rather than asserted: `npm run
verify:chain` confirms all 108 recorded outputs exist and match their recorded
bytes.
<!-- /audit -->

See [mainnet-log.md](docs/mainnet-log.md).
