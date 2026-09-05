# A predicate is data — the compiler

Every predicate in this bench is written as a JavaScript `lock()` that calls
clauses in order. That is already a big step up from hand-counting `OP_PICK`
depths ([authoring.md](authoring.md)). But a `lock()` is still *code*: nothing
stops it from binding outputs under the wrong sighash flag, or self-recreating
with no way to terminate, or leaving a dirty stack — each a mistake that this
bench paid for in a real broadcast before it learned the rule.

`src/compile.js` is the layer above. A predicate becomes **data** — an ordered
list of typed steps plus declared intent — and `compile()` refuses any spec that
violates an invariant a broadcast taught us, *then* emits the bytes.

```js
const covenant = {
  name: 'covenant',
  body: [
    { op: 'auth' },                              // authenticate, baking SIGHASH_ALL
    { op: 'requireOutputs', expected: H },       // bind the exact output set
    { op: 'dropTrue' }                           // finish clean
  ]
}
compile(covenant)   // -> the locking Script, or throws with the violated invariant
```

---

## Thin codegen, on purpose

The compiler does **no clever code generation**. Each step emits a clause that is
already proven correct and deployed on mainnet — `auth` is `authenticate`,
`requireOutputs` is the `hashOutputs` equality, `recreateSelfMinusFee` is the
self-recreation body from [`perpetual`](predicates.md#perpetual). Correctness is
*inherited* from the clauses, not re-established.

That is deliberate, because it lets the compiler make a claim it can prove: the
specs in this repo compile **byte-for-byte** to the same locking scripts the
predicates hand-wrote and deployed. `tools/compile-selftest.js` asserts it:

```
covenant  : byte-identical to the predicate  (linear: auth + bind + finish)
perpetual : byte-identical to the predicate  (linear: self-recreation)
metered   : byte-identical to the predicate  (state + hop/redeem branches)
vesting   : byte-identical to the predicate  (withdraw/finish branches)
token     : byte-identical to the predicate  (merge backtrace + split)
lineage   : byte-identical to the predicate  (descent, linear-asm body)
provenance: byte-identical to the predicate  (authenticity + ownership)
sovereign : byte-identical to the predicate  (all three, 3-way dispatch)
timelock  : byte-identical to the predicate  (locktime + sequence guard)
asset     : byte-identical to the predicate  (conserve + own + atomic swap)
```

If the compiler had drifted from the clauses by a single byte — a reordered
`OP_SWAP`, a different push — the self-test would fail against the predicates'
own output. So the compiler is demonstrably a faithful *front-end* to the existing
predicates, not a second, subtly-different implementation of them. All the value
it adds is in what it **refuses**.

That faithfulness is not a coincidence of careful copying: the branch bodies of
the stateful covenants live in **one** place, `src/covsteps.js`, and both the
predicate and the compiler call them. `metered`'s `buildScript` and the `metered`
spec emit the same `meteredIncrementRecreate`; there is no second copy to drift.

### Branches and carried state

A linear spec is a `body` of steps. A stateful, two-branch covenant is a `branch`
instead — a leading `state` field (pushed and dropped, as in
[`metered`](predicates.md#metered)) and two branch bodies compiled through the
shared-preamble `authenticateThenBranch`:

```js
const metered = {
  name: 'metered',
  state: counterBuf(0),
  branch: {
    style: 'raw',
    if:   { steps: [ readCounterKeep, guardBelow(max), incrementRecreate(fee) ] },   // hop
    else: { steps: [ readCounterDrop, guardAtLeast(max), payFixed(addr, fee) ] }      // redeem
  }
}
```

`style: 'raw'` emits opcodes directly; `style: 'asm'` drives a StackAsm and adds the
clean-stack epilogue, which is how [`vesting`](predicates.md#vesting)'s branches
compile — each as five steps, `gate → read inputs → computeUnvested → guard → pay`.
The two styles exist because the predicates were written in two eras; both are just
ways to fill a branch body.

---

## Pitfalls, as compile-time invariants

The whole point is to move the bench's [pitfalls](pitfalls.md) from "things you
must remember" to "things the compiler will not let you build." The invariant
pass runs before any bytes are emitted; a violation is a thrown error naming the
pitfall, not a script.

- **A covenant that binds outputs must commit to the whole transaction**
  ([pitfall 8](pitfalls.md#8-the-sighash-flag-decides-what-the-covenant-commits-to)).
  The `OP_PUSH_TX` core bakes the sighash flag; if it bakes anything but
  `SIGHASH_ALL` while the spec binds outputs, the authorisation is replayable onto
  a transaction that keeps this input and output and changes everything else. The
  compiler reads the flag the `auth` step bakes and refuses `authOpen`
  (`SINGLE|ANYONECANPAY`) beneath any output binding. `authOpen` is still offered —
  deliberate open-endedness is a real use — but never under an output constraint.

- **A self-recreating covenant that drains value needs an exit**
  ([pitfall 18](pitfalls.md#18-give-a-terminating-covenant-an-exit-branch)). A spec
  with a self-recreating step must be able to terminate: a **branch** covenant
  satisfies it with a sibling branch that is an `exit` (metered's `redeem`,
  vesting's `finish`); a **linear** one must, like
  [`perpetual`](predicates.md#perpetual), acknowledge `terminates: 'fee-exhaustion'`
  — a conscious statement that the remainder is meant to burn down. You cannot
  *accidentally* ship a covenant that strands its tail: the self-test seeds a
  two-branch spec that self-recreates in *both* branches, and the compiler refuses
  it.

- **The script must end clean** (`CLEANSTACK`). The last step must be a terminal
  one, or the final stack is not a single true value and the node refuses to relay
  it. A spec that forgets to finish is refused, not emitted.

- **Authenticate before trusting anything.** A spec with no `auth`/`authOpen` step
  is reading a preimage the spender forged; the compiler refuses it outright.

- **A sibling's balance must be proven, never trusted** — the inflation attack
  ([cross-input.md](cross-input.md)). A covenant cannot read another input's balance
  from its own preimage, so a step that consumes a *pushed* sibling balance
  (`tokMergeConserve`) must be paired, in the same branch, with a **backtrace** step
  (`tokVerifyFunding`) that rebuilds the sibling's funding transaction and hashes it
  to the sibling's real txid. Drop the backtrace and the spender mints value from
  nothing; the compiler refuses the spec. This is the bench's sharpest security
  result — [`token-merge-analysis`](tooling.md) *measures* the attack succeeding on
  the interpreter, and the compiler now makes building it impossible.

- **A token that claims a genesis must prove it** — the counterfeit
  ([`lineage`](predicates.md#lineage)). A covenant that recreates itself carrying a
  genesis (`linSuccessor`, tagged `recreatesGenesis`) presents itself as an
  authentic token; it must also prove that genesis by descent (`linGenesisOrParent`,
  tagged `provesDescent`) — its parent was a genuine token of the same genesis, or it
  is the mint. Omit the proof and you have a self-perpetuating fake: it recreates
  forever but never shows it descends from a real issuance. The compiler refuses it.

- **A spender-chosen owner must be authorised** — theft
  ([`titled`](predicates.md#titled)). A covenant that splices a spender-supplied
  owner into its successor (`provSuccessor`, tagged `writesOwner`) must require the
  *current* owner's signature (`provAuthorise`, tagged `authorisesOwner`), or anyone
  can transfer the token by simply writing themselves in as the new owner.
  Possession is not authority.

Those last three are exactly the properties a token system rests on —
**conservation**, **authenticity**, **ownership** — and the compiler enforces each
before a byte is emitted. [`provenance`](predicates.md#provenance) shows why that is
the point of a compiler rather than a habit: it *composes* authenticity and
ownership, and the invariant pass demands **both** proofs — drop the descent step and
it is a counterfeit, drop the owner check and it is theft. Composing mechanisms is
now spec assembly, and the composition cannot silently lose a guarantee.

The self-test seeds one spec for each *structural* rule (no auth, dirty stack, a
malformed branch, an open core under an output binding) and confirms the compiler
rejects it. The *composition* rules — inflation, counterfeit, theft — it does not
seed by hand at all; see below.

---

## A semantic type system

The invariant pass is not a list of ad-hoc checks; it is a **capability (effect)
system** over semantic types. A value produced inside a spend path carries a
capability — an *authenticated preimage*, a *proven sibling balance*, an
*enforceable locktime* — and a step that consumes such a value declares the
capability it **needs**. A body type-checks only when every step's needs are
established, somewhere in that same path, by a step that **gives** them:

```
gives:  auth → Authenticated, BoundToWholeTx     backtrace → ProvenSibling
        provesDescent → ProvenDescent            requireSeqNonFinal → NonFinalSequence
        authorisesOwner → AuthorisedOwner
needs:  bind outputs → Authenticated, BoundToWholeTx
        conserve-a-sibling → ProvenSibling        recreate-genesis → ProvenDescent
        write-owner → AuthorisedOwner             use-locktime → EnforceableLockTime
```

Capabilities can be **derived**, and that is the leverage — sound values arise only
from sound combinations:

```
EnforceableLockTime  ⇐  Authenticated  ∧  NonFinalSequence
```

So reading `nLockTime` yields nothing usable on its own; only in a path that also
guards the sequence non-final does an `EnforceableLockTime` exist to satisfy
`timelockAtLeast`. Drop the guard and the comparison is reading a number the spender
writes freely — `E_LOCKTIME_INERT`, exactly [pitfall 11](pitfalls.md#11-reading-nlocktime-without-reading-nsequence),
now a type error. Each missing capability maps to a typed code — `E_UNVERIFIED_PREIMAGE`,
`E_REPLAYABLE_OUTPUTS`, `E_INFLATION`, `E_COUNTERFEIT`, `E_THEFT`, `E_LOCKTIME_INERT`
— a bug class the bench paid for, promoted from tribal knowledge to a language rule.
The check is order-agnostic: every clause is a `VERIFY`, so a proof may follow its
use; what matters is that the capability is *present* in the path.

### The source is its own security spec

`deriveRefusals(spec)` reads the capabilities *backwards*: for every capability a
spec's steps need, it finds the step that provides it (or, for a derived capability,
a provider of one of its dependencies) and removes it — yielding the mutant the type
check must reject. So a spec generates **its own adversarial tests**, the negative
cases a developer would otherwise hand-write. The self-test runs this over every
sound spec and gets **sixteen** derived refusals, each firing its typed code — the
three-way `sovereign` merge case alone gives `E_INFLATION`, `E_COUNTERFEIT` and
`E_THEFT` at once, and `timelock` gives `E_LOCKTIME_INERT`. The predicate's *source*
and its *security specification* are the same artifact.

This carries the bench's founding discipline — a predicate is judged by what it
refuses — one rung further: the refusals are now *derived* from the types, not
authored.

## The catalogue is the conformance suite

Because every step compiles byte-for-byte to a predicate measured on the real
interpreter and (mostly) spent on mainnet, the language is not designed from
imagination — it is *extracted from working Bitcoin programs*. Each construct maps
back to a contract that already proved it:

| construct | mechanism | proved by |
|---|---|---|
| `authorize` | a signature | [p2pkh](predicates.md#p2pkh) · [titled](predicates.md#titled) |
| `knowledge` | a hash preimage | [hashlock](predicates.md#hashlock) |
| `after` | nLockTime, bound properly | [timelock](predicates.md#timelock) |
| `bind outputs` | hashOutputs | [covenant](predicates.md#covenant) |
| `recreate` | self-reference | [perpetual](predicates.md#perpetual) |
| `state` | carried in scriptCode | [metered](predicates.md#metered) |
| `conserve` | arithmetic + backtrace | [token](predicates.md#token) |
| `descends-from` | inductive lineage | [lineage](predicates.md#lineage) |
| `owned` | descent + owner sig | [provenance](predicates.md#provenance) |
| `after` | nLockTime, sequence-guarded | [timelock](predicates.md#timelock) |
| `swap` | own output pinned, SIGHASH_ALL atomicity | [asset](predicates.md#asset) |
| all three | conserved + owned + authentic | [sovereign](predicates.md#sovereign) |

---

## What this is, and is not, yet

This is a growing slice, not yet the whole language the
[project review](../README.md) sketches. It now covers linear covenants
(`covenant`, `perpetual`), a two-branch stateful covenant with carried state
(`metered`), and a two-branch covenant computing over time (`vesting`) — reproducing
all four exactly and enforcing the invariants those families most often violate.
The compiler now spans four body shapes: **linear-raw** (covenant, perpetual),
**branch** (metered, vesting, token), **linear-asm** (lineage, provenance), and
**dispatch** (sovereign — a leading state field, a parked preimage, and a nested
`OP_IF` selector over transfer / split / merge, each case self-terminating). The
capstone landed as *spec assembly*: `sovereign`'s three cases are lists of steps
already written for `token` (conservation, the multi-output backtrace), `lineage`
(descent, its `descentReadParent` literally shared), and `titled` (the owner
signature) — and its **merge case trips all three invariants at once** (it recreates
a genesis-carrying owned token *and* conserves a sibling balance), so the compiler
demands descent, an owner signature, *and* a backtrace before it will emit a byte.

Every predicate the bench has built that carries state or binds outputs is now in
the compiler — `asset` closed the list, its four-way dispatch adding an atomic swap
(each owner's `SIGHASH_ALL` signature *is* consent to the whole trade) to the same
conserve-and-own steps `sovereign` uses. The only predicates outside it are the
handful with no state and no output binding (`hashlock`, `rpuzzle`, `merkle`,
`multisig`), where a spec would be longer than the script.

## The surface syntax

The spec is a plain object, but it no longer has to be written by hand. A `.pred`
source (`src/predlang.js` parses it) describes the **rule** in text, and the human
never touches an opcode:

```
predicate covenant {
  authenticate
  require-outputs expected=$expected
  finish
}
```

A statement is one shared step (a few readable aliases — `authenticate`, `finish`,
`require-outputs` — cover the common ones; every other step is its own kebab-cased
name); parameters are `$name`, bound when the source is built. Structure mirrors the
four spec shapes — a leading `state`, a `branch`, a `dispatch`, or an `authenticate`
preamble over an asm `body`. `predlang/` holds one `.pred` per predicate, and
`predlang-selftest.js` proves the only thing that matters: **each parsed, compiled
`.pred` is byte-identical to the deployed predicate** — covenant through the
1420-byte three-way `sovereign`. The invariant pass runs on the parsed spec, so an
unauthenticated or unsound `.pred` is refused at build time, exactly as a
hand-written spec is.

That closes the loop the [project review](../README.md) drew: a human writes the
predicate, the compiler emits the opcode mechanics, and the result is provably the
same Script that was measured against consensus and spent on mainnet.

The direction it points, though, is the important part: the bench's clauses are a
correct-by-construction *instruction set*, StackAsm schedules them without stack
bugs, and this layer checks *intent* against the invariants before emitting. A
declarative contract language for BSV that compiles through exactly this path —
spec → invariants → clauses → the real consensus interpreter → a mainnet receipt —
is a larger prize than any single further predicate, because it makes the whole
catalogue's hard-won correctness the *default* rather than something each new
covenant must re-earn.

See also: [authoring.md](authoring.md) (the StackAsm layer beneath this),
[clauses.md](clauses.md) (the instruction set), [pitfalls.md](pitfalls.md) (the
rules, in the form that cost real coins to learn).
