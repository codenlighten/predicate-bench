# The clause library

Every covenant in this bench is assembled from a small set of reusable pieces
that live in [`src/clauses.js`](../src/clauses.js). This document is the
reference for them: the compositional model they share, the stack contract that
makes them composable, the preimage map their offsets come from, and each
primitive with its stack effect.

If [preimage.md](preimage.md) explains *why* an OP_PUSH_TX signature proves the
transaction, and [predicates.md](predicates.md) shows *what* has been built, this
is the *how* — the layer you write new covenants in.

---

## The shape of every covenant

A covenant here is four phases, in order:

```
authenticate   prove the pushed preimage really describes this spend
introspect     read the fields it needs out of the preimage
constrain      require those fields (and any recreated script) to hold
finish         drop the preimage, leave a single true value
```

The whole point is the first phase. Bitcoin Script has no opcode that says "give
me my spending transaction". OP_PUSH_TX manufactures one: the spender pushes the
BIP-143 preimage as plain data, and the script synthesises an ECDSA signature
over it in-script with a fixed key and nonce, then calls `OP_CHECKSIG`. If it
passes, the pushed bytes are provably the sighash preimage of *this* spend — so
every field the script then reads is trustworthy. See
[preimage.md](preimage.md#reading-your-own-script) for the signature synthesis.

Once authenticated, the preimage is just a byte string on the stack, and
introspection is string surgery: `OP_SPLIT`, `OP_LEFT`, `OP_RIGHT`, `OP_CAT`.

---

## The stack contract

Clauses compose because they all obey one rule:

> Each clause receives the stack as `[…, preimage]`, consumes a **copy** of the
> preimage, and leaves `[…, preimage]` for the next one.

A clause that consumed the preimage would work perfectly alone and silently break
whatever followed it. That invariant is the entire reason a covenant can be
written as `authenticate(s); introspect(s); constrain(s); finish(s)` rather than
as one monolith.

`finish` is the only clause that breaks the invariant, because it is always last:
it drops the preimage and pushes `OP_1`.

---

## The preimage map

Offsets are the load-bearing detail, and there are two frames of reference.

`scriptCode` sits in the middle of the preimage and is **variable-length** — it
is the locking script being spent. So everything *before* it has a fixed offset
from the **front**, and everything *after* it has a fixed offset from the **end**.
Nothing that straddles `scriptCode` has a fixed absolute position at all.

```
 offset (front)                                          offset (end)
 0    nVersion            4 bytes                              —
 4    hashPrevouts       32 bytes   ← item 2, siblings         —
 36   hashSequence       32 bytes                              —
 68   outpoint           36 bytes   ← item 4, this input       —
 104  scriptCode        var (this locking script)             —
 —    value              8 bytes                          from end: 52
 —    nSequence          4 bytes                          from end: 44
 —    hashOutputs       32 bytes   ← item 9, outputs      from end: 40
 —    nLockTime          4 bytes                          from end: 8
 —    sighashType        4 bytes                          from end: 4
```

That table is encoded once, as `FROM_END`:

```js
const FROM_END = { LOCKTIME: 8, HASH_OUTPUTS: 40, SEQUENCE: 44, VALUE: 52 }
```

and the front-addressed fields are read by their own clauses. The tail from
`value` onward is exactly **52 bytes**, which is why `selfChunk` slices
`preimage[104 : len-52]` to recover `scriptCode`.

Two byte-order traps live in this map:

- **Little-endian numbers.** `value`, `nLockTime`, `nSequence` are little-endian.
  Reading one as a script number needs a sign-pad and re-minimisation
  ([pitfall 1](pitfalls.md#1-consensus-valid-is-not-relayable)).
- **Reversed txids.** The outpoints inside `hashPrevouts` are `reverse(txid) ‖
  vout` — bsv holds txids in display order and reverses them into the sighash
  ([pitfall 23](pitfalls.md#23-hashprevouts-reverses-the-txid-and-a-symmetric-test-hides-it)).

---

## Authentication clauses

### `authenticate(s)`
`[…, preimage] → […, preimage]`

The whole first phase in one call: `OP_DUP`, the lean OP_PUSH_TX core, `OP_VERIFY`.
After it, the preimage is proven and still on top. Note it **already does the
`OP_DUP`** — a caller that adds its own leaves a second copy and fails
CLEANSTACK, which cost 2000 satoshis before it was centralised here
([pitfall 2](pitfalls.md#2-consensus-hides-more-than-minimaldata--cleanstack-too)).

### `authenticateThenBranch(s)`
`[…, flag, preimage] → […]` then opens `OP_IF`

For a two-branch covenant. Authenticating inside each branch carries the
OP_PUSH_TX preamble twice, and that preamble is most of the script. This emits it
**once**, above the branch split, then `OP_SWAP`s the branch flag up for `OP_IF`.
The unlocking script must push the flag *below* the preimage: `… <flag>
<preimage>`. The caller supplies the two branches and the closing `OP_ENDIF`.
Worth ~40% on a two-branch script — see
[sizing.md](sizing.md).

### `requireSighashAll(s)`
`[…, preimage] → […, preimage]`

Rejects anything but `SIGHASH_ALL | FORKID`. Under `SINGLE` or `NONE`,
`hashOutputs` covers one output or none, so any output constraint would bind the
wrong thing. A covenant that constrains outputs must assert this or it is
replayable ([pitfall on sighash flags](pitfalls.md)).

---

## Introspection clauses

### `fieldFromEnd(s, fromEnd, len)`
`[…, preimage] → […, preimage, field]`

Take `len` bytes starting `fromEnd` bytes from the end of a copy. This is how
every tail field is read; pass it a `FROM_END` value.

### `hashPrevoutsFromFront(s)`
`[…, preimage] → […, preimage, hashPrevouts]`

Item 2, addressed from the front (only the 4-byte version precedes it). The one
window a covenant has onto the *other* inputs of its spend — `companion` uses it.

### `selfChunk(s)`
`[…, preimage] → […, preimage, chunk]`

Recover `scriptCode` — the `scriptlen ‖ script` bytes, varint included — as
`preimage[104 : len-52]`. This is the mechanism behind a self-recreating
covenant: it reads its *own* bytes out of its *own* preimage rather than
committing to a hash of them, which sidesteps the circular reference WP1605 marks
"infeasible" ([preimage.md](preimage.md#reading-your-own-script)).

### `fieldFromChunk(s, at, bytes)`
`[…, chunk] → […, chunk, field]`

Take `bytes` bytes starting `at` bytes into a chunk on top. The offset is from
the chunk's start (its varint), so a caller passes `HEAD_BYTES + fieldOffset`,
never a hand-counted absolute. This is how a stateful covenant reads a field out
of its own recovered script.

---

## Constraint clauses

### `requireOutputs(s, expectedHashOutputs)`
`[…, preimage] → […, preimage]` then `OP_EQUALVERIFY`

The spend must create exactly this 32-byte `hashOutputs` and nothing else. Used
when the output set is known at lock time (a fixed payee).

### `requireOutputIs(s)`
`[…, preimage, outputs] → […, bool]`

The dynamic form: `HASH256` the output set the script just built, compare to the
preimage's `hashOutputs`. Used when the covenant computes its own successor —
every self-recreating and stateful covenant ends its branch here.

### `requireSequenceNonFinal(s)`
`[…, preimage] → […, preimage]` then `OP_VERIFY`

The input must be non-final (`nSequence != 0xffffffff`), or `nLockTime` is inert
and any lock-time check below is reading a number the spender writes freely. A
timelock is only a timelock with this ([pitfall on locktime](pitfalls.md)).

### `requireLockTimeAtLeast(s, floor)`
`[…, preimage] → […, preimage]` then `OP_VERIFY`

`nLockTime >= floor`. Pads for sign, then `OP_BIN2NUM` to re-encode minimally —
the pad's trailing zeros are a non-minimal script number that passes consensus
and is refused at broadcast, which is
[pitfall 1](pitfalls.md#1-consensus-valid-is-not-relayable) exactly.

---

## Building an output, in script

To recreate itself or pay a computed amount, a covenant assembles a TxOut on the
stack: `value (8 LE) ‖ scriptlen (varint) ‖ script`.

### `newValueLE(s, fee)`
`[…, preimage] → […, value8]`

`value - fee`, as the 8-byte little-endian amount a TxOut starts with. This is
how a covenant that shrinks by a fee each hop computes its successor's value.

### `txOutChunk(script)` · `p2pkhTxOutChunk(addr)`
returns a `Buffer` (compile-time, not a stack op)

The `scriptlen ‖ script` half of a TxOut for a constant output — the same framing
`selfChunk` extracts, so a covenant can build one and compare. `p2pkhTxOutChunk`
does it for a P2PKH to an address. One-byte varint only (scripts ≤ 252 bytes),
which covers every constant output worth hard-coding.

### `hash160Of(a)`
returns 20 bytes

An address, address string, or raw hash160 → 20 bytes. The normaliser every
predicate uses so a caller can pass whichever they have.

---

## Grinding and finishing

### `grindPreimage(tx, inputIndex, lockingScript, satoshis, pin, sighashType)`
returns a `Buffer` (off-chain)

Search for a transaction whose in-script OP_PUSH_TX signature is clean low-S DER.
**Which field carries the grind matters.** Sweeping `nLockTime` moves the unlock
time itself — one block per attempt against a height floor, turning a one-block
lock into hours. So when the input is non-final it grinds the *sequence* instead
and leaves `nLockTime` pinned where the caller asked; only a deliberately-final
sequence (the case proving the non-final guard works) falls back to grinding
`nLockTime`. About 2% of preimages pass, so ~50 tries.

### `finish(s)`
`[…, preimage] → […, 1]`

Drop the preimage, push `OP_1`. Every composition ends here, and it is the one
clause allowed to consume the preimage because nothing follows it.

---

## Relay, not just validity

### `policyFlags()`
returns the interpreter flag word

What a node will actually **relay**, not merely what a block would accept:
consensus, plus the standardness bits that are not in the consensus flag word —
`MINIMALDATA`, `CLEANSTACK`, `SIGPUSHONLY`, `LOW_S`, `NULLFAIL`,
`DISCOURAGE_UPGRADABLE_NOPS`, `NULLDUMMY`. Verifying under consensus alone is a
*different* check, not a smaller one, and every missing bit cost a broadcast to
discover. It lives in one place so the harness, the tracer and the broadcast path
cannot drift on what "valid" means. Why these exact seven, measured rather than
reasoned: [pitfall 3](pitfalls.md#3-measure-the-flags-dont-reason-about-them).

---

## A covenant from scratch

Putting the vocabulary together — a coin that may only be spent to a fixed payee,
the simplest possible output-binding covenant:

```js
const C = require('../clauses')
const bsv = require('@smartledger/bsv')

function lock ({ payTo, satoshis, fee }) {
  const hashOutputs = C.hashOutputs([C.p2pkhOutput(payTo, satoshis - fee)])
  const s = new bsv.Script()
  C.authenticate(s)                 // [preimage] proven
  C.requireSighashAll(s)            // outputs mean what we think
  C.requireOutputs(s, hashOutputs)  // exactly this payee, this amount
  return C.finish(s)                // drop, leave true
}
```

The unlocking script is just the ground-out preimage:

```js
function unlock ({ tx, inputIndex, lockingScript, satoshis }) {
  const preimage = C.grindPreimage(tx, inputIndex, lockingScript, satoshis, tx.nLockTime)
  return new bsv.Script().add(preimage)
}
```

That is [`covenant`](predicates.md#covenant). Everything more elaborate —
carrying state, splicing a spender-chosen value, paying a royalty in ordered
outputs, reading a sibling input — is the same four phases with a richer
introspect-and-constrain middle. Read the predicates in ascending size and each
one adds exactly one idea to this skeleton.
