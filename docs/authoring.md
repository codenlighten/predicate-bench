# Authoring covenants

[clauses.md](clauses.md) covers the vocabulary — the reusable pieces and the
four-phase shape (authenticate → introspect → constrain → finish). This document
is about writing the *hard* ones: covenants with a dozen live values, three
branches, a backtrace. The small predicates are written by hand; past a certain
size that stops being safe, and this is how the large ones in this bench are
actually built.

---

## Two ways to check a thing

Every covenant constraint can be written in one of two styles, and choosing the
right one per constraint is most of what keeps a large script tractable.

**The covenant computes.** The script derives the value itself and compares.
`perpetual` computes its successor's amount as `value - fee` and rebuilds the
output; the spender supplies nothing it could lie about. Use this when the value
is a function of things the covenant already holds.

**The spender assembles; the covenant verifies by equality.** The spender pushes
a fully-formed byte string and the script checks it against something it trusts.
`companion` takes the whole outpoint vector and checks `HASH256(vector) ==
hashPrevouts`; it never parses the vector, because the hash equality pins it
completely. `token`'s backtrace takes the sibling's whole output section and pins
it the same way. Use this when parsing in-script would be large and fragile — a
hash or a length check can pin a structure the script would otherwise have to walk.

The second style is the one that scales. A spender lie changes the bytes, the
pinning check fails, and the coin does not move — so the covenant gets the safety
of parsing without the cost of it. The rule of thumb: **never walk a structure in
script if a hash of it, or a length of it, already constrains what it must be.**

---

## The stack is the enemy

Bitcoin Script has no named variables. Everything is depth arithmetic:
`OP_PICK 7` copies whatever is seven-deep *right now*, and "right now" shifts every
time anything is pushed or consumed. A covenant with a dozen live values is a
dozen depths that all move as you write, and a single wrong count is a
security-relevant bug that still *runs* — it just reads the wrong field.

That is not a hazard worth facing by hand. Every non-trivial covenant here is
authored with a **stack-tracking assembler**, [`src/stackasm.js`](../src/stackasm.js).

### What it does

`StackAsm` keeps a symbolic model of the main and alt stacks as lists of *names*,
and every operation updates the model as the real interpreter would. You address
values by name; it computes the depth and emits the `OP_PICK` / `OP_ROLL` /
`OP_SWAP` for you.

```js
const asm = new StackAsm(script)
asm.given(['lt4', 'iblob', 'sibBal8', 'sibling', 'preimage'])  // the unlock left these
asm.toAlt()                       // park the preimage; model tracks the altstack too
asm.pick('sibBal8')               // emits the right depth for sibBal8, wherever it is now
asm.bin2num('sibNum')             // top is now a number named sibNum
asm.pick('ownBal8'); asm.bin2num('ownNum'); asm.add('total')
```

The covenant reads as data flow — `pick('sibBal8')`, not `OP_7 OP_PICK` — and the
depths are never wrong, because the model is the single source of truth for where
everything is. `_depth()` throws if you name something that is not on the stack,
so a mistake is a build-time exception, not a silent mis-read on chain.

### Why it is not unit-tested

It has no test file, on purpose. Its correctness is proven **end to end**: a wrong
depth produces a script the real consensus interpreter rejects, and every covenant
built on it carries an adversarial suite that would fail. If `token`'s fourteen
cases are green — the honest merges *and* the inflation attacks that must be
refused — the emitted depths were right. A separate unit test of the assembler
would be testing a model of the thing the interpreter already tests directly.

### The method set

Introducing values: `data(buf, name)`, `num(v, name)`, `given([...])`,
`seedAlt([...])`. Moving: `pick(name)` (copy to top), `roll(name)` (move to top).
Altstack: `toAlt()`, `fromAlt()`, `rename(name)`. Bytes: `splitAt(offset, lo, hi)`,
`split(lo, hi)` (offset from the stack), `cat(name)`, `sizeOf(name, out)`.
Arithmetic: `bin2num`, `num2bin(width, name)`, `add`, `sub`, `mul`, `div`. Checks
(they consume): `equalVerify`, `numEqualVerify`, `verify`, `geVerify`, `leVerify`,
`checkSigVerify`. Hashing: `hash256(name)`, `hash160(name)`. And `raw(op, pop,
push)` for anything not wrapped, with an explicit stack delta so the model stays
honest.

---

## Reading your own script, without a circular constant

A self-recreating covenant must reference its own bytes, and it cannot embed them
— a constant that contains the script changes the script's length, which changes
the constant. The way out is to **read, not embed**: `selfChunk` (see
[clauses.md](clauses.md)) pulls the covenant's own `scriptCode` straight out of the
authenticated preimage, so the script never names itself.

The same principle applies to any constant derived from the script's own size.
`token`'s two-output backtrace needs the byte *stride* of a token output — but the
stride depends on the script length, and hard-coding it would be circular. So it
is computed at runtime: `stride = 8 + size(selfChunk)`. Nothing about the
script's own dimensions is ever written as a literal.

---

## Dispatching branches

**Two branches:** `authenticateThenBranch` (clauses) emits the OP_PUSH_TX preamble
once, above an `OP_IF`, so a two-branch covenant carries the expensive
authentication only once. The unlocking script pushes the branch flag *below* the
preimage; the preamble swaps it up. `htlc`, `titled`, `royalty`, `ticket` and
`token` are built this way.

**Three or more branches:** nesting `OP_IF` around the preimage gets awkward. The
cleaner pattern, used by [`asset`](predicates.md#asset), is to authenticate once,
**park the preimage on the altstack**, then dispatch on a one-byte selector with
the preimage out of the way:

```
OP_DUP <MERGE> OP_EQUAL OP_IF  <merge>  OP_ELSE
OP_DUP <SPLIT> OP_EQUAL OP_IF  <split>  OP_ELSE
                               <transfer>
OP_ENDIF OP_ENDIF
```

Each branch gets a fresh `StackAsm` whose model is seeded with the branch's own
unlock data (`given`) and the parked preimage (`seedAlt(['preimage'])`). Because
the instances are independent and the real runtime stack in each branch is
independent, the models never interfere; each branch just has to leave the same
shape (one true value, empty altstack) for `CLEANSTACK`.

---

## A worked constraint: the backtrace

Putting the pieces together — how `token` proves a sibling's balance, in the
assembler. The spender has pushed the sibling funding tx's opaque input section,
its output section, the claimed balance, and the outpoint; the covenant has to
prove the claim without walking the transaction.

```js
// count = size(outsBlob)/stride, an exact whole number of outputs, 1 or 2
asm.sizeOf('outsBlob', 'outsSize')
asm.pick('outsSize'); asm.pick('stride'); asm.div('count')
asm.pick('count'); asm.pick('stride'); asm.mul('cs'); asm.pick('outsSize'); asm.numEqualVerify()
asm.pick('count'); asm.num2bin(1, 'countByte')      // the output-count byte, derived not trusted

// sibSlice = outsBlob[vout*stride : +stride] must be DUST8 ‖ sibChunk
asm.pick('voutNum'); asm.pick('stride'); asm.mul('offset')
asm.pick('outsBlob'); asm.pick('offset'); asm.split('pre', 'rest')
asm.pick('stride'); asm.split('sibSlice', 'post')
asm.drop(); asm.nip()
asm.data(dustLE(), 'dustE'); asm.pick('sibChunk'); asm.cat('expectedSib'); asm.equalVerify()

// funding = VERSION ‖ iblob ‖ countByte ‖ outsBlob ‖ lt4 ; hash == the sibling's txid
asm.data(VERSION, 'ver'); asm.pick('iblob'); asm.cat('vi')
asm.pick('countByte'); asm.cat('vic'); asm.pick('outsBlob'); asm.cat('vico')
asm.pick('lt4'); asm.size('ltsz'); asm.num(4, 'four'); asm.equalVerify(); asm.cat('funding')
asm.hash256('fhash'); asm.pick('txidB'); asm.equalVerify()
```

Every value is named; not one `OP_PICK` depth is written by hand. That is what
made a 692-byte, two-output, branchless backtrace assemble correctly on the first
run — and what let [`asset`](predicates.md#asset) add ownership on top of it
without the two concerns tangling. See [cross-input.md](cross-input.md) for why
this construction is sound, and [predicates.md](predicates.md#token) for what it
proves.
