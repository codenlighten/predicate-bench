# Sizing: one preamble, not two

Script size is not a cosmetic concern in a covenant. It is the fee, and for a
covenant that dictates its own outputs the fee is fixed when the coin is locked
— see [pitfall 17](pitfalls.md#17-a-covenant-that-dictates-outputs-also-dictates-the-fee).
A script that is too big to spend at the prevailing rate is a coin that stops
moving.

Every two-branch covenant here authenticated its preimage **inside each branch**,
so it carried the OP_PUSH_TX preamble twice — and that preamble is the bulk of
the script.

## The obstacle, and the fix

It cannot simply be hoisted above `OP_IF`, because the branch flag is on top of
the stack when the locking script begins: `OP_DUP` would duplicate the flag, not
the preimage. The answer is to push the flag **below** the preimage:

```
unlocking:  ... <flag> <preimage>

locking:    <state> OP_DROP
            OP_DUP <pushTxCore> OP_VERIFY <assertSighashAll>
            OP_SWAP
            OP_IF <branch A> OP_ELSE <branch B> OP_ENDIF
```

The preimage is on top to be authenticated; one `OP_SWAP` brings the flag back
for `OP_IF`. `assertSighashAll` is stack-neutral — `OP_DUP`, last four bytes,
`OP_EQUALVERIFY` — so it does not disturb what sits underneath. Each branch then
begins with exactly the stack it had before, and **the branches themselves do not
change at all**.

## What it bought

387 bytes off every two-branch script — one `pushTxCore` plus one
`assertSighashAll`:

| predicate | before | after | saved |
|---|---|---|---|
| `metered` | 913 B | 526 B | 42% |
| `titled` | 931 B | 544 B | 42% |
| `royalty` | 1028 B | 641 B | 38% |
| `registry` | 979 B | 592 B | 40% |

The transaction-level saving is larger than the script saving, because a
locking script appears **twice** in a spend: once in the output that carries the
successor, and once inside the preimage as `scriptCode`. Measured on chain, the
same predicate performing the same operation before and after:

```
before hoisting   2312 B   lock 979 B
after  hoisting   1539 B   lock 592 B
saved              773 B   (33%)  = 78 sat per spend at 100 sat/kb
```

All 101 cases pass unchanged. That is the point of having them: a restructuring
that touches every stateful predicate is only safe to make when the suite can
tell you the semantics did not move.

## Trimming the core itself

The remaining bulk is `pushTxCore` — 377 bytes, and two thirds of that is a
single unavoidable thing:

| part | bytes |
|---|---|
| two 32-byte endianness flips | 248 |
| everything else | 129 |

`OP_HASH256` emits big-endian, script arithmetic is little-endian, and DER wants
big-endian again. Every byte has to move, and at four script bytes per byte
moved the reversal loop is already near the floor. That part stays.

But two steps in the middle are **dead code** — not usually dead, provably dead:

```
s = (HASH256(preimage) + Gx) mod n,  then NUM2BIN to 32 bytes LE
                          ^^^^^^^         ^^^^^^^^^^^^^^^^^^^^^
```

`sFromPreimage` already refuses any preimage unless **(a)** `z[0]` is in
`0x01..0x7f`, so that `e` read little-endian is positive and minimally encoded —
without which the script needs a sign byte and stops being relayable — and
**(b)** `s <= n/2`, for canonical low-S.

From (a), `e < 0x80 * 2^248 = 2^255`. And `Gx ~ 0.4756 * 2^256`. So

```
e + Gx  <  0.5*2^256 + 0.4756*2^256  =  0.9756 * 2^256  <  n
```

The sum can never reach `n`, so **the mod never reduces anything**. And from (b)
plus the check that `sBE[0] >= 0x01`, `s` lies in `[2^248, n/2]`, whose minimal
little-endian encoding is exactly 32 bytes — so **`OP_NUM2BIN(32)` is a no-op**
on every value that can reach it.

Measured over 200,000 preimages: 4124 accepted by the grind, **0** where the mod
would have fired, **0** where NUM2BIN would have padded.

Both removals are safe in the strong direction. A preimage violating the
assumptions produces a wrong-length buffer, the 31-way `OP_SPLIT` reversal fails
with `INVALID_SPLIT_RANGE`, and the spend is refused. Removing them can only make
a spend harder to construct, never easier to forge — confirmed directly: a valid
preimage from a *different* transaction is still refused, and a one-byte-flipped
preimage still fails.

377 → 339 bytes, and 38 off every OP_PUSH_TX predicate. `perpetual`, which had
been using the library's PELS core, was rebuilt on the shared primitives and
came down from 423 B to 385 B with it.

## What was measured and kept anyway

`assertSighashAll` is **also** redundant: the core pins the flag implicitly,
since its synthetic signature carries `0x41` and `OP_CHECKSIG` derives the
sighash using that byte. Removing it, every SIGHASH_NONE and SIGHASH_SINGLE
refusal in the suite still passes.

It stays. Twelve bytes buys a fail-fast error at the top of the script instead of
a confusing failure deep inside `OP_CHECKSIG`, and it survives a refactor of the
core — which is not hypothetical, since this section is one.

## Three generations, measured on chain

The same registry transfer, broadcast three times:

```
original (per-branch core)   2312 B tx   979 B lock   232 sat fee
hoisted core                 1539 B tx   592 B lock   154 sat fee   (-33%)
hoisted + lean core          1462 B tx   554 B lock   147 sat fee   (-37%)
```

For a covenant whose fee is fixed at lock time, 37% off is not a fee saving so
much as a lifetime extension: the same balance survives roughly half as many
hops again before it can no longer pay to move.

---

---

# OP_CODESEPARATOR: the saving that lands twice

Everything above shrinks the *locking* script. This shrinks the **preimage**,
which is a bigger prize, because the preimage is the unlocking script — so the
saving lands twice in a spend.

The sighash's `scriptCode` is the script from the last executed
`OP_CODESEPARATOR` to the end. Put one immediately before the `OP_CHECKSIG` in
the OP_PUSH_TX core and the ~340 bytes of endianness-flipping machinery that
precede it are excluded from the digest. Measured on an output covenant:

```
without   scriptCode 384 B   preimage 543 B   tx 633 B
with      scriptCode  46 B   preimage 203 B   tx 290 B   (-54%)
```

**One byte of locking script for a 54% smaller transaction.** The technique is
sCrypt's — its `checkPreimageOCS` variants do exactly this.

## Two conditions, and the second is the one that bites

**The spender must compute the preimage over the truncated script**, from just
after the separator, or the two digests will not agree. `pushtx.subscript()`
returns it.

**Never on a self-recreating covenant.** Those read their own bytes out of the
preimage's `scriptCode` to rebuild themselves — see
[preimage.md](preimage.md#reading-your-own-script). Truncating it means the
slice `preimage[104 : len-52]` is a tail rather than the script, so the covenant
rebuilds the wrong thing and the output can never match `hashOutputs`. On
`perpetual` the separator would leave **2 bytes where 385 are needed**.

So the technique splits the predicates cleanly:

| reads | OCS |
|---|---|
| tail fields only — nLockTime, hashOutputs, value | **yes**, large win |
| its own scriptCode, to rebuild itself | **no**, breaks entirely |

There is a smaller trade alongside it. The signature now commits to less of the
locking script, so anything distinguishing one covenant from another has to live
*after* the separator. For these predicates it does — the committed constants
all sit in the logic that follows the core.

---

# The Optimal core: 85 bytes instead of 339

Everything above treats the two 32-byte endianness reversals as irreducible.
They are — but only if you insist on `a = 1`.

`OP_HASH256` gives `H`, 32 bytes big-endian, and `e` is `H` read as a big-endian
integer. `OP_BIN2NUM` reads those *same bytes* as a **little-endian** script
number. `OP_1ADD` adds one at the little-endian low end, and `<32> OP_NUM2BIN`
writes it back — which is `H` with **byte 0 incremented**. Read back as the DER
`s`, byte 0 is the *most* significant. So four opcodes compute:

```
s = e + 2^248
```

ECDSA with `k = 1` gives `s = e + r·a`, and `r = Gx`. So the construction is
sound for the private key satisfying `r·a = 2^248`:

```
a = 2^248 · Gx⁻¹ mod n
```

**The byte-order mismatch is not fought, it is absorbed into the key.** Verified:
`Gx · a mod n` equals `2^248` exactly, and the derived public key is fixed and
hard-coded like `Gx` — malleability requires it (WP1605 Claim 2).

```
classic (lean) core : 339 B
optimal core        :  85 B    -75%
```

## The cost moves off-chain, and it moves down

Classic guarantees low-S compliance in script, by group-order subtraction.
Optimal delegates it to the spender's grind, with four conditions the classic
core handled in opcodes:

| condition | why |
|---|---|
| `H[31] < 0x80` | or `OP_BIN2NUM` reads the number as **negative** |
| `H[0] < 0xff` | or incrementing byte 0 carries, and `s` is not `H`-with-a-bump |
| `s ≤ n/2` | low-S, which classic enforced by subtraction |
| `sBE[0]` in `1..0x7f` | valid fixed-length DER |

The literature frames this as a trade — smaller script, more grinding. Measured
here, it is not a trade at all:

```
grind acceptance   optimal 25.0%    classic 2.0%
```

Optimal is **cheaper to spend as well as smaller**, because classic's low-S
condition (`s = e + Gx` with `Gx ≈ 0.476n`) forces `e` into a narrow window,
while optimal's offset of `2^248` barely moves it.

## Both optimisations, and where the separator goes

They compound, but only with the separator placed exactly right — immediately
before `OP_CHECKSIG`, as late as it can go. One chunk earlier leaves the
public-key push inside `scriptCode`, and the optimal core pushes its 33-byte key
inline rather than fetching it from the altstack, so that alone costs 34 bytes
of preimage in every spend.

An output covenant, four builds:

| build | lock | preimage | tx | grind |
|---|---|---|---|---|
| classic | 384 B | 543 B | 633 B | 25 |
| classic + OCS | 385 B | 203 B | 290 B | 73 |
| optimal | 130 B | 287 B | 377 B | 4 |
| **optimal + OCS** | **131 B** | **202 B** | **289 B** | **4** |

**66% off the locking script and 54% off the transaction**, at a quarter of the
grinding. The separator still cannot be used on a self-recreating covenant — see
[pitfall 7](pitfalls.md#7-op_codeseparator-and-self-reference-cannot-coexist) —
but the optimal core can, and is a pure win there.
