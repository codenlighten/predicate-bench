# The preimage

Everything in this bench that is more interesting than a hash lock rests on one
idea: a script can be handed a description of the transaction that is spending
it, and can be made to reason about that description.

## Layout

The BIP-143 sighash preimage is a flat byte string with one variable-length
field in the middle:

```
offset  size  field
     0     4  nVersion
     4    32  hashPrevouts
    36    32  hashSequence
    68    36  outpoint (txid 32 || vout 4)
   104   var  scriptLen (CompactSize varint)
     .   var  scriptCode          <-- the locking script being spent
     .     8  value               (satoshis of the input, LE)
     .     4  nSequence           (of THIS input)
     .    32  hashOutputs
     .     4  nLockTime
     .     4  sighashType
```

The head is 104 bytes. The tail is 52. Between them sits `scriptCode`, whose
length depends on the script being spent.

## Offsets are measured from the END

This is the single most important mechanical fact.

Every field before `scriptCode` sits at a fixed offset from the start. Every
field after it sits at a fixed offset from the *end*. Nothing after `scriptCode`
has a stable offset from the start, because `scriptCode` moves.

```
field         bytes from END
sighashType    4
nLockTime      8
hashOutputs   40
nSequence     44
value         52
```

An offset counted from the head is correct for exactly one scriptCode length
and wrong for every other. This is not a subtle bug — it produces a script that
either fails immediately or, worse, silently compares the wrong bytes.

Two ways to take a field from the tail:

```
# Chronicle string opcodes (0xb4/0xb5) — concise
<fromEnd> OP_RIGHT <len> OP_LEFT

# Genesis-era arithmetic — works pre-Chronicle too
OP_SIZE <fromEnd> OP_SUB OP_SPLIT OP_NIP <len> OP_SPLIT OP_DROP
```

`OP_LEFT`/`OP_RIGHT` are **Chronicle** opcodes. Before Chronicle those bytes
were `OP_NOP5`/`OP_NOP6`, and a pre-Chronicle UTXO treats them as no-ops — the
extraction silently does not happen. Chronicle activated at height 943816 and
is long live on mainnet, so either form is correct today; the arithmetic form is
the conservative choice for a library that might touch older UTXOs.

## Binding the preimage: OP_PUSH_TX

A preimage the spender pushed is just bytes the spender chose. On its own it
proves nothing.

```
# NOT a covenant. Proves only that the spender retyped a known value.
OP_HASH256 <constant> OP_EQUALVERIFY
```

The constant was fixed when the locking script was written, so it can only be
the hash of a preimage already known then — which means the spending transaction
was already decided. Every field read out of such a preimage is equally
unconstrained.

`OP_PUSH_TX` makes the interpreter compute the sighash itself. The script
assembles a DER signature in-script over the pushed preimage, using a fixed
generator-derived key, and hands it to `OP_CHECKSIG`. `OP_CHECKSIG` recomputes
the sighash from the actual transaction being validated; the signature only
verifies if the pushed preimage is that transaction's. In this library:

```js
const s = new Script().add(Opcode.OP_DUP)
PushTx.pushTxCore(s)
s.add(Opcode.OP_VERIFY)   // stack: [preimage], now provably this spend's
```

Two consequences worth internalising:

- **No key is involved.** The CHECKSIG is against a fixed generator-derived key,
  not anyone's. Nobody "owns" an OP_PUSH_TX covenant — anyone can spend it who
  satisfies its rules. Custody is by script, not by ownership.
- **The signature must be low-S canonical DER**, and whether it is depends on
  the preimage's bytes. So spending requires *grinding*: vary something in the
  transaction until the derived signature is clean. `nLockTime` is the usual
  nonce, which is why a covenant that also constrains `nLockTime` must grind
  upward from its floor rather than from zero.

## The sighash type is part of the contract

`hashOutputs` means different things under different sighash types:

| type | hashOutputs covers |
|---|---|
| SIGHASH_ALL | every output |
| SIGHASH_SINGLE | only the output at this input's index |
| SIGHASH_NONE | nothing (32 zero bytes) |

A script that constrains `hashOutputs` without pinning the sighash type is
binding something it did not choose. `PushTx.assertSighashAll(s)` fails fast
unless the spend is `SIGHASH_ALL | FORKID` (0x41). Any covenant with an output
clause needs it.

## Reading your own script

`preimage[104 : len-52]` is `scriptLen || scriptCode` — which is byte-for-byte
the second half of a serialized TxOut. A TxOut is:

```
value (8, LE) || scriptLen (varint) || script
```

So a covenant can construct an output paying back into *itself* as:

```
<value - fee, 8-byte LE> || preimage[104 : len-52]
```

with the varint arriving free. This is how a self-recreating covenant escapes
the circularity of needing to contain its own hash. It never learns its own
length or hash; it just copies the framed bytes it was given.

See [predicates.md](predicates.md) for what gets built on top of this.

---

## WP1605 conformance, measured

nChain's PUSHTX white paper — *PUSHTX and its Building Blocks*, WP1605, by Wei
Zhang, created 20/05/2021 and last updated 14/12/2021. The technique itself is
credited in the paper to Y. Chan and D. Kramer at nChain in 2017; the paper is
not theirs, and citing it as "Chan & Kramer 2017" (as this document previously
did) conflates the invention with the write-up.

Its four numbered claims, checked against this implementation rather than
assumed:

| claim | status here |
|---|---|
| **1.** a valid `(r,s)` cannot be moved to another message `m'` *for the same P* | relied upon — this is what makes the pushed preimage trustworthy |
| **2.** the public key `P` must be fixed in the locking script | **yes** in every covenant (`02‖Gx`); **deliberately violated** by `rpuzzle`, and the predicted attack works — see below |
| **3.** the ephemeral key `k` must be fixed | **yes** — `k = 1`, so `r = Gx`, a hard-coded constant |
| **4.** the sighash flag must be fixed | **yes** — `0x41` concatenated into the DER before `OP_CHECKSIG` |

The paper's own recommendation for the keys is exactly what is implemented
here: *"one can choose small values for k and a such as 1... if k = a = 1, then
s = z + Gx mod n"*. Claim 1 is the load-bearing one and it is assumed, not
tested — it rests on double-SHA256 being preimage- and collision-resistant.

### Claim 2 is not theoretical

The paper's reasoning for Claim 2 is constructive: given a valid `(r,s)` and any
chosen message `m'`, set `u' = z'/s` and `v = r/s`, then

```
P' = (R - u'G) / v
```

and `(r,s)` verifies against `P'` on `m'`. `P'` is a curve point nobody knows the
discrete log of, and `OP_CHECKSIG` does not ask for one.

`rpuzzle` fixes `r` and lets the key float, which is precisely the configuration
Claim 2 warns about. The attack is in the suite as a **passing** case: one
signature observed in the mempool, replayed into a different transaction under a
solved-for key. No `k`, no `d`, no private key. See
[predicates.md](predicates.md#rpuzzle).

### Low-S: the paper says policy, the network says mandatory

Remark 4 on page 5 describes the canonical-S requirement as *"a policy rule in
the Bitcoin network"*, adding that nodes *"seem unlikely to accept
alternatives"*.

Measured on BSV mainnet, it is not policy. A high-S signature is refused with

```
16: mandatory-script-verify-flag-failed (Non-canonical signature: S value is unnecessarily high)
```

Code **16** is the node's wording for *invalid*, as distinct from code 64
`non-mandatory-script-verify-flag`, which is what it uses for standardness — and
four other constructions in the same test run did come back as 64. This is the
same finding that produced the fix to `currentConsensusFlags()` in
`@smartledger/bsv` 9.5.0. See
[pitfall 3](pitfalls.md#3-measure-the-flags-dont-reason-about-them).

The paper enforces low-S **in script**, by group subtraction:

```
[toCanonical] := OP_DUP n/2 OP_GREATERTHAN OP_IF n OP_SWAP OP_SUB OP_ENDIF
```

This implementation enforces it **off-chain**, by grinding until `s <= n/2`.
That removes the `n` constant and the branch from the script and moves the cost
to the spender: measured acceptance is about **2%** (399 of 20,000 preimages).

### Where the bytes actually go

The paper's appendix reports *"a 32-byte string would require **124 bytes** of
opcodes to reverse its endianness"*, and that it reverses twice, giving 248
bytes inside the locking script. Its "over 500 bytes" figure is those same 248
counted **twice**, because the locking script travels twice — once as the output
script, and again inside the preimage the unlocking script pushes.

An earlier version of this document read that as a like-for-like comparison and
claimed 248 "not ~500", i.e. that this implementation beat the paper's baseline
on reversals. It does not. The reversal cost is identical, because the technique
is identical:

```
two 32-byte endianness reversals : 248 B   (124 each — the paper's own figure)
gxLe constant + OP_ADD           :  34 B
Gx constant, shared via altstack :  34 B
DER assembly + sighash byte      : ~22 B
-----------------------------------------
stock core                       : 377 B
lean core (mod + NUM2BIN removed): 339 B
```

The paper proposes storing `Gx` and `n` on the alt stack, costing 15 extra
opcodes and saving `(32×2 + 32×2) − 15 = 113` bytes (its appendix separately
estimates "about 200"). Only half of that applies here. The lean core has **no
`n` at all** — the `OP_MOD` is provably dead given the grind's constraints, so
both instances are gone for free rather than alt-stacked. `Gx` is already shared
via the alt stack between the DER r-value and the public key, worth 33 bytes.

### The honest size comparison

The paper quotes several transaction sizes and they are not interchangeable.
1142 bytes, 941 with the `outputsRequest` optimisation, and 828 with alt-stack
storage all describe an **illustrative** script — the paper states plainly that
*"reversing endianness is omitted"* from those. The figure to compare against is
the appendix's tested implementation on Bitcoin SV v1.0.8 regtest: **1415
bytes**.

Against that, `perpetual` — a self-recreating covenant, the same shape as the
paper's PELS — measures:

```
lock 385 B   unlock 547 B   spending transaction 996 B
```

which is a real ~30% improvement, from the two dead-code removals and from
emitting a fixed `30 44 02 20` DER prefix instead of computing the length in
script.

The 290-byte figure elsewhere in these docs is for an `OP_CODESEPARATOR`
covenant and is **not** comparable to a PELS: the separator truncates
`scriptCode`, which is exactly what a self-recreating covenant needs to read.
See [pitfall 7](pitfalls.md#7-op_codeseparator-and-self-reference-cannot-coexist).

### The fields that cannot be predetermined

Table 1 of the paper lists the eleven components of the signed message and marks
three as *infeasible due to circular reference*: item 2 (`hashPrevouts`), item 4
(the input outpoint, though it notes the 4-byte index alone can be fixed), and
item 6 (the previous locking script).

Item 6 is the interesting one, and it is why self-recreating covenants **read**
their own script out of the preimage rather than committing to a hash of it —
see [reading your own script](#reading-your-own-script). The circularity the
paper identifies is exactly the one that construction sidesteps.

It also predicts the termination property these covenants have: *"diminishing
output values can limit total spend iterations."* That is `perpetual` running
out of fee, and `registry`'s `maxTransfers` is the same limit made explicit.
