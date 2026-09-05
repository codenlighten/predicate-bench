# Verifying off-chain data in Script

Every covenant elsewhere in this bench decides a spend from one of two kinds of
fact: a **key** the spender holds, or the **shape of the spending transaction** —
its outputs, its nLockTime, its sibling inputs. Neither can express *"pay out if
the BSV/USD price closed above 60"* or *"release the insurance if the flight was
cancelled."* Those turn on a fact the chain cannot see. This document is about the
third kind of fact — an **external event, attested by a named third party** — and
the one mechanism that lets a locking script verify it: the **Rabin signature**.

The predicate that puts it to work is [`oracle`](predicates.md#oracle); the signer
is [`src/rabin.js`](../src/rabin.js). It is deployed and claimed on mainnet — the
whole verification runs under consensus and relay policy, not merely offline.

---

## Why `OP_CHECKSIG` cannot do this

The instinct is to have the oracle sign the data with an ordinary ECDSA key and
check it with `OP_CHECKSIG`. It does not work, and the reason is structural rather
than a missing feature.

`OP_CHECKSIG` does not verify a signature against a message you provide. It
verifies a signature against **the sighash of the spending transaction**, which
the *interpreter* computes from the transaction being validated. The message is
not on the stack; it is the transaction itself. There is no opcode that says
"check this signature against those arbitrary bytes." Bitcoin Cash added one —
`OP_CHECKDATASIG` — but **BSV never did**, and post-Genesis it is not available.

So an oracle cannot hand the covenant `sign_ECDSA(message)` and expect
`OP_CHECKSIG` to check it: `OP_CHECKSIG` will compute *this transaction's* sighash
and compare against that, which is unrelated to the oracle's message. (You can
smuggle a fact into a spend this way — the [`rpuzzle`](predicates.md#rpuzzle)
trick commits to a nonce, and an oracle could refuse to co-sign until an event
occurs — but that binds the oracle to *this transaction*, not to a reusable public
statement about the world. It is a different tool.)

The way through is a signature scheme whose **verification is pure arithmetic**,
so the covenant can carry the message itself and check the signature against it
with opcodes Script already has. That scheme is Rabin.

---

## Rabin signatures from first principles

Rabin signing rests on the same hard problem as RSA — factoring — but its
verification is a single squaring, which is exactly what makes it cheap in Script.

**Key.** The oracle picks two primes `p, q ≡ 3 (mod 4)` and publishes
`N = p·q`. The factorisation `(p, q)` is the private key; `N` is public and is
hard-coded into the covenant. (The `≡ 3 (mod 4)` condition is what makes square
roots easy to compute for the signer — see below.)

**Sign.** To sign a message `m`, the oracle wants an `s` with

```
    s² ≡ H(m) (mod N)
```

for a hash `H(m)` reduced mod `N`. Such an `s` exists only when `H(m)` is a
**quadratic residue** mod `N` — a square — which happens for about ¼ of values.
So the oracle appends a small **padding** nonce and tries `H(m ‖ 0)`, `H(m ‖ 1)`,
… until one is a residue (a handful of tries). Then it takes the square root,
which needs the factorisation:

- mod a prime `p ≡ 3 (mod 4)`, a square root of `h` is simply `h^((p+1)/4) mod p`
  — no general algorithm needed, which is the whole reason for that congruence;
- do this mod `p` and mod `q`, then combine the two roots into one mod `N` with
  the **Chinese Remainder Theorem**.

The signature is `(s, padding)`.

**Verify.** Anyone with `N` checks

```
    s² mod N  ==  H(m ‖ padding) mod N
```

No factorisation, no inverse, no elliptic curve — one multiply and two mods. A
forger without `(p, q)` would have to take a square root mod `N` themselves, which
is equivalent to factoring `N`. This is the property the covenant leans on.

All of this is in [`src/rabin.js`](../src/rabin.js): `keygen`, `sign` (the CRT
square root), and `verify` (the reference the covenant reproduces byte-for-byte).

---

## Expanding the hash to the width of N

`H(m)` has to be a number the size of `N` — for the demo key, 512 bits — but
`SHA256` gives only 256. So `H` is an **expanded hash**: several SHA256 blocks
concatenated. The bench uses four, each over the message with a distinct suffix
byte:

```
    H(x) = SHA256(x ‖ 0x01) ‖ SHA256(x ‖ 0x02) ‖ SHA256(x ‖ 0x03) ‖ SHA256(x ‖ 0x04)
```

That is 128 bytes, reduced `mod N` on both sides of the check. The signer and the
covenant must expand identically — a mismatch of one byte in either the block
count or the suffix scheme makes every signature fail. Production Rabin oracles
(sCrypt's, for instance) use the same idea with the block count scaled to the key
width.

---

## The check in Script, step by step

The claim branch of [`oracle`](predicates.md#oracle) builds both sides of
`s² mod N == H(m ‖ pad) mod N` and compares them. The message is `FEED ‖ value`,
and the covenant hard-codes `N`. Written through the [stack
assembler](authoring.md):

**Left side — `s² mod N`:**

```
pick rsig ; bin2num          # s, as a number (unsigned)
pick s ; mul                 # s·s  → up to 128 bytes
push N ; mod                 # s² mod N
```

**Right side — `H(FEED ‖ value ‖ pad) mod N`:**

```
pick msg ; pick pad2 ; cat   # x = msg ‖ padding
pick x ; push OP_1 ; cat ; sha256      # SHA256(x ‖ 0x01)
pick x ; push OP_2 ; cat ; sha256 ; cat   # ‖ SHA256(x ‖ 0x02)
pick x ; push OP_3 ; cat ; sha256 ; cat   # ‖ SHA256(x ‖ 0x03)
pick x ; push OP_4 ; cat ; sha256 ; cat   # ‖ SHA256(x ‖ 0x04)  → 128-byte blob
push 0x00 ; cat ; bin2num    # read the blob unsigned
push N ; mod                 # H mod N
```

**Compare:** `OP_NUMEQUALVERIFY`. If the two disagree, the spend dies here.

Four subtleties, each of which silently breaks the check if missed — the first two
are general to big-number arithmetic in Script, the last two are specific to this
construction:

1. **Read hashes unsigned.** Script numbers are signed little-endian: the high bit
   of the top byte is the sign. The 128-byte hash blob, and `value` inside the
   message, both read **negative** whenever that bit is set — about half the time
   for a hash, and for any `value ≥ 2³¹`. `OP_MOD` on a negative dividend
   truncates toward zero and no longer matches the signer's unsigned reduction. A
   trailing `0x00` byte before `OP_BIN2NUM` forces a positive interpretation. This
   is the same fix the [timelock](predicates.md#timelock) uses for nLockTime, and
   the `value` case was a real bug caught in code review after the first mainnet
   deploy.
2. **Pushing `0x00` is legal under MINIMALDATA.** `OP_0` pushes the *empty* array,
   not a zero byte, so a one-byte `0x00` has no shorter encoding and a direct push
   is minimal. (Only `0x01`–`0x10` and `0x81` are forced to `OP_N`/`OP_1NEGATE`.)
   The block-counter bytes `1..4`, by contrast, *are* forced to `OP_1..OP_4`.
3. **Arithmetic operands must be minimally encoded.** `OP_MUL` and `OP_MOD` reject
   a non-minimal number regardless of policy flags, so everything fed to them goes
   through `OP_BIN2NUM` first, and the hard-coded `N` is emitted in the minimal
   form `rabin.toScriptNum(N)`.
4. **The signature must bind the value, not merely the fact of signing.** Covered
   next — it is the sharpest test in the suite.

---

## Why the value is bound, not just the signature

An oracle attestation is a signature over `FEED ‖ value`. A covenant that checked
only *"the oracle signed **some** value, and the value I was handed clears the
threshold"* would be trivially forgeable: take the oracle's real signature for a
low value, and present it alongside a message that claims a high one.

The suite's `forgeValue` case does exactly that. The oracle genuinely signed
`6000`. The spender presents a message claiming `9999` — above the threshold —
with that same, genuine signature:

```
threshold check:   9999 ≥ 6000            ✓   (passes)
signature check:   s was a root of H(FEED ‖ 6000)
                   covenant recomputes     H(FEED ‖ 9999)
                   s² mod N  ≠  H(FEED ‖ 9999) mod N   ✗   → OP_NUMEQUALVERIFY fails
```

Because the covenant rebuilds the hash over the **presented** message and the
oracle's `s` is a root of the hash over the **signed** message, the two match only
when those messages are identical. The value is bound by construction. A design
that verified the signature over a *stored* value and then trusted a *separately
pushed* value for the comparison would not have this property; keeping them the
same buffer is the point.

---

## The trust model, honestly

Rabin verification proves one thing and nothing more: **these bytes were signed by
the holder of the factorisation of `N`.** Everything else is a matter of how the
covenant is built around it.

- **The oracle is trusted.** It can attest anything; the covenant cannot tell a
  true price from a lie. This is an oracle, not an argument — the mechanism moves
  trust to a named party and makes their statements verifiable, it does not remove
  trust. Splitting that trust is the natural next step (see below).
- **Attestations are public data, and replayable.** A signature over
  `FEED ‖ value` is just bytes; anyone who sees it can put it in a transaction.
  That is why the claim branch **also** requires the winner's own signature — the
  attestation says *what is true*, the key says *who may act on it*. Omit the key
  binding and the first person to see the attestation takes the payout.
- **The message needs everything that scopes the claim.** `FEED ‖ value` here also
  implies a *time* in practice — a real feed message carries a timestamp or round
  number, or an old attestation is replayable forever. The bench's message is
  minimal to isolate the mechanism; a production message is wider.
- **Key size is a parameter, not a property of the design.** The demo key is
  512-bit — factorable by a determined adversary, and chosen only to keep the
  script and this walkthrough small. A production oracle uses 2048+ bits, which
  widens the `N` pushes and the single `OP_MUL` and nothing else; the Script is
  identical in shape.

---

## The shape it enables: a binary option

[`oracle`](predicates.md#oracle) wraps the verifier in a complete, fundable
instrument — two branches on a selector:

- **CLAIM** — winner's signature **and** an oracle attestation of `value ≥
  THRESHOLD` for the named feed. No preimage needed; the winner's `OP_CHECKSIG`
  binds the spend.
- **REFUND** — if the event never happens, the funder reclaims after a deadline,
  gated by the [timelock](predicates.md#timelock) done properly (preimage bound,
  sequence non-final, sign-padded). Without this the option is a one-way trap:
  coins locked forever on an event that did not occur.

The two branches read entirely different unlocking stacks — a Rabin proof on one
side, a preimage on the other — so the stack assembler models each branch from its
own declared layout, the same machinery the [sovereign](predicates.md#sovereign)
descent needed. Note the refund branch does **not** assert `SIGHASH_ALL`, and
correctly so: like `timelock` it reads only the input's own nSequence and
nLockTime, present under every sighash flag. It would need the assertion only if an
output constraint were added to it.

---

## Where this goes next

The binary option is the floor, not the ceiling. Everything above generalises:

- **Numeric settlement — built.** Instead of *winner-takes-all above a threshold*,
  split a pot between two parties as a function of the attested value — a contract
  for difference, a ranged insurance payout. This is
  [`settlement`](predicates.md#settlement): it composes the Rabin verifier here
  (now the shared clause `src/rabinscript.js`) with the **conserved arithmetic** of
  [`token`](predicates.md#token) and the **output-binding** of
  [`covenant`](predicates.md#covenant). The oracle's number drives *how much* each
  side receives, and `hashOutputs` forces exactly those payments — deployed on
  mainnet, where an attestation of `6000` split a pot 50/50 in Script.
- **Split trust — m-of-n oracles — built.** Verify several independent Rabin
  signatures and require a threshold of them to agree, so no single oracle can move
  the coins. This is [`quorum`](predicates.md#quorum): the
  [`multisig`](predicates.md#multisig) idea applied to attestations rather than
  spenders, built on the non-aborting `check` clause and deployed on mainnet as a
  2-of-3. Each slot hard-codes its oracle's modulus, so a quorum needs *distinct*
  oracles — one cannot fill two slots.
- **Oracle-driven state — built.** A self-recreating covenant that consumes an
  attestation each hop and carries the result forward in its own `scriptCode`. This
  is [`ticker`](predicates.md#ticker): [`metered`](predicates.md#metered)'s
  self-recreation fed by the oracle instead of an internal `+1`. It forces a
  problem neither parent has — **replay**: an attestation is public, reusable bytes,
  so the covenant carries a monotonic *round* and refuses any update whose round
  does not exceed the one in its own state. Deployed on mainnet as a full
  `deploy → update → update → redeem` lifecycle.

Each reuses the verifier unchanged; the composition is in what the covenant does
with a *true* number once it has one. All three follow-ons are now built —
[`settlement`](predicates.md#settlement), [`quorum`](predicates.md#quorum),
[`ticker`](predicates.md#ticker) — the numeric, the multi-party, and the stateful
faces of one verifier.

---

## On chain

Deployed and claimed on mainnet with a real attestation — the full
`s² mod N == H(m) mod N`, four `OP_SHA256` blocks and a 128-byte `OP_MUL`, ran
under both consensus and relay policy and the node accepted it. The current bytes
on chain reproduce `buildScript` exactly. See the
[mainnet log](mainnet-log.md#oracle).

See also: [preimage.md](preimage.md) (the other way a script reads its world),
[predicates.md#oracle](predicates.md#oracle) (the catalogue entry),
[pitfalls.md](pitfalls.md) (the sign and MINIMALDATA traps in their general form).
