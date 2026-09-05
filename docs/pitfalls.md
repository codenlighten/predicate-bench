# Pitfalls

Every entry here cost either a real broadcast, a stranded output, or a bug that
verified locally and failed on the network. They are ordered by how expensive
they are to learn the hard way.

## 1. Consensus-valid is not relayable

`Interpreter.verify()` under `currentConsensusFlags()` answers "would a block
containing this be valid". It does **not** answer "will a node relay this".
Nodes additionally enforce standardness policy, and `SCRIPT_VERIFY_MINIMALDATA`
is not in the consensus flag word.

A timelock covenant verified locally and mainnet refused it:

```
non-mandatory-script-verify-flag (Non-minimally encoded script number)
```

`non-mandatory` in that message is the tell: the script is valid, the
transaction is unrelayable.

**Cause.** Appending `0x00` to make `nLockTime` unsigned leaves trailing zeros —
964000 becomes `a0b50e0000`, a non-minimally encoded script number.

**Fix.** `OP_BIN2NUM` after the pad. It re-encodes minimally while keeping the
sign fix: a value whose high bit is set keeps its pad, one whose high bit is
clear loses it.

**Rule.** Verify under `currentConsensusFlags() | SCRIPT_VERIFY_MINIMALDATA`
before broadcasting. Note that passing explicit flags enables FORKID, which then
requires the satoshis argument — the undefined-flags path strips FORKID instead,
which is why omitting flags works without it.

**This is not retryable.** A locking script is immutable once funded. The
covenant at `865288a8…` can only be spent by producing that same non-minimal
number, and no `nLockTime` below `0x80000000` avoids it. Those 1000 satoshis are
unreachable through normal relay until 2038.

## 2. Consensus hides more than MINIMALDATA — CLEANSTACK too

The same lesson, learned twice, for 3000 satoshis total.

A rebuilt covenant verified locally and mainnet refused it:

```
non-mandatory-script-verify-flag (Script did not clean its stack)
```

`SCRIPT_VERIFY_CLEANSTACK` requires **exactly one** item on the stack after
evaluation, and like MINIMALDATA it is standardness policy, absent from the
consensus flag word.

**Cause.** A helper already did the `OP_DUP` on the preimage and the caller
added a second one, leaving a stray 545-byte preimage under the result. Trivial,
invisible to consensus, and permanent: the extra copy comes from the *locking*
script, so no unlocking script can clean it up. Those coins cannot be spent
through normal relay.

**Fix.** Define what a node will actually relay once, in one place, and point the
harness, the tracer and the broadcast path at it:

```js
consensus | MINIMALDATA | CLEANSTACK | SIGPUSHONLY | LOW_S | NULLFAIL
```

Verifying under consensus alone is not a smaller check, it is a different one.
Every missing bit costs a broadcast to discover.

## 3. Measure the flags; don't reason about them

Twice the hand-written flag list was wrong in a way that cost coins, so it is
worth checking rather than thinking harder. It can be: build a transaction that
is **consensus-valid but violates exactly one standardness rule**, broadcast it,
and read what the node says.

**The probes are free.** A refused transaction never touches the chain, so the
funding coin is untouched and reusable. Violating probes go first; the baseline
goes last, and its acceptance is what makes the refusals attributable to the
violations rather than to the coin, the key or the fee.

A probe only means something if it isolates one rule, so each is checked locally
first: consensus must accept it and `consensus | thatFlag` must reject it.

Measured on mainnet. Every one of these was broadcast and the node's own answer
recorded:

| rule | the node's message | verdict |
|---|---|---|
| SIGPUSHONLY | `Only non-push operators allowed in signatures` | **code 16 — mandatory** |
| LOW_S | `S value is unnecessarily high` | **code 16 — mandatory** |
| NULLFAIL | `Signature must be zero for failed CHECK(MULTI)SIG operation` | **code 16 — mandatory** |
| MINIMALDATA | `Data push larger than necessary` | code 64 — policy |
| CLEANSTACK | `Script did not clean its stack` | code 64 — policy |
| DISCOURAGE_UPGRADABLE_NOPS | `NOPx reserved for soft-fork upgrades` | code 64 — policy |
| NULLDUMMY | `Dummy CHECKMULTISIG argument must be zero` | code 64 — policy |
| *baseline* | accepted | the control |

Two findings, neither reachable by reading.

**Three rules are mandatory, and the library called none of them consensus.**
`mandatory-script-verify-flag-failed` means the node judged the script
*invalid*, not merely non-standard — yet `currentConsensusFlags()` contained
neither SIGPUSHONLY, nor LOW_S, nor NULLFAIL, so a script verified under that
flag word could be invalid rather than just unrelayable.

Reported as
[smartledger-bsv#152](https://github.com/codenlighten/smartledger-bsv/issues/152)
and fixed in **9.5.0**. Four of that library's own tests had been relying on the
permissive default — they verified with non-push unlocking scripts — which is
the failure mode its `currentConsensusFlags()` docblock already described:
wrong in the direction nothing testing the library against itself can see.

**Two enforced rules were missing from the hand-written list.**
`DISCOURAGE_UPGRADABLE_NOPS` and `NULLDUMMY` are both enforced and neither was
in it. A covenant using `OP_NOP1/9/10`, or a multisig with a non-empty dummy,
would have passed every local check and been refused by the network — the same
shape as the two mistakes that cost 3000 satoshis, caught this time for the
price of fees.

All seven bits are now measured rather than assumed.

### Probing a rule that needs a deployed script

Four of those are isolatable from a scriptSig. Three are not —
`DISCOURAGE_UPGRADABLE_NOPS`, `NULLFAIL` and `NULLDUMMY` all need the offending
construct inside a **locking** script. Put a NOP in the unlocking script and
SIGPUSHONLY — which is *mandatory* here — fails first, so the answer would be
about the wrong rule.

Deploying a probe normally means risking the stake: if the rule is enforced, the
output is unspendable and the coins are gone.

An escape branch removes the risk entirely:

```
OP_IF <the thing being tested> OP_ENDIF OP_1
```

Unlock with `OP_1` and the construct executes — that is the probe. Unlock with
`OP_0` and it is skipped — that is how the coins come back when the answer is
"refused". The measurement costs only fees.

The same shape carried all three deployed probes:

```
NOPs      OP_IF OP_NOP1 OP_ENDIF OP_1                                    4 B
NULLFAIL  OP_IF <pubkey> OP_CHECKSIG OP_NOT OP_ELSE OP_DROP OP_1 OP_ENDIF  41 B
NULLDUMMY OP_IF OP_1 <pubkey> OP_1 OP_CHECKMULTISIG OP_ELSE OP_2DROP OP_1 OP_ENDIF  42 B
```

Each was refused, and each escape branch returned the coins. Total cost across
all three: the fees.

The two message forms are the finding. `mandatory` means the node judged the
script invalid, not merely non-standard — and `currentConsensusFlags()` contains
**neither** SIGPUSHONLY nor LOW_S. A script verified only under that flag word
can therefore be not just unrelayable but invalid.

Both happened to be in the hand-written policy list already. That was luck, and
luck is the thing this pitfall exists to stop relying on.

## 4. BSV holds non-final transactions; it does not reject them

A timelock deployed with a floor two blocks in the future, then spent
immediately, was **accepted** for relay:

```
script verdict (local): VALID
network: ACCEPTED bd427165cb0cd8c4…
```

That is not a broken lock. BSV nodes keep time-locked transactions in a separate
**non-final pool** and release them once they become final, rather than refusing
them. The transaction sat unmined with `nLockTime 965010` above a tip of 965008,
and entered the normal mempool the moment the chain reached 965010.

The observable states, measured:

| tip | `/tx/{txid}` | coins in the spender's UTXO set |
|---|---|---|
| below the floor | **404** — held in the non-final pool | no |
| at or above it | 200 with no block fields — normal mempool | **yes** |

This matters for testing. "Broadcast was accepted" does **not** mean a timelock
failed, and `confirmations > 0` is not a release signal — it stays undefined
until a block is found, well after the lock opens. Detect release by whether the
coins actually became spendable.

## 5. Grinding nLockTime destroys the lock you asked for

OP_PUSH_TX needs a preimage whose in-script signature is clean low-S DER, which
means grinding some malleable field. **Which** field is not a free choice.

Grinding `nLockTime` moves the unlock time itself, one unit per attempt. Against
a timestamp floor that is ~40 seconds of drift and invisible. Against a **height**
floor it is one whole block per attempt: a typical ~40-try grind turns a
one-block lock into roughly seven hours, silently, and the caller never asked
for it.

The input's sequence is malleable too, and a correct timelock already requires it
to be non-final. Sweep it down from `0xfffffffe` instead: the lock stays exactly
where it was set.

```
nLockTime : 965010   exactly the floor, no drift
sequence  : 0xffffffee   non-final, carried the grind
```

Fall back to grinding `nLockTime` only when a caller has deliberately pinned a
*final* sequence — the case that tests the guard — so that choice is not
silently overwritten.

## 6. OP_CHECKLOCKTIMEVERIFY does not work on BSV

Genesis reverted it to `OP_NOP2` for every output created after 2020. The
[BSV wiki](https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script)
lists it under *"Used NOP opcode identifiers"* as **NO OPERATION**, with the old
semantics applying only to "UTXOs that pre-date genesis". Same for
`OP_CHECKSEQUENCEVERIFY` (`OP_NOP3`).

This is worse than an unsupported opcode, because it fails in two directions at
once:

```
script: ffc99a3b OP_NOP2 OP_DROP OP_1      a floor of 999999999

consensus (as verify() defaults)   SPENDS (the lock enforces nothing)
+ CHECKLOCKTIMEVERIFY              SPENDS (the lock enforces nothing)
our policy set                     refused (SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS)
```

A floor of 999,999,999 spends with `nLockTime` at **0**. Setting the
`CHECKLOCKTIMEVERIFY` flag does not help — `isAfterGenesis()` short-circuits it.
And broadcast to mainnet, the same script is refused as a discouraged upgradable
NOP.

**Unenforced and unrelayable.** It looks like a timelock, enforces nothing, and
cannot be broadcast. Anyone porting a Bitcoin contract will reach for it first.

The wiki and the measurement describe different layers and both are true:
consensus *ignores* the opcode (the wiki's "does not mark transaction as
invalid"), while relay policy *refuses* it (code 64, non-mandatory). A NOP
script is minable but not relayable.

Use a preimage-split timelock instead — see [timelock](predicates.md#timelock)
and [htlc](predicates.md#htlc). It costs about 340 bytes more, which is the real
price of the opcode's removal.

## 7. OP_CODESEPARATOR and self-reference cannot coexist

`OP_CODESEPARATOR` before the `OP_CHECKSIG` shrinks the preimage dramatically —
54% off a transaction for one byte of locking script, see
[sizing.md](sizing.md#op_codeseparator-the-saving-that-lands-twice).

It also silently breaks any covenant that reads its own script. This is worth
being explicit about because the combination appears in circulation — a
"self-modifying UTXO" sketch with `… OP_CODESEPARATOR OP_CHECKSIG` in a contract
whose first step is "introspect scriptCode from the preimage". Built and
measured, that exact shape does not work:

```
without a separator      lock 385B  scriptCode 385B  RECREATES ITSELF
WITH OP_CODESEPARATOR    lock 386B  scriptCode  46B  refused (SCRIPT_ERR_EVAL_FALSE_IN_STACK)
```
 Those take
`preimage[104 : len-52]` as `scriptlen || scriptCode` to rebuild themselves; with
a separator that slice is a *tail*, so the successor they build is not the script
they are. On `perpetual` it would leave 2 bytes where 385 are needed, and the
output could never match `hashOutputs`.

Nothing warns about this. The script is well-formed, the preimage authenticates,
and the covenant simply cannot be spent.

## 8. The sighash flag decides what the covenant commits to

nChain's WP1605 suggests `SIGHASH_SINGLE|ANYONECANPAY` for fee flexibility: it
lets a counterparty add funding inputs and change outputs without invalidating
the authorisation. That is exactly what it does, and exactly the problem.

Barbacovi & Larraia put the other side of it — their integrity mechanism
prevents replay *"only if implemented using the flag sighash all. In case other
flags are used, the replay attack can still be carried out."*

Both are correct. Demonstrated:

```
original spend, 1 output      : VALID
preimages identical           : true
the SAME preimage on tx B     : VALID — replayed

tx A outputs: 4000
tx B outputs: 4000, 500   <- 500 sat the covenant never authorised
```

Under `SIGHASH_SINGLE|ANYONECANPAY` the preimage commits to this input's
outpoint, script, value and sequence, and to the output at the same index — and
to **nothing else**. `ANYONECANPAY` zeroes `hashPrevouts` and `hashSequence`;
`SINGLE` narrows `hashOutputs` to one output. So a transaction that keeps that
input and that output, and changes everything around them, produces a
**byte-identical preimage**. The same authorisation spends both.

That is the flexibility, seen from the attacker's side. Choose the flag by what
the covenant must be a commitment to, not by convenience:

| flag | commits to | use when |
|---|---|---|
| `SIGHASH_ALL` | the whole spending transaction | the covenant constrains outputs — every predicate here |
| `SINGLE\|ANYONECANPAY` | this input, and one output | a counterparty must be free to add inputs and change |

**Pinning the flag has three independent justifications**, which is why
`assertSighashAll` stays even though the core already fixes it: WP1605's
Claim 4 (fix the SIGHASH flag to prevent unintended modification), the replay
result above, and fail-fast diagnosis.

## 9. Never hand-assemble era flags

The size and number limits an interpreter applies are derived from era bits, and
the constant you would reach for is not the one that lifts them.
`SCRIPT_GENESIS` is named "GENESIS", but the 520-byte push cap reads
`isAfterGenesis()`, which tests `SCRIPT_UTXO_AFTER_GENESIS` and nothing else. A
flag word carrying `SCRIPT_GENESIS` alone still gets pre-Genesis caps, still
fails with `PUSH_SIZE`, and the error names the push rather than the flags.

**Rule.** Omit the `flags` argument and let the interpreter resolve current
mainnet, or pass `Interpreter.mainnetFlags()`. Only hand-assemble when
deliberately testing a historical era.

## 10. nLockTime is a floor, never a ceiling

`nLockTime` can express "no earlier than". It can never express "no later than".

A transaction that becomes minable stays minable — nothing expires. So a script
demanding `nLockTime <= T` is satisfied by a spender setting `nLockTime` to 0
and broadcasting years later. Deadlines need a competing spend path that opens
at T, or a pre-signed transaction held by a counterparty. Not a script check.

## 11. Reading nLockTime without reading nSequence

`nLockTime` is **inert** when the input is final (`nSequence == 0xffffffff`).
Consensus skips the locktime check entirely, so the transaction is minable
immediately whatever `nLockTime` says.

A script that reads `nLockTime` alone is reading a number the spender may write
freely. Demonstrated against a real covenant: with a final sequence, the script
passed and the transaction was minable at once.

`OP_CHECKLOCKTIMEVERIFY` checks the sequence for you. Preimage splitting does
not. Testing this one input is sufficient — one non-final input makes the whole
transaction non-final.

## 12. The sign bit in nLockTime

`nLockTime` is a little-endian uint32. Script numbers carry sign in the high bit
of the last byte. From `0x80000000` — 19 January 2038 — the raw four bytes read
back **negative**, and a `>= floor` comparison silently evaluates false for
everyone, locking the coin forever.

Append `0x00`, then `OP_BIN2NUM` (see pitfall 1).

## 13. Client-side checks that are not the network's

`tx.serialize()` runs heuristics that a custom script defeats:

- **isFullySigned** cannot read an unrecognised script kind and refuses outright.
- **dustOutputs** refuses anything under 546 satoshis — but BSV removed the dust
  limit from node policy. A 450-satoshi output relayed fine when tested.

Neither is consensus and neither is relay policy. Disable them and let the
Interpreter run and the node be the authorities. Verify the claim before
repeating it; the dust assertion here was wrong until it was actually tested.

## 14. WhatsOnChain's unspent index lags *and flaps*

It does not merely trail mempool spends. Three consecutive calls returned the
stale set, then the correct set, then an empty one. Building from the stale set
produces a transaction double-spending an input already committed
(`txn-mempool-conflict`); building from the empty one reports "no UTXOs" for a
funded wallet.

**Fix.** Track your own spent outpoints and your own outputs locally, and merge
the API in rather than trusting it. A single-spender wallet knows exactly what
it created.

## 15. Decide what you will record before the irreversible step

`unlock` once computed a covenant's successor UTXO *after* `woc.broadcast()`,
referencing variables scoped to another function. The ReferenceError landed
after the transaction was already on chain: the coin had moved and nothing local
knew where.

A covenant output is owned by no wallet. Only the script can spend it, so losing
the record is losing the coins. Recovery meant refetching the raw transaction and
rebuilding the predicted successor script to identify the output.

**Rule.** Derive the follow-up state first, carry it into the broadcast, then
record. Wrap post-broadcast bookkeeping so a failure prints the txid and says
plainly that it must be recorded by hand. Error handling gets *louder* after the
irreversible step, not quieter.

## 16. Command-line parameters are strings

`notBefore + 1` on `"800000"` is `"8000001"` — a valid nLockTime ten times
further out, with no error anywhere. Coerce numeric-looking values at the
boundary.

## 17. A covenant that dictates outputs also dictates the fee

If `hashOutputs` commits to the output set, the fee is the remainder — not a
rate you tune afterwards. Trimming an output to pay a different fee changes the
hash and the coin stops being spendable at all. Paying *less* than committed
fails exactly as hard as skimming.

Consequence: the fee is fixed when the coin is locked. If network rates ever
exceed it, the coin stops moving.

**The way out is to pin a prefix, not the whole set.** Build outputs 0..k in
script, concatenate a tail the spender pushes, and hash the concatenation. The
tail needs no validation of any kind: `hashOutputs` already covers every output,
so bytes that are not the transaction's real remaining outputs hash to something
else and the spend dies. Two opcodes — `OP_ROT OP_CAT` — and the covenant works
alongside ordinary funding inputs with change. `ticket` does this; the older
covenants here do not, which is why their fees are frozen at mint.

## 18. Give a terminating covenant an exit branch

A self-recreating covenant that shrinks by a fee each hop **terminates**. It runs
out of hops with value still in it, and with no exit path that remainder is
unspendable forever.

Two branches with exactly complementary guards (`counter < max` /
`counter >= max`) partition the state space: no state is stuck, and no state
opens both paths. The meter expires into a settlement rather than a burn.

## 19. One explorer is a single point of failure that does not announce itself

WhatsOnChain's free tier began returning 429 to every request after a run of
broadcasts. With one source, `utxos()` reported an **empty wallet** rather than
an error — and "no coins" and "nobody would tell me" lead to very different
mistakes.

Query more than one explorer and report which answered. Note that a pruned
explorer is a cross-check, not a replacement: Bitails 404'd on transactions
WhatsOnChain still served, so a zero from it means nothing on its own.

## 20. `.change()` silently drops a dust-sized change output

A deploy consumed two inputs totalling 1636 satoshis to fund a 1500-satoshi
covenant. The expected 136-satoshi change output does not exist: bsv omits it
when it would be below the dust threshold, and the whole remainder became fee.

The wallet then looked empty while an API still reported a stale balance. Read
the actual transaction rather than the balance endpoint when the two disagree.

## 21. Fixed-width state, or the offsets move

State carried inside a script must be a fixed-width push. A variable-width one
changes the script's length, which changes its `scriptLen` varint, which shifts
every offset the script uses to find itself — and the script rebuilds garbage
that hashes to nothing. An unspendable coin, silently.

Check it: diff the script at two state values. Exactly the state bytes should
differ, and the lengths must match.

Related: a script reading its own bytes must know its varint width. The
implementations here assume 3 bytes (scripts of 253..65535) and **assert** the
built script falls in that range rather than trusting it.

## 22. `LOW_S` normalisation negates a recovered nonce

Any scheme that recovers an ECDSA nonce from a broadcast signature —
`k = s⁻¹(e + r·d)`, the mechanism behind R-puzzle key release — has to reckon
with the fact that `s` is not the value the signer computed.

BSV enforces `LOW_S` as a **mandatory** rule: a high-`s` signature comes back
`16: mandatory-script-verify-flag-failed`, invalid rather than merely
unrelayable. So the signer rewrites `s` to `N - s` whenever it lands in the
upper half, and the rearrangement then returns `N - k` instead of `k`.

Both values are consistent with the same `r`, since `kG` and `(N-k)G` share an
x-coordinate. The signature carries nothing that distinguishes them.

The failure is that it works about half the time. A first test passes, the
scheme looks sound, and every other segment thereafter decrypts to noise. Reduce
to a canonical representative — `min(k, N-k)` — on both sides:

```js
const canonical = (k) => (k.cmp(N.shrn(1)) > 0 ? N.sub(k) : k)
```

`npm run selftest:nonce` walks nonces until it has observed both branches, so it
fails rather than passing on whichever one it happened to draw. Related:
[pitfall 3](#3-currentconsensusflags-is-not-what-a-node-enforces) — `LOW_S` is
one of the three rules `currentConsensusFlags()` used to omit.

## 23. hashPrevouts reverses the txid, and a symmetric test hides it

A covenant that reads `hashPrevouts` (item 2) to reason about sibling inputs has
to reconstruct each outpoint as the 36 bytes the sighash actually commits to:

```
reverse(prevTxId) ‖ vout   (4-byte little-endian)
```

The reversal is the trap. bsv holds `prevTxId` in **display** order — the hex you
read on an explorer — and reverses it to internal little-endian only when it
serialises the outpoint into the preimage. So the bytes inside `hashPrevouts` are
the txid *backwards* relative to what `input.prevTxId` hands you.

This one nearly shipped wrong. The first probe used `Buffer.alloc(32, 7)` and
`Buffer.alloc(32, 9)` as test txids and the reconstruction matched `hashPrevouts`
perfectly — because a buffer of identical bytes is its own reverse. The bug only
appears with an asymmetric txid, which is every real one. The fix, and the
lesson: **never test a byte-order-sensitive path with a palindromic fixture.**
`companion`'s cases use real non-repeating txids for exactly this reason.

The same reversal applies to item 4 (the input's own outpoint) and to any
per-input outpoint a covenant reconstructs.

## 24. A companion covenant must not let its deploy spend the companion

A `companion` covenant hard-codes the outpoint of a sibling that must be
co-spent. If that sibling is an ordinary wallet UTXO and the deploy transaction
is funded by automatic coin selection, the selection can pick the companion
itself to pay for the deploy — destroying it in the same transaction that commits
to it.

The covenant is then locked to a companion that no longer exists. It is
script-valid and on chain, so nothing flags it; it is simply unspendable, because
its one spending path requires an input that can never be present again. 1000
satoshis went this way once.

**Fix.** Explicit coin control. Mint the companion in its own output and fund the
deploy from a *different* one, so no coin-selection heuristic can consume the
thing the covenant depends on. The general rule: whenever a covenant commits to
an external outpoint, that outpoint's lifetime is now part of the covenant's
correctness, and the deploy is the first place it can be violated.

## 25. OP_CHECKSIG verifies the transaction, not a message

The first instinct for an oracle contract is to have the oracle sign the data with
an ECDSA key and check it with `OP_CHECKSIG`. It cannot work, and the reason is
structural, not a missing feature.

`OP_CHECKSIG` does not take a message off the stack. It verifies a signature
against **the sighash of the spending transaction**, which the interpreter
computes itself from the transaction being validated. There is no opcode that
checks a signature against arbitrary pushed bytes. Bitcoin Cash added one,
`OP_CHECKDATASIG`; **BSV never did**, and post-Genesis it is unavailable.

So an oracle's `sign_ECDSA(message)` is uncheckable in Script: `OP_CHECKSIG` will
compare it against *this transaction's* sighash — unrelated to the message — and
fail. Anyone porting a "the contract checks the oracle's signature" design from a
chain with `OP_CHECKDATASIG` reaches for this first, and it silently does the
wrong thing.

**Fix.** Use a signature scheme whose verification is arithmetic the covenant can
run over a message it carries itself — a **Rabin signature**, checked as
`s² mod N == H(m) mod N` with `OP_MUL` and `OP_MOD`. See
[oracle.md](oracle.md) and [`oracle`](predicates.md#oracle). The one genuinely
new cost is reading big numbers unsigned (a `0x00` pad before `OP_BIN2NUM`), the
same sign trap as [12](#12-the-sign-bit-in-nlocktime) in another guise.

## 26. A fixed output-count backtrace strands a coin whose parent has change

A covenant that proves something about its **parent transaction** by rebuilding
it — [`lineage`](predicates.md#lineage), [`conserve`](predicates.md#conserve) —
reconstructs the parent from its parts (`version ‖ inputs ‖ outputs ‖ locktime`)
and hashes it to the parent's txid. If the script hard-codes the parent's
**output count** — say `OP_2`, because the design mints exactly two coins — then
the parent must have *exactly* that many outputs, forever. A parent with one more
output does not rebuild to its real txid, and the coins it created **cannot be
spent by any witness** — an unforgeable hash will not match.

This is exactly how the first `conserve` genesis stranded its pair. The genesis
transaction was funded from the wallet and given a `.change()` output, so it had
**three** outputs (side 0, side 1, change) — but the coins' covenant rebuilt their
parent assuming **two**. `HASH256(version ‖ inputs ‖ 0x02 ‖ side0 ‖ side1 ‖
locktime)` is not the txid of a three-output transaction, so `54c9…`'s predecessor
`63c8…` holds 4000 satoshis behind coins no transaction can ever satisfy. Consensus
is fine with them; they are simply unspendable, like the two strandings of
[pitfall 1](#1-consensus-valid-is-not-relayable) and
[pitfall 2](#2-consensus-hides-more-than-minimaldata--cleanstack-too).

**Fix.** Make the backtrace count-agnostic: fold the output count into the inputs
blob the spender pushes, read the first *k* outputs it actually needs, and let the
rest ride in an unverified `pTail`. Then a parent may carry a change output — or
any trailing outputs — and still rebuild to its txid. `conserve` does this, so its
genesis and every rebalance can be funded the ordinary way, with change. The
general rule: **never hard-code a transaction's shape you do not control.** A
funding wallet controls whether there is change; the covenant must not assume there
is not.

## 27. A preimage nLockTime check must pin the domain, not just the magnitude

A hand-rolled timelock reads `nLockTime` from the preimage and requires it `≥ floor`.
But `nLockTime` is overloaded: BIP-65 reads a value **below 500,000,000** as a *block
height* and one **at or above** it as a *unix timestamp*. A bare numeric `nLockTime ≥
floor` on a **height** floor — say `900000` — is therefore also satisfied by any past
**timestamp**, say `1_600_000_000`: it is numerically far larger, so the comparison
passes, *and* it makes the input final immediately, so the "lock" is no lock at all.

For a refund or timeout branch this is exploitable whenever spending **early**
advantages someone. In [`market`](predicates.md#market) the refund splits the pot
50/50; a party who is about to *lose* the oracle settlement could set `nLockTime` to a
past timestamp, satisfy `≥ 900000` numerically, and grab the refund *now* — before the
deadline height, defeating winner-take-all.

**Fix.** Pin the **domain** as well as the magnitude: when the floor is a height,
require the presented `nLockTime` to also be a height (`< 500,000,000`); when it is a
timestamp, require a timestamp. This is exactly what `OP_CHECKLOCKTIMEVERIFY` does
internally (and one more reason its being an inert NOP post-Genesis —
[pitfall 6](#6-op_checklocktimeverify-does-not-work-on-bsv) — has to be compensated for
by hand). The shared `requireLockTimeAtLeast` clause takes an opt-in `{ pinDomain: true }`
for this; `market`'s refund sets it. It is opt-in only so the earlier timelock-family
demos ([`timelock`](predicates.md#timelock), [`oracle`](predicates.md#oracle),
[`htlc`](predicates.md#htlc), [`composed`](predicates.md#composed)) keep the exact bytes
they were **deployed** with on mainnet — their demonstrations predate the guard, and are
safe as long as the spender uses a height `nLockTime`; a new covenant where early
spending is adversarial should always pin the domain.
