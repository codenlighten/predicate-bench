# The opcode layer

The complete opcode set of the current release, catalogued directly from the library (`src/opcodes.js`) and reconciled against it by `tools/opcodes-selftest.js` — 118 opcodes, no gaps, every code matched. This is the **expert escape hatch**: anything a
[clause](clauses.md) or [step](compiler.md) does not cover is still reachable by name via
`StackAsm.op(name)`. The safety of the bench lives in the curated vocabulary above this
layer, not here — so each opcode is annotated **honestly**, including the ones that are
inert NOPs or traps the bench proved on chain.

**Status legend.** `active` normal; `restored` re-enabled at Genesis (disabled on BTC);
`nop` does nothing (inert); `reserved` invalid if executed; `caution` works but has a
sharp edge; `terminal` ends evaluation; `pseudo` template/internal, not usable live.

## push

| opcode | hex | status | note |
|---|---|---|---|
| `OP_0` | 0x00 | active |  |
| `OP_FALSE` | 0x00 | active |  |
| `OP_PUSHDATA1` | 0x4C | active |  |
| `OP_PUSHDATA2` | 0x4D | active |  |
| `OP_PUSHDATA4` | 0x4E | active |  |
| `OP_1NEGATE` | 0x4F | active |  |
| `OP_RESERVED` | 0x50 | reserved | invalid if executed. |
| `OP_1` | 0x51 | active |  |
| `OP_TRUE` | 0x51 | active |  |
| `OP_2` | 0x52 | active |  |
| `OP_3` | 0x53 | active |  |
| `OP_4` | 0x54 | active |  |
| `OP_5` | 0x55 | active |  |
| `OP_6` | 0x56 | active |  |
| `OP_7` | 0x57 | active |  |
| `OP_8` | 0x58 | active |  |
| `OP_9` | 0x59 | active |  |
| `OP_10` | 0x5A | active |  |
| `OP_11` | 0x5B | active |  |
| `OP_12` | 0x5C | active |  |
| `OP_13` | 0x5D | active |  |
| `OP_14` | 0x5E | active |  |
| `OP_15` | 0x5F | active |  |
| `OP_16` | 0x60 | active |  |

## stack

| opcode | hex | status | note |
|---|---|---|---|
| `OP_TOALTSTACK` | 0x6B | active |  |
| `OP_FROMALTSTACK` | 0x6C | active |  |
| `OP_2DROP` | 0x6D | active |  |
| `OP_2DUP` | 0x6E | active |  |
| `OP_3DUP` | 0x6F | active |  |
| `OP_2OVER` | 0x70 | active |  |
| `OP_2ROT` | 0x71 | active |  |
| `OP_2SWAP` | 0x72 | active |  |
| `OP_IFDUP` | 0x73 | active |  |
| `OP_DEPTH` | 0x74 | active |  |
| `OP_DROP` | 0x75 | active |  |
| `OP_DUP` | 0x76 | active |  |
| `OP_NIP` | 0x77 | active |  |
| `OP_OVER` | 0x78 | active |  |
| `OP_PICK` | 0x79 | active |  |
| `OP_ROLL` | 0x7A | active |  |
| `OP_ROT` | 0x7B | active |  |
| `OP_SWAP` | 0x7C | active |  |
| `OP_TUCK` | 0x7D | active |  |

## splice

| opcode | hex | status | note |
|---|---|---|---|
| `OP_CAT` | 0x7E | restored | restored at Genesis (disabled on BTC) — concatenation, the workhorse of covenant assembly. |
| `OP_SPLIT` | 0x7F | restored | restored at Genesis; splits a byte string at an index (replaced OP_SUBSTR). |
| `OP_NUM2BIN` | 0x80 | restored | restored at Genesis; fixed-width encode a number. |
| `OP_BIN2NUM` | 0x81 | restored | restored at Genesis; minimal-encode a byte string as a number (mind the sign bit — pitfall 12). |
| `OP_SIZE` | 0x82 | active |  |

## bitwise

| opcode | hex | status | note |
|---|---|---|---|
| `OP_INVERT` | 0x83 | restored | restored at Genesis (disabled on BTC). |
| `OP_AND` | 0x84 | restored | restored at Genesis (disabled on BTC). |
| `OP_OR` | 0x85 | restored | restored at Genesis (disabled on BTC). |
| `OP_XOR` | 0x86 | restored | restored at Genesis (disabled on BTC). |

## equality

| opcode | hex | status | note |
|---|---|---|---|
| `OP_EQUAL` | 0x87 | active |  |
| `OP_EQUALVERIFY` | 0x88 | active |  |
| `OP_RESERVED1` | 0x89 | reserved | invalid if executed. |
| `OP_RESERVED2` | 0x8A | reserved | invalid if executed. |

## arithmetic

| opcode | hex | status | note |
|---|---|---|---|
| `OP_1ADD` | 0x8B | active |  |
| `OP_1SUB` | 0x8C | active |  |
| `OP_2MUL` | 0x8D | reserved | not enabled — use OP_MUL. |
| `OP_2DIV` | 0x8E | reserved | not enabled — use OP_DIV. |
| `OP_NEGATE` | 0x8F | active |  |
| `OP_ABS` | 0x90 | active |  |
| `OP_NOT` | 0x91 | active |  |
| `OP_0NOTEQUAL` | 0x92 | active |  |
| `OP_ADD` | 0x93 | active |  |
| `OP_SUB` | 0x94 | active |  |
| `OP_MUL` | 0x95 | restored | restored at Genesis (disabled on BTC) — used for Rabin-signature arithmetic (oracle). |
| `OP_DIV` | 0x96 | restored | restored at Genesis (disabled on BTC). |
| `OP_MOD` | 0x97 | restored | restored at Genesis (disabled on BTC) — used for Rabin verification. |
| `OP_LSHIFT` | 0x98 | restored | restored at Genesis (disabled on BTC). |
| `OP_RSHIFT` | 0x99 | restored | restored at Genesis (disabled on BTC). |
| `OP_BOOLAND` | 0x9A | active |  |
| `OP_BOOLOR` | 0x9B | active |  |
| `OP_NUMEQUAL` | 0x9C | active |  |
| `OP_NUMEQUALVERIFY` | 0x9D | active |  |
| `OP_NUMNOTEQUAL` | 0x9E | active |  |
| `OP_LESSTHAN` | 0x9F | active |  |
| `OP_GREATERTHAN` | 0xA0 | active |  |
| `OP_LESSTHANOREQUAL` | 0xA1 | active |  |
| `OP_GREATERTHANOREQUAL` | 0xA2 | active |  |
| `OP_MIN` | 0xA3 | active |  |
| `OP_MAX` | 0xA4 | active |  |
| `OP_WITHIN` | 0xA5 | active |  |

## crypto-hash

| opcode | hex | status | note |
|---|---|---|---|
| `OP_RIPEMD160` | 0xA6 | active |  |
| `OP_SHA1` | 0xA7 | active |  |
| `OP_SHA256` | 0xA8 | active |  |
| `OP_HASH160` | 0xA9 | active |  |
| `OP_HASH256` | 0xAA | active |  |

## crypto-sig

| opcode | hex | status | note |
|---|---|---|---|
| `OP_CODESEPARATOR` | 0xAB | caution | works, but truncates the scriptCode the preimage commits to — incompatible with self-recreating covenants (pitfall 7). |
| `OP_CHECKSIG` | 0xAC | active |  |
| `OP_CHECKSIGVERIFY` | 0xAD | active |  |
| `OP_CHECKMULTISIG` | 0xAE | active | consumes an extra dummy element (an off-by-one that once cost a stranded coin — see multisig). |
| `OP_CHECKMULTISIGVERIFY` | 0xAF | active | as OP_CHECKMULTISIG, then VERIFY. |

## flow

| opcode | hex | status | note |
|---|---|---|---|
| `OP_NOP` | 0x61 | nop | does nothing. |
| `OP_VER` | 0x62 | reserved | invalid if executed. |
| `OP_IF` | 0x63 | active |  |
| `OP_NOTIF` | 0x64 | active |  |
| `OP_VERIF` | 0x65 | reserved | invalid whether executed or not. |
| `OP_VERNOTIF` | 0x66 | reserved | invalid whether executed or not. |
| `OP_ELSE` | 0x67 | active |  |
| `OP_ENDIF` | 0x68 | active |  |
| `OP_VERIFY` | 0x69 | active |  |
| `OP_RETURN` | 0x6A | terminal | ends script evaluation; in a locking script it marks the output unspendable / a data carrier. |

## locktime/nop/splice

| opcode | hex | status | note |
|---|---|---|---|
| `OP_NOP1` | 0xB0 | nop | does nothing. |
| `OP_CHECKLOCKTIMEVERIFY` | 0xB1 | nop | a NO-OP post-Genesis — it does NOT enforce a timelock (pitfall 6). Read nLockTime from the preimage and require a non-final sequence instead (see timelock). |
| `OP_NOP2` | 0xB1 | active |  |
| `OP_CHECKSEQUENCEVERIFY` | 0xB2 | nop | a NO-OP post-Genesis, inert like CLTV. |
| `OP_NOP3` | 0xB2 | active |  |
| `OP_SUBSTR` | 0xB3 | active |  |
| `OP_LEFT` | 0xB4 | active |  |
| `OP_RIGHT` | 0xB5 | active |  |
| `OP_LSHIFTNUM` | 0xB6 | active |  |
| `OP_RSHIFTNUM` | 0xB7 | active |  |
| `OP_NOP9` | 0xB8 | nop | does nothing. |
| `OP_NOP10` | 0xB9 | nop | does nothing. |

## pseudo

| opcode | hex | status | note |
|---|---|---|---|
| `OP_PUBKEYHASH` | 0xFD | pseudo | template/internal — not usable in a live script. |
| `OP_PUBKEY` | 0xFE | pseudo | template/internal — not usable in a live script. |
| `OP_INVALIDOPCODE` | 0xFF | pseudo | sentinel for an unknown opcode. |

## Not present

`OP_CHECKDATASIG` never existed on BSV — verify off-chain (oracle) signatures with Rabin
arithmetic (`OP_MUL`/`OP_MOD`) instead; see [oracle.md](oracle.md). The disabled/removed
opcodes of other chains are simply absent from the table above.

See [pitfalls.md](pitfalls.md#6-op_checklocktimeverify-does-not-work-on-bsv) for CLTV,
[pitfalls.md](pitfalls.md#7-op_codeseparator-and-self-reference-cannot-coexist) for OP_CODESEPARATOR.
