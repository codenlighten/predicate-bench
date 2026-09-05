'use strict'

const bsv = require('@smartledger/bsv')
const MAP = bsv.Opcode.map                                 // name -> number, from the library itself

// THE OPCODE LAYER — the complete, expert-tier escape hatch. Built FROM the library's
// own opcode table, so it covers exactly the opcode set the interpreter supports (a
// self-test reconciles the two and flags drift if a node release changes it). This is
// the floor beneath StackAsm: any opcode in the current release is reachable by name.
//
// The safety of the bench does NOT come from exposing opcodes — it comes from the
// curated STEP vocabulary and the type systems above. So this layer is honest rather
// than encouraging: several BSV opcodes are inert NOPs or traps, and each such opcode
// is annotated with the reality the bench proved on chain. Reach for a raw opcode only
// when no clause or step covers the need.

function categoryOf (code) {
  if (code <= 96) return 'push'                            // OP_0..OP_16, OP_PUSHDATA*, OP_1NEGATE
  if (code === 106) return 'flow'                          // OP_RETURN
  if (code >= 97 && code <= 105) return 'flow'             // NOP/VER/IF/NOTIF/ELSE/ENDIF/VERIFY (+reserved)
  if (code >= 107 && code <= 125) return 'stack'
  if (code >= 126 && code <= 130) return 'splice'          // CAT SPLIT NUM2BIN BIN2NUM SIZE
  if (code >= 131 && code <= 134) return 'bitwise'         // INVERT AND OR XOR
  if (code >= 135 && code <= 138) return 'equality'
  if (code >= 139 && code <= 165) return 'arithmetic'
  if (code >= 166 && code <= 170) return 'crypto-hash'
  if (code >= 171 && code <= 175) return 'crypto-sig'
  if (code >= 176 && code <= 185) return 'locktime/nop/splice'
  return 'pseudo'                                          // 253..255 template/internal
}

// The honest annotations — only where BSV reality differs from a naive reading. Anything
// not listed is a plain, active opcode. status: active | restored | nop | reserved |
// caution | terminal | pseudo.
const NOTES = {
  OP_CHECKLOCKTIMEVERIFY: { status: 'nop', note: 'a NO-OP post-Genesis — it does NOT enforce a timelock (pitfall 6). Read nLockTime from the preimage and require a non-final sequence instead (see timelock).' },
  OP_CHECKSEQUENCEVERIFY: { status: 'nop', note: 'a NO-OP post-Genesis, inert like CLTV.' },
  OP_NOP: { status: 'nop', note: 'does nothing.' },
  OP_NOP1: { status: 'nop', note: 'does nothing.' },
  OP_NOP9: { status: 'nop', note: 'does nothing.' },
  OP_NOP10: { status: 'nop', note: 'does nothing.' },
  OP_CODESEPARATOR: { status: 'caution', note: 'works, but truncates the scriptCode the preimage commits to — incompatible with self-recreating covenants (pitfall 7).' },
  OP_RETURN: { status: 'terminal', note: 'ends script evaluation; in a locking script it marks the output unspendable / a data carrier.' },
  OP_CAT: { status: 'restored', note: 'restored at Genesis (disabled on BTC) — concatenation, the workhorse of covenant assembly.' },
  OP_SPLIT: { status: 'restored', note: 'restored at Genesis; splits a byte string at an index (replaced OP_SUBSTR).' },
  OP_NUM2BIN: { status: 'restored', note: 'restored at Genesis; fixed-width encode a number.' },
  OP_BIN2NUM: { status: 'restored', note: 'restored at Genesis; minimal-encode a byte string as a number (mind the sign bit — pitfall 12).' },
  OP_AND: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_OR: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_XOR: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_INVERT: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_MUL: { status: 'restored', note: 'restored at Genesis (disabled on BTC) — used for Rabin-signature arithmetic (oracle).' },
  OP_DIV: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_MOD: { status: 'restored', note: 'restored at Genesis (disabled on BTC) — used for Rabin verification.' },
  OP_LSHIFT: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_RSHIFT: { status: 'restored', note: 'restored at Genesis (disabled on BTC).' },
  OP_2MUL: { status: 'reserved', note: 'not enabled — use OP_MUL.' },
  OP_2DIV: { status: 'reserved', note: 'not enabled — use OP_DIV.' },
  OP_VER: { status: 'reserved', note: 'invalid if executed.' },
  OP_VERIF: { status: 'reserved', note: 'invalid whether executed or not.' },
  OP_VERNOTIF: { status: 'reserved', note: 'invalid whether executed or not.' },
  OP_RESERVED: { status: 'reserved', note: 'invalid if executed.' },
  OP_RESERVED1: { status: 'reserved', note: 'invalid if executed.' },
  OP_RESERVED2: { status: 'reserved', note: 'invalid if executed.' },
  OP_CHECKMULTISIG: { status: 'active', note: 'consumes an extra dummy element (an off-by-one that once cost a stranded coin — see multisig).' },
  OP_CHECKMULTISIGVERIFY: { status: 'active', note: 'as OP_CHECKMULTISIG, then VERIFY.' },
  OP_PUBKEYHASH: { status: 'pseudo', note: 'template/internal — not usable in a live script.' },
  OP_PUBKEY: { status: 'pseudo', note: 'template/internal — not usable in a live script.' },
  OP_INVALIDOPCODE: { status: 'pseudo', note: 'sentinel for an unknown opcode.' }
}

const CATALOG = Object.entries(MAP)
  .map(([name, code]) => ({ name, code, hex: '0x' + code.toString(16).padStart(2, '0').toUpperCase(), category: categoryOf(code), status: (NOTES[name] || {}).status || 'active', note: (NOTES[name] || {}).note || null }))
  .sort((a, b) => a.code - b.code || a.name.localeCompare(b.name))

const byName = Object.fromEntries(CATALOG.map((o) => [o.name, o]))

/** Resolve an opcode name to its number, or throw if the current release has no such opcode. */
function opcode (name) {
  if (!(name in MAP)) throw new Error(`no opcode '${name}' in this release — see docs/opcodes.md for the full set`)
  return MAP[name]
}
/** Is this opcode a safe, active one to emit? (not a NOP, reserved, or pseudo opcode) */
function isActive (name) { const o = byName[name]; return !!o && (o.status === 'active' || o.status === 'restored' || o.status === 'terminal') }

module.exports = { CATALOG, MAP, byName, opcode, isActive, categoryOf }
