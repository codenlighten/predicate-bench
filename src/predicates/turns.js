'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const covsteps = require('../covsteps')
const Script = bsv.Script
const Opcode = bsv.Opcode

// TURNS — a two-player, turn-based game state machine. The on-chain referee the
// game vision needs: Bitcoin will not let the WRONG player move, will not let a
// player move TWICE, and forces the turn to alternate and the game state to carry
// forward. The move's game-specific legality (a square is empty, a jump is valid)
// is the app's to add on top; what `turns` enforces is the universal spine every
// turn game shares — authority, alternation, and honest state succession.
//
//   state = a(20) ‖ b(20) ‖ turn(1) ‖ gstate(32)
//
//   move    the player whose turn it is signs, chooses the next game state, and the
//           coin recreates itself with the turn flipped — nobody else can move, and
//           nobody can skip their opponent's turn.
//   settle  BOTH players sign to agree the game is over, paying the pot to an
//           agreed winner (the exit).
//
// `turn` is 0 (player a to move) or 1 (player b to move). Authority is turn-bound:
// the signer must be a AND turn 0, or b AND turn 1 — possession of the coin is not
// enough. Game state is 32 bytes (a board hash, a score encoding, whatever the app
// commits to), spender-chosen each move and spliced in, everything else identical.

const GSTATE_BYTES = 32
const DUST = 2000
const DEFAULT_FEE = 300

function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function hash160Of (a) { return Buffer.isBuffer(a) ? a : (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  if (typeof a === 'string') return /^[0-9a-f]{40}$/i.test(a) ? Buffer.from(a, 'hex') : bsv.Address.fromString(a).hashBuffer
  if (a instanceof bsv.PrivateKey) return bsv.crypto.Hash.sha256ripemd160(a.publicKey.toBuffer())
  if (a instanceof bsv.PublicKey) return bsv.crypto.Hash.sha256ripemd160(a.toBuffer())
  if (a && a.hashBuffer) return a.hashBuffer
  return hash160Of(a)
}
function gstateBuf (g) { const b = g ? buf(g) : Buffer.alloc(GSTATE_BYTES); if (b.length !== GSTATE_BYTES) throw new Error('gstate must be 32 bytes'); return b }
function state (a, b, turn, gstate) { return Buffer.concat([pkhOf(a), pkhOf(b), Buffer.from([turn]), gstateBuf(gstate)]) }

function buildScript ({ a, b, turn = 0, gstate, fee = DEFAULT_FEE }) {
  const s = new Script()
  s.add(state(a, b, turn, gstate)).add(Opcode.OP_DROP)
  C.authenticateThenBranch(s)

  const mv = new StackAsm(s); mv.main = ['pubkey', 'sig', 'newState', 'preimage']
  covsteps.turnsMove(mv, { fee })

  s.add(Opcode.OP_ELSE)
  const st = new StackAsm(s); st.main = ['pubA', 'sigA', 'pubB', 'sigB', 'winner', 'preimage']
  covsteps.turnsSettle(st, { fee })
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  return s
}

const A = bsv.PrivateKey.fromRandom()
const B = bsv.PrivateKey.fromRandom()

module.exports = {
  name: 'turns',
  describe: 'a two-player turn-based game: the player whose turn it is moves, the turn alternates, the state carries; both settle',
  example: () => ({ a: A, b: B, turn: 0, gstate: Buffer.alloc(32, 0), branch: 'move', to: Buffer.alloc(32, 1), moverKey: A }),

  DUST,
  DEFAULT_FEE,
  GSTATE_BYTES,
  buildScript,
  state,
  pkhOf,
  gstateBuf,

  lock (tc) {
    if (!tc.a || !tc.b) throw new Error('two players a and b are required')
    return buildScript({ a: tc.a, b: tc.b, turn: tc.turn ?? 0, gstate: tc.gstate, fee: tc.fee })
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    if ((tc.branch || 'move') === 'settle') {
      const winner = pkhOf(tc.winner)
      if (tc.actualOutputs) return tc.actualOutputs({ fee, winner })
      return [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(winner), tc.satoshis - fee)]
    }
    const next = buildScript({ a: tc.a, b: tc.b, turn: 1 - (tc.turn ?? 0), gstate: tc.to, fee })
    if (tc.actualOutputs) return tc.actualOutputs({ fee, script: next })
    return [new bsv.Transaction.Output({ script: next, satoshis: tc.satoshis - fee })]
  },

  continuation (tc) {
    if ((tc.branch || 'move') === 'settle') return null
    const params = { a: pkhOf(tc.a).toString('hex'), b: pkhOf(tc.b).toString('hex'), turn: 1 - (tc.turn ?? 0), gstate: gstateBuf(tc.to).toString('hex'), fee: tc.fee ?? DEFAULT_FEE }
    return { script: buildScript(params), params }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const branch = tc.branch || 'move'
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sign = (k) => bsv.Transaction.Sighash.sign(tx, k, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      if (branch === 'settle') {
        const ka = tc.aKey || A; const kb = tc.bKey || B
        return new Script().add(ka.publicKey.toBuffer()).add(sign(ka)).add(kb.publicKey.toBuffer()).add(sign(kb))
          .add(pkhOf(tc.winner)).add(Opcode.OP_0).add(preimage)
      }
      const mover = tc.moverKey || ((tc.turn ?? 0) === 0 ? A : B)
      const pub = (tc.wrongPubkey || mover).publicKey.toBuffer()
      return new Script().add(pub).add(sign(mover)).add(gstateBuf(tc.to)).add(Opcode.OP_1).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
