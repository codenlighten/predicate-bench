'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode

// LIFECYCLE — a predicate OBJECT with a CONSTITUTION. Every state covenant so far
// advanced a value (a counter, a round, a hash head). This one is a proper STATE
// MACHINE: a status field that may move only along an allowed-transition set, an
// immutable core no transition may rewrite, a TERMINAL state from which nothing
// follows, and an issuer whose signature authorises each move.
//
//   state = genesis(32) ‖ status(1) ‖ issuer(20)
//
//   transition  status: old -> new, where (old, new) is an ALLOWED pair; the
//               genesis and issuer are spliced UNCHANGED into the successor, so
//               they are immutable for the life of the object; issuer signs.
//   retire      the issuer sweeps the remainder and stops (the exit).
//
// The allowed pairs are baked into the script as a set the transition must be a
// member of. A status with no outgoing pair — REVOKED, below — is TERMINAL: the
// transition branch can never leave it, so an impossible transition (revoked back
// to active) is not merely detectable, it is unspendable. And because genesis and
// issuer come from the object's OWN state, not the spender, even the issuer cannot
// rewrite the object's foundational terms — a digital constitution.
//
// The demo is a certificate: ISSUED -> ACTIVE/REVOKED, ACTIVE -> SUSPENDED/REVOKED,
// SUSPENDED -> ACTIVE/REVOKED, REVOKED -> (nothing).

const GEN_BYTES = 32
const STATUS_BYTES = 1
const ISSUER_BYTES = 20
const STATE_BYTES = GEN_BYTES + STATUS_BYTES + ISSUER_BYTES   // 53, push-op 0x35
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const DUST = 2000
const DEFAULT_FEE = 250
const P2PKH_PRE = Buffer.from('1976a914', 'hex')
const P2PKH_POST = Buffer.from('88ac', 'hex')

// the certificate state machine
const ISSUED = 0
const ACTIVE = 1
const SUSPENDED = 2
const REVOKED = 3
const CERT_TRANSITIONS = [
  [ISSUED, ACTIVE], [ISSUED, REVOKED],
  [ACTIVE, SUSPENDED], [ACTIVE, REVOKED],
  [SUSPENDED, ACTIVE], [SUSPENDED, REVOKED]
  // REVOKED -> nothing : terminal
]

function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function buf (x) { return Buffer.isBuffer(x) ? x : Buffer.from(x, 'hex') }
function pkhOf (a) {
  if (Buffer.isBuffer(a)) return a
  return /^[0-9a-f]{40}$/i.test(a) ? Buffer.from(a, 'hex') : hash160Of(a)
}
function transKey (old, next) { return Buffer.from([old, next]) }
function state (genesis, status, issuer) {
  return Buffer.concat([buf(genesis), Buffer.from([status]), pkhOf(issuer)])
}

function readState (asm) {
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(HEAD_BYTES, 'header', 'r1')
  asm.splitAt(GEN_BYTES, 'genesis', 'r2')
  asm.splitAt(STATUS_BYTES, 'status1', 'r3')
  asm.splitAt(ISSUER_BYTES, 'issuer', 'tail')
}
function requireIssuerSig (asm) {
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('issuer'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
}
function transitionBody (asm, { transitions, fee }) {
  readState(asm)
  requireIssuerSig(asm)

  // The spender presents move = old ‖ new (two bytes). Pushed whole, it dodges
  // the small-int MINIMALDATA trap a bare status byte would hit, and — the load-
  // bearing part — its FIRST byte must equal the object's REAL current status,
  // so a spender cannot claim a move out of a state the object is not in. That
  // is what makes REVOKED terminal: no allowed move begins with it, and the move
  // cannot lie about where it begins.
  asm.pick('move'); asm.splitAt(1, 'moveOld', 'moveNew')
  asm.pick('moveOld'); asm.pick('status1'); asm.equalVerify()

  // move must be one of the allowed pairs — a set-membership test
  asm.pick('move'); asm.data(transKey(transitions[0][0], transitions[0][1]), 'k0'); asm.equal('acc')
  for (let i = 1; i < transitions.length; i++) {
    asm.pick('move'); asm.data(transKey(transitions[i][0], transitions[i][1]), 'k' + i); asm.equal('ei')
    asm.raw(Opcode.OP_BOOLOR, 2, ['acc'])
  }
  asm.verify()                                            // the transition is allowed

  // successor: genesis and issuer UNCHANGED, status -> moveNew
  asm.pick('genesis'); asm.pick('moveNew'); asm.cat('gn'); asm.pick('issuer'); asm.cat('newState')
  asm.pick('header'); asm.pick('newState'); asm.cat('hn'); asm.pick('tail'); asm.cat('newChunk')
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('nextOutput')
  asm.bindOutput('nextOutput')
}

function retireBody (asm, { fee }) {
  readState(asm)
  requireIssuerSig(asm)
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.data(P2PKH_PRE, 'pre'); asm.pick('issuer'); asm.cat('ik1'); asm.data(P2PKH_POST, 'post'); asm.cat('issuerChunk')
  asm.cat('retireOutput')
  asm.bindOutput('retireOutput')
}

function buildScript ({ genesis, status = ISSUED, issuer, transitions = CERT_TRANSITIONS, fee = DEFAULT_FEE }) {
  const g = buf(genesis); const iss = pkhOf(issuer)
  if (g.length !== GEN_BYTES) throw new Error('genesis must be 32 bytes')
  if (iss.length !== ISSUER_BYTES) throw new Error('issuer must be a 20-byte pkh')

  const s = new Script()
  s.add(state(g, status, iss)).add(Opcode.OP_DROP)
  C.authenticateThenBranch(s)

  const tr = new StackAsm(s); tr.main = ['pubkey', 'sig', 'move', 'preimage']
  transitionBody(tr, { transitions, fee })
  while (tr.main.length) tr.drop()
  tr.raw(Opcode.OP_1, 0, ['ok'])
  const trDepth = tr.main.length

  s.add(Opcode.OP_ELSE)
  const rt = new StackAsm(s); rt.main = ['pubkey', 'sig', 'preimage']
  retireBody(rt, { fee })
  while (rt.main.length) rt.drop()
  rt.raw(Opcode.OP_1, 0, ['ok'])
  if (rt.main.length !== trDepth) throw new Error(`lifecycle: branches leave different depths (${trDepth} vs ${rt.main.length})`)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

module.exports = {
  name: 'lifecycle',
  describe: 'a certificate-style object: an immutable core, a bounded status machine, a terminal state, issuer-signed',
  example: () => ({ genesis: Buffer.alloc(32, 1), status: ISSUED, issuer: Buffer.alloc(20, 2), fee: DEFAULT_FEE, to: ACTIVE, branch: 'transition' }),

  GEN_BYTES,
  DUST,
  DEFAULT_FEE,
  ISSUED,
  ACTIVE,
  SUSPENDED,
  REVOKED,
  CERT_TRANSITIONS,
  buildScript,
  state,
  hash160Of,
  pkhOf,

  lock (tc) {
    if (!tc.genesis || !tc.issuer) throw new Error('genesis and issuer are required')
    return buildScript(tc)
  },

  outputs (tc) {
    const fee = tc.fee ?? DEFAULT_FEE
    const iss = pkhOf(tc.issuer)
    if ((tc.branch || 'transition') === 'retire') {
      if (tc.actualOutputs) return tc.actualOutputs({ fee, iss })
      return [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(iss), tc.satoshis - fee)]
    }
    const script = buildScript({ genesis: tc.genesis, status: tc.to, issuer: iss, transitions: tc.transitions, fee })
    if (tc.actualOutputs) return tc.actualOutputs({ fee, script })
    return [new bsv.Transaction.Output({ script, satoshis: tc.satoshis - fee })]
  },

  continuation (tc) {
    if ((tc.branch || 'transition') === 'retire') return null
    const params = { genesis: buf(tc.genesis).toString('hex'), status: tc.to, issuer: pkhOf(tc.issuer).toString('hex'), transitions: tc.transitions, fee: tc.fee ?? DEFAULT_FEE }
    return { script: buildScript(params), params }
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const priv = tc.issuerKey || tc.key
    for (let t = 0; t < 50000; t++) {
      tx.nLockTime = t
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, priv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const pub = priv.publicKey.toBuffer()
      if ((tc.branch || 'transition') === 'retire') {
        return new Script().add(pub).add(sig).add(Opcode.OP_0).add(preimage)
      }
      const move = tc.presentMove || Buffer.from([tc.status, tc.to])
      return new Script().add(pub).add(sig).add(move).add(Opcode.OP_1).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
