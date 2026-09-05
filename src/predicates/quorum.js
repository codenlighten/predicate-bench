'use strict'

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const R = require('../rabin')
const rabinScript = require('../rabinscript')
const { StackAsm } = require('../stackasm')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// QUORUM — m-of-n oracles. The honest weakness of a single-oracle contract is
// that the one oracle is trusted absolutely: it can lie, or it can vanish, and
// the coins move on its word alone. `quorum` splits that trust the way
// [multisig] splits spending authority — across a PANEL of independent oracles,
// each with its own Rabin key, requiring a threshold m of them to attest the
// same value before the spend is allowed.
//
// The mechanism is the boolean Rabin check (src/rabinscript.js `check`), which —
// unlike the asserting `verify` — leaves 1 or 0 on the stack without aborting.
// The covenant runs it once per panel member, over the SAME message, sums the
// results, and requires the sum ≥ m:
//
//     Σ  valid_i(sig_i over FEED‖value under N_i)   ≥   m
//
// Two properties fall out of the construction, both load-bearing:
//   - Each slot i hard-codes oracle i's modulus N_i, so a signature counts for
//     slot i only if it is a root mod N_i. One oracle's attestation cannot be
//     replayed into another's slot to fake a quorum — the modulus won't match.
//   - The message is shared across every check, so the m agreeing oracles must
//     agree on the SAME value, not merely each sign something.
//
// Like [oracle] this is the claim half (winner's key binds who acts on the public
// attestations). It isolates the split-trust mechanism; a complete instrument
// composes it with a refund/timeout as `oracle` does.

const PANEL = require('./oracle-panel.json').keys
const PANEL_N = PANEL.map(k => BigInt(k.n))
const PANEL_KEYS = PANEL.map(k => ({ p: BigInt(k.p), q: BigInt(k.q), n: BigInt(k.n) }))

const FEED_BYTES = 8
const VALUE_BYTES = 4
const DUST = 2000

function feedTag (s) {
  const b = Buffer.alloc(FEED_BYTES)
  Buffer.from(s, 'latin1').copy(b, 0, 0, FEED_BYTES)
  return b
}
function valueLE (v) { const b = Buffer.alloc(VALUE_BYTES); b.writeUInt32LE(v >>> 0, 0); return b }
function message (feed, value) { return Buffer.concat([feedTag(feed), valueLE(value)]) }
function padBytes (p) { return Buffer.from([p & 0xff, (p >> 8) & 0xff]) }

function buildScript ({ feed, threshold, winnerPKH, m = 2, panelN }) {
  const w = Buffer.isBuffer(winnerPKH) ? winnerPKH : Buffer.from(winnerPKH, 'hex')
  if (w.length !== 20) throw new Error('winnerPKH must be 20 bytes')
  const moduli = (panelN || PANEL_N).map(x => R.toScriptNum(x))
  const N = moduli.length
  if (!(m >= 1 && m <= N)) throw new Error(`m must be in 1..${N}`)

  // unlock leaves: [wsig, wpub, msg, sig0, pad0, … sig_{N-1}, pad_{N-1}]
  const slots = []
  for (let i = 0; i < N; i++) slots.push('sig' + i, 'pad' + i)
  const s = new Script()
  const asm = new StackAsm(s).given(['wsig', 'wpub', 'msg', ...slots])

  // winner P2PKH — the attestations are public, so bind who may claim to a key
  asm.pick('wpub'); asm.hash160('wh'); asm.data(w, 'WPKH'); asm.equalVerify()
  asm.pick('wsig'); asm.pick('wpub'); asm.checkSigVerify()

  // the message every oracle must have signed: this feed, a value ≥ threshold
  asm.pick('msg', 'mc'); asm.splitAt(FEED_BYTES, 'tag', 'val')
  asm.roll('tag'); asm.data(feedTag(feed), 'FEED'); asm.equalVerify()
  asm.data(Buffer.from([0]), 'vz'); asm.cat('valp'); asm.bin2num('v')
  asm.num(threshold, 'thr'); asm.geVerify()

  // count how many panel members validly signed that message, require ≥ m
  for (let i = 0; i < N; i++) {
    rabinScript.check(asm, { nBytes: moduli[i], sig: 'sig' + i, msg: 'msg', pad: 'pad' + i })
    if (i === 0) asm.rename('acc'); else asm.add('acc')
  }
  asm.num(m, 'M'); asm.geVerify()          // acc ≥ m

  while (asm.main.length) asm.drop()
  asm.raw(Opcode.OP_1, 0, ['ok'])
  return s
}

// ---- scenarios --------------------------------------------------------------

function attestWith (keyObj, feed, value) {
  const msg = message(feed, value)
  const { sig, padding } = R.sign(msg, keyObj)
  return { sig, pad2: padBytes(padding) }
}

module.exports = {
  name: 'quorum',
  describe: 'm-of-n independent oracles must attest the same value before the winner can claim',
  example: () => ({
    feed: 'BSVUSD', threshold: 6000, winnerPKH: Buffer.alloc(20, 1), m: 2,
    signers: [0, 1], attestValue: 6543
  }),

  FEED_BYTES,
  DUST,
  PANEL_N,
  buildScript,
  message,
  attestWith,

  lock (tc) {
    if (!tc.winnerPKH) throw new Error('winnerPKH is required')
    return buildScript(tc)
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const wpriv = tc.winnerKey || tc.key
    const wsig = bsv.Transaction.Sighash.sign(
      tx, wpriv, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()

    const feed = tc.attestFeed || tc.feed
    const msgValue = tc.forgeValue !== undefined ? tc.forgeValue : tc.attestValue
    const msg = message(feed, msgValue)

    // slotKeys[i] = which panel key signs slot i (null = a dummy, counts as 0).
    // Defaults from `signers`; an explicit slotKeys can misattribute a key to a
    // slot it does not own, to prove a quorum needs DISTINCT oracles.
    const signers = tc.signers || [0, 1]
    const slotKeys = tc.slotKeys || PANEL_KEYS.map((_, i) => (signers.includes(i) ? i : null))

    const script = new Script().add(wsig).add(wpriv.publicKey.toBuffer()).add(msg)
    for (let i = 0; i < PANEL_KEYS.length; i++) {
      if (slotKeys[i] === null || slotKeys[i] === undefined) {
        script.add(Buffer.from([0])).add(Buffer.from([0, 0]))     // dummy → check yields 0
      } else {
        const a = attestWith(PANEL_KEYS[slotKeys[i]], feed, tc.attestValue)
        script.add(a.sig).add(a.pad2)
      }
    }
    return script
  }
}
