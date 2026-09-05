'use strict'

const bsv = require('@smartledger/bsv')
const Interpreter = bsv.Script.Interpreter
const Opcode = bsv.Opcode
const BN = bsv.crypto.BN

// Measuring what a node actually enforces, instead of guessing.
//
// `clauses.policyFlags()` is a hand-written list, and twice this session a flag
// missing from it cost a permanently unspendable output. The list can be
// checked rather than reasoned about: build a transaction that is
// CONSENSUS-VALID but violates exactly one standardness rule, broadcast it, and
// read what the node says.
//
// The probes cost nothing. A rejected transaction never touches the chain, so
// the funding UTXO is untouched and can be reused for the next probe. Each
// probe pays back to our own wallet, so even an unexpected ACCEPT only spends
// the fee.
//
// A probe is only meaningful if it isolates one rule. Every one below is
// verified locally first: it must PASS under consensus flags and FAIL under
// consensus|thatFlag. A probe that fails that check is reported as
// un-isolated rather than broadcast, because its rejection would prove nothing.

/** Signature bytes for a P2PKH input, optionally with s negated to break low-S. */
function signInput (tx, key, lockingScript, satoshis, { highS = false } = {}) {
  const type = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const sig = bsv.Transaction.Sighash.sign(tx, key, type, 0, lockingScript, new BN(satoshis))
  if (highS) {
    // s' = n - s is the other valid signature for the same message. It verifies
    // fine — that is the point — but it is not canonical, so LOW_S refuses it.
    sig.s = bsv.crypto.Point.getN().sub(sig.s)
  }
  return sig.toTxFormat()
}

/**
 * The probes. Each returns the unlocking script for a plain P2PKH spend, built
 * so that exactly one standardness rule is broken.
 */
const PROBES = {
  baseline: {
    flag: null,
    describe: 'a correct spend — the control',
    build: (sig, pub) => new bsv.Script().add(sig).add(pub)
  },
  MINIMALDATA: {
    flag: 'SCRIPT_VERIFY_MINIMALDATA',
    describe: 'the pubkey pushed with OP_PUSHDATA1 where a direct push would do',
    build: (sig, pub) => {
      const s = new bsv.Script().add(sig)
      // A hand-built non-minimal push: OP_PUSHDATA1 <len> <data>.
      s.chunks.push({ buf: pub, len: pub.length, opcodenum: Opcode.OP_PUSHDATA1 })
      s._chunkToString  // keep the setter honest
      return bsv.Script.fromBuffer(s.toBuffer())
    }
  },
  CLEANSTACK: {
    flag: 'SCRIPT_VERIFY_CLEANSTACK',
    describe: 'one extra item left under the result',
    build: (sig, pub) => new bsv.Script().add(Opcode.OP_1).add(sig).add(pub)
  },
  SIGPUSHONLY: {
    flag: 'SCRIPT_VERIFY_SIGPUSHONLY',
    describe: 'a non-push opcode (OP_NOP) in the unlocking script',
    build: (sig, pub) => new bsv.Script().add(sig).add(pub).add(Opcode.OP_NOP)
  },
  LOW_S: {
    flag: 'SCRIPT_VERIFY_LOW_S',
    describe: 'a mathematically valid signature with s negated (non-canonical)',
    build: (sig, pub) => new bsv.Script().add(sig).add(pub),
    highS: true
  }
}

/**
 * How the LIBRARY classifies a rule, checked against how the NETWORK does.
 *
 * Originally this only asked "does the probe isolate one rule" — consensus must
 * accept it and consensus|flag must reject it. That question quietly changed
 * meaning when @smartledger/bsv 9.5.0 moved SIGPUSHONLY, LOW_S and NULLFAIL
 * into `currentConsensusFlags()`: the probes stopped isolating, because
 * consensus itself now rejects them. Reporting that as NOT ISOLATED would flag
 * the fix as a failure.
 *
 * So the useful question is the comparison. For each rule we know what the
 * network answered (mandatory or policy, from MEASURED). The library either
 * treats it as consensus or it does not. Those two should agree:
 *
 *   network says mandatory + library has it in consensus  -> agree
 *   network says policy    + library leaves it out        -> agree
 *
 * Anything else is a real divergence and worth a look.
 */
function classify (name, unlockingScript, lockingScript, tx, satoshis) {
  const probe = PROBES[name]
  const consensus = Interpreter.currentConsensusFlags()
  const a = new Interpreter()
  const consensusOk = a.verify(unlockingScript, lockingScript, tx, 0, consensus, new BN(satoshis))

  if (!probe.flag) {
    return { control: true, consensusOk, isolated: consensusOk, err: a.errstr }
  }

  const b = new Interpreter()
  const flagOk = b.verify(unlockingScript, lockingScript, tx, 0,
    consensus | Interpreter[probe.flag], new BN(satoshis))

  // The library calls it consensus if the default flag word already rejects it.
  const libraryTreatsAsConsensus = !consensusOk
  const measured = MEASURED[name]
  const networkSaysMandatory = measured && measured.kind === 'consensus'
  const agrees = measured ? (libraryTreatsAsConsensus === networkSaysMandatory) : null

  return {
    consensusOk,
    flagOk,
    // Isolation only means anything while the library still treats it as
    // non-consensus; once it agrees, there is nothing left to isolate.
    isolated: consensusOk && !flagOk,
    libraryTreatsAsConsensus,
    networkSaysMandatory,
    agrees,
    err: (consensusOk ? b : a).errstr
  }
}

/** Kept as the older name; the report now shows the comparison. */
const isolate = classify

/**
 * What mainnet actually answered, 2026-09-02. Re-measure with
 * `npm run probe -- --broadcast`; the probes cost nothing when refused.
 *
 * The distinction in the two message forms is the finding:
 *
 *   code 16  mandatory-script-verify-flag-failed   the node treats it as CONSENSUS
 *   code 64  non-mandatory-script-verify-flag      the node treats it as POLICY
 *
 * SIGPUSHONLY and LOW_S came back MANDATORY. The library's
 * `currentConsensusFlags()` contains neither — so a script verified only under
 * that flag word can be not merely unrelayable but invalid. Both happened to be
 * in our hand-written policy list already, which was luck rather than knowledge.
 */
const MEASURED = {
  DISCOURAGE_UPGRADABLE_NOPS: {
    kind: 'policy', code: 64, says: 'NOPx reserved for soft-fork upgrades',
    note: 'needs a deployed locking script — see DEPLOYED_PROBE below'
  },
  NULLFAIL: {
    kind: 'consensus', code: 16, says: 'Signature must be zero for failed CHECK(MULTI)SIG operation',
    note: 'deployed probe: OP_IF <pubkey> OP_CHECKSIG OP_NOT OP_ELSE OP_DROP OP_1 OP_ENDIF'
  },
  NULLDUMMY: {
    kind: 'policy', code: 64, says: 'Dummy CHECKMULTISIG argument must be zero',
    note: 'deployed probe: OP_IF OP_1 <pubkey> OP_1 OP_CHECKMULTISIG OP_ELSE OP_2DROP OP_1 OP_ENDIF'
  },
  MINIMALDATA: { kind: 'policy', code: 64, says: 'Data push larger than necessary' },
  CLEANSTACK: { kind: 'policy', code: 64, says: 'Script did not clean its stack' },
  SIGPUSHONLY: { kind: 'consensus', code: 16, says: 'Only non-push operators allowed in signatures' },
  LOW_S: { kind: 'consensus', code: 16, says: 'Non-canonical signature: S value is unnecessarily high' },
  baseline: { kind: 'accepted', code: null, says: 'accepted, confirming the rejections were attributable' }
}

/**
 * Some rules cannot be isolated from a scriptSig at all.
 *
 * DISCOURAGE_UPGRADABLE_NOPS needs the NOP inside a LOCKING script: put it in
 * the unlocking script and SIGPUSHONLY — which is mandatory here — fails first,
 * so the answer would be about the wrong rule.
 *
 * Deploying a probe normally risks the coins: if the rule IS enforced, the
 * output is unspendable and the stake is gone. An escape branch removes that:
 *
 *     OP_IF <the thing being tested> OP_ENDIF OP_1
 *
 * Unlock with OP_1 and the NOP executes — that is the probe. Unlock with OP_0
 * and it is skipped — that is how the coins come back when the answer is
 * "refused". Four bytes, and the measurement costs only fees.
 *
 * Measured 2026-09-02: deploy 7e813cfe…, probe refused with code 64
 * "NOPx reserved for soft-fork upgrades", coins recovered by 68700e4e….
 * The flag was missing from policyFlags() and has been added.
 */
const DEPLOYED_PROBE = {
  script: () => new bsv.Script()
    .add(Opcode.OP_IF).add(Opcode.OP_NOP1).add(Opcode.OP_ENDIF).add(Opcode.OP_1),
  probeBranch: Opcode.OP_1,
  escapeBranch: Opcode.OP_0,
  flag: 'SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS'
}

/**
 * Build the probe transactions, check each isolates its rule, and optionally
 * broadcast. Violating probes go first so that a refusal leaves the funding
 * coin untouched for the next one; the baseline goes last, and its acceptance
 * is what makes the refusals attributable to the violations rather than to the
 * coin, the key or the fee.
 */
async function run ({ broadcast = false } = {}) {
  const wallet = require('./wallet')
  const woc = require('./woc')
  const w = wallet.load()
  const utxos = await wallet.utxos()
  if (!utxos.length) throw new Error('no funding UTXO to probe with')
  const u = utxos[0]
  const lockingScript = bsv.Script.buildPublicKeyHashOut(w.addressObj)

  const order = ['MINIMALDATA', 'CLEANSTACK', 'SIGPUSHONLY', 'LOW_S', 'baseline']
  const results = []

  for (const name of order) {
    const probe = PROBES[name]
    const tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
      prevTxId: Buffer.from(u.txId, 'hex'), outputIndex: u.outputIndex,
      script: new bsv.Script(), sequenceNumber: 0xffffffff
    }), lockingScript, u.satoshis)
    tx.to(w.address, u.satoshis - 300)

    const sig = signInput(tx, w.privateKey, lockingScript, u.satoshis, { highS: !!probe.highS })
    const unlockingScript = probe.build(sig, w.publicKey.toBuffer())
    tx.inputs[0].setScript(unlockingScript)

    const iso = classify(name, unlockingScript, lockingScript, tx, u.satoshis)
    const row = { name, flag: probe.flag, describe: probe.describe, ...iso }

    if (broadcast && iso.isolated) {
      const raw = tx.serialize({ disableIsFullySigned: true, disableDustOutputs: true })
      try {
        const txid = await woc.broadcast(raw)
        row.network = 'ACCEPTED ' + String(txid).replace(/"/g, '')
        if (name === 'baseline') { wallet.recordSpent(tx); wallet.recordOutputs(tx) }
      } catch (err) {
        const m = err.message.match(/unexpected response code \d+: (.*)"/)
        row.network = 'refused: ' + (m ? m[1] : err.message.slice(0, 90))
      }
    }
    results.push(row)
  }
  return results
}

module.exports = { PROBES, MEASURED, DEPLOYED_PROBE, signInput, isolate, classify, run }
