'use strict'

const bsv = require('@smartledger/bsv')
const Interpreter = bsv.Script.Interpreter
const { policyFlags } = require('./clauses')
const BN = bsv.crypto.BN

// A predicate is only ever asked one question: does this unlocking script,
// prepended to this locking script, leave a true value on the stack under
// current consensus rules? Everything below exists to ask exactly that
// without touching the network.

// Any 32 bytes will do. The outpoint is data as far as the sighash is
// concerned, and this tx is never broadcast — but keep it fixed so a failing
// run reproduces byte-for-byte.
const MOCK_PREVOUT = Buffer.from(
  '0'.repeat(63) + '1', 'hex'
)

const SIGHASH_ALL_FORKID =
  bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID

/**
 * Build the transaction that spends `lockingScript`. Handed to the predicate's
 * unlock() so it can sign over the real thing — a covenant that reads its own
 * preimage needs the actual spending tx, not a stand-in.
 */
function buildSpendingTx ({ lockingScript, satoshis, payTo, fee = 0, nLockTime, sequenceNumber = 0xffffffff, outputs, siblings, prevTxId, prevVout }) {
  const tx = new bsv.Transaction()
  // A covenant that backtraces to its OWN funding transaction (lineage) needs
  // input 0's outpoint to be the real (HASH256(fundingTx), vout); otherwise the
  // fixed MOCK_PREVOUT stands in.
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: prevTxId ? (Buffer.isBuffer(prevTxId) ? prevTxId : Buffer.from(prevTxId, 'hex')) : MOCK_PREVOUT,
    outputIndex: prevVout ?? 0,
    script: new bsv.Script(),
    sequenceNumber
  }), lockingScript, satoshis)

  // Extra inputs, for a covenant that reasons about its SIBLINGS. The covenant
  // under test stays at index 0 and is the only one verified — but every input's
  // outpoint enters input 0's hashPrevouts, so a cross-input covenant needs a
  // real multi-input transaction, not a stand-in. Their scripts never run here,
  // so an empty unlocking script and a nominal value are enough.
  if (siblings) {
    for (const sib of siblings) {
      tx.addInput(new bsv.Transaction.Input({
        prevTxId: Buffer.isBuffer(sib.prevTxId) ? sib.prevTxId : Buffer.from(sib.prevTxId, 'hex'),
        outputIndex: sib.outputIndex,
        script: new bsv.Script(),
        sequenceNumber: sib.sequenceNumber ?? 0xffffffff
      }), sib.script || new bsv.Script().add(bsv.Opcode.OP_1), sib.satoshis ?? 1000)
    }
  }

  // A covenant that constrains its outputs must be the thing that supplies
  // them; paying change wherever we like would break its own commitment.
  if (outputs) {
    outputs.forEach(o => tx.addOutput(o))
  } else {
    const out = satoshis - fee
    if (out > 0) tx.to(payTo, out)
  }
  if (nLockTime !== undefined) tx.nLockTime = nLockTime
  return tx
}

/**
 * Sign an input over a custom subscript, and return the bytes a script
 * actually pushes: DER signature with the sighash type appended. Returning
 * the Signature object instead is the reliable way to produce a signature
 * that verifies everywhere except on chain.
 */
function signInput (tx, privateKey, lockingScript, satoshis, inputIndex = 0, sighashType = SIGHASH_ALL_FORKID) {
  const sig = bsv.Transaction.Sighash.sign(
    tx, privateKey, sighashType, inputIndex, lockingScript, new BN(satoshis)
  )
  return sig.toTxFormat()
}

/**
 * Run one case against the real interpreter.
 *
 * `flags` is deliberately left undefined by default: the interpreter then
 * resolves current mainnet consensus itself. Hand-assembling a flag word is
 * how you end up testing pre-Genesis limits by accident.
 */
function run (predicate, testCase = {}) {
  const name = testCase.name || predicate.name
  const satoshis = testCase.satoshis ?? predicate.satoshis ?? 1000
  const payTo = testCase.payTo || predicate.payTo || bsv.PrivateKey.fromRandom().toAddress()

  let lockingScript, unlockingScript, tx
  try {
    lockingScript = predicate.lock(testCase)

    // A cross-input covenant declares the sibling inputs it must be spent
    // beside. They are added before the grind so hashPrevouts is final.
    const siblings = predicate.siblings
      ? predicate.siblings({ ...testCase, lockingScript, satoshis })
      : testCase.siblings

    // A covenant that backtraces to its own funding tx declares input 0's real
    // outpoint (its funding txid and vout).
    const spend0 = predicate.spendOutpoint
      ? predicate.spendOutpoint({ ...testCase, lockingScript, satoshis })
      : { prevTxId: testCase.prevTxId, prevVout: testCase.prevVout }

    tx = buildSpendingTx({
      lockingScript,
      satoshis,
      payTo,
      outputs: predicate.outputs &&
        predicate.outputs({ ...testCase, lockingScript, satoshis }),
      fee: testCase.fee ?? 0,
      nLockTime: testCase.nLockTime,
      sequenceNumber: testCase.sequenceNumber ??
        (predicate.unlockDefaults && predicate.unlockDefaults.sequenceNumber),
      siblings,
      prevTxId: spend0 && spend0.prevTxId,
      prevVout: spend0 && spend0.prevVout
    })

    unlockingScript = predicate.unlock({
      tx,
      inputIndex: 0,
      lockingScript,
      satoshis,
      sighashType: testCase.sighashType,
      satoshisBN: new BN(satoshis),
      sign: (privateKey, sighashType) =>
        signInput(tx, privateKey, lockingScript, satoshis, 0, sighashType),
      ...testCase
    })

    tx.inputs[0].setScript(unlockingScript)
  } catch (err) {
    return { name, ok: false, phase: 'build', error: err.message }
  }

  // Verify under what a node will RELAY, not just what a block would accept.
  // Consensus alone hides MINIMALDATA and CLEANSTACK, and each of those cost a
  // broadcast to find. A case may still pass explicit flags to test an era.
  const interp = new Interpreter()
  const ok = interp.verify(
    unlockingScript, lockingScript, tx, 0,
    testCase.flags !== undefined ? testCase.flags : policyFlags(),
    new BN(satoshis)
  )

  return {
    name,
    ok,
    phase: ok ? 'verified' : 'verify',
    error: ok ? null : interp.errstr,
    eraHint: interp.eraHint || null,
    lockingScript,
    unlockingScript,
    tx,
    lockAsm: lockingScript.toASM(),
    unlockAsm: unlockingScript.toASM(),
    lockHex: lockingScript.toHex(),
    lockSize: lockingScript.toBuffer().length,
    unlockSize: unlockingScript.toBuffer().length,
    stack: (interp.stack || []).map(b => b.toString('hex'))
  }
}

/**
 * A predicate is worth nothing until you have also shown what it REFUSES.
 * Cases marked `shouldFail` invert: the case passes when verification fails.
 */
function suite (predicate, cases) {
  return cases.map(c => {
    const r = run(predicate, c)
    const passed = c.shouldFail ? !r.ok : r.ok
    // Carry the predicate and case through so a failure can be re-run under the
    // tracer without the reporter reconstructing it by hand.
    return { ...r, shouldFail: !!c.shouldFail, passed, predicate, testCase: c }
  })
}

module.exports = { run, suite, buildSpendingTx, signInput, SIGHASH_ALL_FORKID, MOCK_PREVOUT }
