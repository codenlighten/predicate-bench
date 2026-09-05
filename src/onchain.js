'use strict'

const fs = require('fs')
const path = require('path')
const bsv = require('@smartledger/bsv')
const BN = bsv.crypto.BN
const Interpreter = bsv.Script.Interpreter

const cfg = require('./config')
const wallet = require('./wallet')
const woc = require('./woc')
const { signInput, SIGHASH_ALL_FORKID } = require('./harness')

const LEDGER = path.join(__dirname, '..', 'deployments.json')

function readLedger () {
  return fs.existsSync(LEDGER) ? JSON.parse(fs.readFileSync(LEDGER, 'utf8')) : []
}

// Return one deployed record by predicate name, or fail with an actionable message
// instead of a raw `undefined.params` crash. The mainnet receipts (deployments.json)
// are committed to the repo, so a fresh clone finds them; this only bites if the file
// was deleted or a family was never deployed.
function requireDeployed (name, { latest = true } = {}) {
  const matches = readLedger().filter((x) => x.predicate === name)
  const rec = latest ? matches[matches.length - 1] : matches[0]
  if (!rec) {
    throw new Error(
      `deployments.json has no '${name}' record. The mainnet receipts are committed to ` +
      `the repo — restore them with \`git checkout -- deployments.json\`, or redeploy the ` +
      `family with its scripts/deploy-*.js.`
    )
  }
  return rec
}

function appendLedger (entry) {
  const all = readLedger()
  all.push(entry)
  fs.writeFileSync(LEDGER, JSON.stringify(all, null, 2))
  return entry
}

/** sat/KB applied to a byte count, never rounding down to free. */
function feeFor (bytes) {
  return Math.max(1, Math.ceil(bytes * cfg.feePerKb / 1000))
}

function loadPredicate (name) {
  return require(path.join(__dirname, 'predicates', name + '.js'))
}

/**
 * Park `testOutputSats` behind a predicate's locking script and broadcast.
 * The output is non-standard by design; only the locking script decides who
 * gets it back, which is the point of the exercise.
 */
async function deploy (predicateName, params = {}, { dryRun = false } = {}) {
  const w = wallet.load()
  const predicate = loadPredicate(predicateName)
  const ctx = { ...params, key: w.privateKey }
  const lockingScript = predicate.lock(ctx)

  const utxos = await wallet.utxos()
  if (!utxos.length) throw new Error(`funding wallet ${w.address} has no UTXOs`)

  const tx = new bsv.Transaction()
    .from(utxos)
    .addOutput(new bsv.Transaction.Output({
      script: lockingScript,
      satoshis: cfg.testOutputSats
    }))
    .change(w.address)
    .feePerKb(cfg.feePerKb)
    .sign(w.privateKey)

  const rawtx = tx.serialize()
  const record = {
    network: cfg.network,
    predicate: predicateName,
    params,
    txid: tx.id,
    vout: 0,
    satoshis: cfg.testOutputSats,
    lockAsm: lockingScript.toASM(),
    lockHex: lockingScript.toHex(),
    fee: tx.getFee(),
    at: new Date().toISOString()
  }

  if (dryRun) return { ...record, rawtx, broadcast: false }

  const txid = await woc.broadcast(rawtx)
  record.txid = typeof txid === 'string' ? txid.replace(/"/g, '') : tx.id
  wallet.recordSpent(tx)
  wallet.recordOutputs(tx)
  appendLedger(record)
  return { ...record, rawtx, broadcast: true }
}

/**
 * Spend a deployed output back to the funding wallet.
 *
 * The local Interpreter runs BEFORE the broadcast, against the exact bytes
 * that would go out. A predicate that fails here fails on chain too, and
 * finding that out locally costs nothing.
 */
async function unlock (deployment, params = {}, opts = {}) {
  // The unlocking script's size is not knowable until it has been built, and
  // for a preimage predicate building it depends on the output amount, which
  // depends on the fee, which depends on the size. Build once to measure, then
  // rebuild at the real rate. Converges immediately in practice; the loop is
  // there so it cannot silently under-pay if it does not.
  let estimate = 300
  let last = null
  for (let pass = 0; pass < 3; pass++) {
    last = await buildUnlock(deployment, params, opts, estimate)
    const actual = Math.ceil(last.rawtx.length / 2)
    if (last.fee >= feeFor(actual) || params.fee !== undefined) break
    estimate = actual
  }
  if (opts.dryRun || (!last.verifiedLocally && !opts.force)) return publicResult(last)

  const txid = await woc.broadcast(last.rawtx)
  wallet.recordSpent(last.tx)
  wallet.recordOutputs(last.tx)
  const broadcastTxid = typeof txid === 'string' ? txid.replace(/"/g, '') : last.txid

  // A self-recreating covenant hands its coins to a fresh UTXO carrying the
  // same locking script. That output belongs to no wallet — only the script can
  // spend it — so record it as a deployment in its own right, or the chain
  // stops here with the coins live and unreachable by any command.
  const recreated = recordContinuation(deployment, last, broadcastTxid)
  return { ...publicResult(last), broadcast: true, txid: broadcastTxid, recreated }
}

/**
 * Register the UTXO a covenant leaves behind.
 *
 * Wrapped so a bookkeeping failure can never be silent: the transaction is
 * already on chain by this point, and losing the record of a covenant output
 * means losing the coins — no wallet owns them, only the script can spend
 * them, and nothing else knows they exist.
 */
function recordContinuation (deployment, last, broadcastTxid) {
  const recreated = []
  try {
    const cont = last.continuation
    const wanted = cont ? cont.script.toHex() : deployment.lockHex
    last.tx.outputs.forEach((o, i) => {
      if (o.script.toHex() !== wanted) return
      recreated.push(appendLedger({
        ...deployment,
        params: cont ? cont.params : deployment.params,
        lockAsm: cont ? cont.script.toASM() : deployment.lockAsm,
        lockHex: wanted,
        txid: broadcastTxid,
        vout: i,
        satoshis: o.satoshis,
        hopFrom: deployment.txid,
        hop: (deployment.hop || 0) + 1,
        at: new Date().toISOString()
      }))
    })
  } catch (err) {
    console.error(
      `\nBROADCAST SUCCEEDED but recording it failed: ${err.message}\n` +
      `  txid ${broadcastTxid}\n` +
      `  Add it to ${LEDGER} by hand before spending anything else, or the ` +
      `covenant output is live and unreachable.\n`)
  }
  return recreated
}

async function buildUnlock (deployment, params, opts, estimatedUnlockSize) {
  const w = wallet.load()
  const predicate = loadPredicate(deployment.predicate)
  const lockingScript = bsv.Script.fromHex(deployment.lockHex)
  const satoshis = deployment.satoshis

  // A predicate that reads nSequence has to be given an input it can accept.
  // bsv defaults to 0xffffffff, which is exactly the value a timelock must
  // refuse, so let the predicate declare its own default and keep the explicit
  // param as the override.
  const defaults = predicate.unlockDefaults || {}
  const sequenceNumber = params.sequenceNumber ?? defaults.sequenceNumber ?? 0xffffffff

  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(deployment.txid, 'hex'),
    outputIndex: deployment.vout,
    script: new bsv.Script(),
    sequenceNumber
  }), lockingScript, satoshis)

  const ctx0 = { ...deployment.params, ...params, key: w.privateKey, lockingScript, satoshis }
  const dictated = predicate.outputs && predicate.outputs(ctx0)

  let fee
  if (dictated) {
    // The covenant fixes the outputs, so the fee is whatever the input exceeds
    // them by. It is not ours to choose: trimming an output to pay a different
    // fee changes hashOutputs and the coin stops being spendable at all.
    dictated.forEach(o => tx.addOutput(o))
    fee = satoshis - dictated.reduce((sum, o) => sum + o.satoshis, 0)
    if (fee < 0) throw new Error(`committed outputs exceed the ${satoshis} sat input by ${-fee}`)
  } else {
    fee = params.fee ?? feeFor(estimatedUnlockSize)
    if (satoshis - fee <= 0) throw new Error(`fee ${fee} exceeds the ${satoshis} sat output`)
    tx.to(w.address, satoshis - fee)
  }
  if (params.nLockTime !== undefined) tx.nLockTime = params.nLockTime

  const ctx = {
    ...deployment.params,
    ...params,
    key: w.privateKey,
    tx,
    inputIndex: 0,
    lockingScript,
    satoshis,
    satoshisBN: new BN(satoshis),
    sign: (privateKey, sighashType = SIGHASH_ALL_FORKID) =>
      signInput(tx, privateKey || w.privateKey, lockingScript, satoshis, 0, sighashType)
  }

  const unlockingScript = predicate.unlock(ctx)
  tx.inputs[0].setScript(unlockingScript)

  // Consensus flags are what the chain enforces; a node will also refuse to
  // RELAY a transaction that breaks standardness policy, and MINIMALDATA is
  // the policy bit these scripts trip. Verifying under consensus alone passes
  // locally and then fails at the broadcast, which costs a round trip and
  // teaches nothing. Check policy here, and report both.
  const consensusFlags = Interpreter.currentConsensusFlags()
  const policy = require('./clauses').policyFlags()

  const consensusRun = new Interpreter()
  const consensusOk = consensusRun.verify(
    unlockingScript, lockingScript, tx, 0, consensusFlags, new BN(satoshis))

  const interp = new Interpreter()
  const ok = interp.verify(
    unlockingScript, lockingScript, tx, 0, policy, new BN(satoshis))

  // Work out the successor UTXO BEFORE anything is broadcast. Computing it
  // afterwards means a failure there lands after the irreversible step, which
  // is how this went wrong: a ReferenceError past the broadcast left the coin
  // moved on chain and untracked locally. Decide what will be recorded first,
  // then broadcast, then record.
  const continuation = predicate.continuation
    ? predicate.continuation({ ...ctx0, lockingScript, satoshis })
    : null

  const result = {
    tx,
    continuation,
    verifiedLocally: ok,
    consensusOk,
    standardnessOnly: consensusOk && !ok,
    error: ok ? null : interp.errstr,
    eraHint: interp.eraHint || null,
    unlockAsm: unlockingScript.toASM(),
    // Two of bsv's client-side serialization checks are disabled here.
    //
    // isFullySigned: a custom unlocking script is not a script kind the
    // library recognises, so the heuristic cannot read it and refuses. The
    // real gate is the Interpreter run above — consensus plus policy flags,
    // not a heuristic.
    //
    // dustOutputs: a covenant's output amount is dictated by the covenant, so
    // a fixed 546-sat floor in the library can make a perfectly spendable
    // coin unserializable. BSV removed the dust limit from node policy; the
    // library's threshold is neither consensus nor relay policy, and the node
    // is the authority on what it will accept. Verified by broadcasting a
    // 450-sat output, which relayed.
    rawtx: tx.serialize({ disableIsFullySigned: true, disableDustOutputs: true }),
    txid: tx.id,
    fee
  }

  return {
    ...result,
    broadcast: false,
    note: ok ? undefined : 'not broadcast — local verification failed'
  }
}

/** The tx is carried through the build passes for recordSpent; it is not
 *  something a caller wants printed, and serializing it buries everything. */
function publicResult (r) {
  const { tx, ...rest } = r
  return rest
}

module.exports = { deploy, unlock, readLedger, requireDeployed, appendLedger, loadPredicate, LEDGER }
