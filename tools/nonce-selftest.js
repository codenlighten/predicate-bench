'use strict'

const bsv = require('@smartledger/bsv')
const BN = bsv.crypto.BN
const N = bsv.crypto.Point.getN()
const HALF = N.shrn(1)
const rp = require('../src/predicates/rpuzzle')
const harness = require('../src/harness')

// An R-puzzle spend is supposed to release its nonce to anyone holding the
// signing key. That is the mechanism behind pay-per-segment streaming: the
// server cannot take the money without publishing the decryption key.
//
// It has a failure mode that testing does not surface, because it only bites
// half the time. BSV enforces LOW_S as MANDATORY — a high-s signature is
// refused with code 16, not merely unrelayed — so the signer negates s whenever
// it lands in the upper half, which negates the recovered nonce with it. A
// scheme built on the naive recovery works, then silently fails on the next
// segment, then works again.
//
// So this walks nonces until it has seen BOTH branches and checks recovery in
// each. If the library ever stops normalising s, the "flipped" branch stops
// appearing and this says so rather than passing vacuously.

let flipped = 0
let plain = 0
const problems = []

for (let i = 0; i < 60 && (flipped === 0 || plain === 0); i++) {
  const nonce = 'segment ' + i
  const d = bsv.PrivateKey.fromRandom()
  const { k } = rp.grindNonce(nonce)
  const res = harness.run(rp, { name: 'recovery', nonce, key: d })
  if (!res.ok) { problems.push(`nonce ${i}: the spend itself did not verify`); continue }

  const sig = bsv.crypto.Signature.fromTxFormat(res.unlockingScript.chunks[0].buf)
  const e = BN.fromBuffer(
    bsv.Transaction.Sighash.sighash(res.tx, sig.nhashtype, 0, res.lockingScript, new BN(1000)),
    { endian: 'little' })

  // What the signer would have produced before normalisation.
  const rawS = k.invm(N).mul(e.add(d.bn.mul(sig.r))).umod(N)
  const wasFlipped = rawS.cmp(HALF) > 0
  if (wasFlipped) flipped++; else plain++

  const naive = sig.s.invm(N).mul(e.add(sig.r.mul(d.bn))).umod(N)
  const recovered = rp.recoverNonce({
    tx: res.tx, lockingScript: res.lockingScript, satoshis: 1000,
    unlockingScript: res.unlockingScript, d
  })

  if (!recovered.eq(rp.canonicalNonce(k))) {
    problems.push(`nonce ${i}: canonical recovery disagreed with the real k`)
  }
  if (wasFlipped && naive.eq(k)) {
    problems.push(`nonce ${i}: s was flipped yet naive recovery matched — check the premise`)
  }
  if (!wasFlipped && !naive.eq(k)) {
    problems.push(`nonce ${i}: s was untouched yet naive recovery missed`)
  }
}

if (!flipped) problems.push('never observed a flipped s in 60 tries — is LOW_S still being applied?')
if (!plain) problems.push('never observed an untouched s in 60 tries')

for (const p of problems) console.log(`  ${p}`)
if (problems.length) {
  console.log(`\n${problems.length} problem(s) in nonce recovery`)
  process.exit(1)
}
console.log('nonce recovery survives LOW_S normalisation in both directions')
