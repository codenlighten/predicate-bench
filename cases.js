'use strict'

// The suite's cases, as data.
//
// They live apart from the runner so that tooling can read them directly
// instead of parsing test output. The audit needs to know which cases are
// refusals, and scraping stdout for that got it wrong on every predicate whose
// block happens to re-require its own module.

const bsv = require('@smartledger/bsv')

const key = bsv.PrivateKey.fromRandom()
const other = bsv.PrivateKey.fromRandom()

const beneficiary = bsv.PrivateKey.fromRandom().toAddress().toString()
const stranger = bsv.PrivateKey.fromRandom().toAddress().toString()

const runs = [
  [require('./src/predicates/p2pkh'), [
    { name: 'p2pkh: correct key spends', key },
    { name: 'p2pkh: wrong key is refused', key, wrongKey: other, shouldFail: true }
  ]],
  [require('./src/predicates/hashlock'), [
    { name: 'hashlock: correct preimage spends', secret: 'open sesame' },
    { name: 'hashlock: wrong preimage is refused', secret: 'open sesame', revealed: 'guess', shouldFail: true }
  ]],
  [require('./src/predicates/timelock'), [
    { name: 'timelock: non-final sequence, nLockTime at the floor',
      notBefore: 800000, sequenceNumber: 0xfffffffe },
    { name: 'timelock: FINAL sequence is refused (it would disable nLockTime)',
      notBefore: 800000, sequenceNumber: 0xffffffff, shouldFail: true },
    { name: 'timelock: without the sequence check that attack succeeds',
      notBefore: 800000, sequenceNumber: 0xffffffff, omitSequenceCheck: true },
    { name: 'timelock: post-2038 floor spends when sign-padded',
      notBefore: 2415919104, sequenceNumber: 0xfffffffe },
    { name: 'timelock: post-2038 floor is unspendable without the pad',
      notBefore: 2415919104, sequenceNumber: 0xfffffffe, omitSignPad: true, shouldFail: true }
  ]],
  [require('./src/predicates/covenant'), [
    { name: 'covenant: paying the committed output spends',
      payTo: beneficiary, payAmount: 900 },
    { name: 'covenant: paying a stranger is refused',
      payTo: beneficiary, payAmount: 900, actualPayTo: stranger, shouldFail: true },
    { name: 'covenant: paying one satoshi less is refused',
      payTo: beneficiary, payAmount: 900, actualPayAmount: 899, shouldFail: true },
    { name: 'covenant: paying one satoshi more is refused',
      payTo: beneficiary, payAmount: 900, actualPayAmount: 901, shouldFail: true }
  ]],
  [require('./src/predicates/perpetual'), [
    { name: 'perpetual: recreating itself minus the fee spends',
      hopFee: 150, satoshis: 1000 },

    // The whole point is that the coin cannot leave. Each of these is a way out.
    { name: 'perpetual: paying a plain address instead is refused',
      hopFee: 150, satoshis: 1000, shouldFail: true,
      actualScript: bsv.Script.buildPublicKeyHashOut(stranger) },
    { name: 'perpetual: skimming one satoshi extra is refused',
      hopFee: 150, satoshis: 1000, actualAmount: 849, shouldFail: true },
    { name: 'perpetual: paying itself one satoshi too much is refused',
      hopFee: 150, satoshis: 1000, actualAmount: 851, shouldFail: true },
    { name: 'perpetual: adding a second output is refused',
      hopFee: 150, satoshis: 1000, extraOutput: 100, shouldFail: true },

    // Under SIGHASH_SINGLE or NONE, hashOutputs covers one output or nothing,
    // so the equality would be binding something other than the output set.
    { name: 'perpetual: SIGHASH_SINGLE is refused',
      hopFee: 150, satoshis: 1000, shouldFail: true,
      sighashType: bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_FORKID },
    { name: 'perpetual: SIGHASH_NONE is refused',
      hopFee: 150, satoshis: 1000, shouldFail: true,
      sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID },

    // Hops 2 and 3, at the values the chain actually reaches.
    { name: 'perpetual: hop 2 (850 -> 700)', hopFee: 150, satoshis: 850 },
    { name: 'perpetual: hop 3 (700 -> 550)', hopFee: 150, satoshis: 550 }
  ]],
  [require('./src/predicates/composed'), (() => {
    const base = { payTo: beneficiary, payAmount: 900, notBefore: 964000, sequenceNumber: 0xfffffffe }
    const SIG = bsv.crypto.Signature
    return [
      { ...base, name: 'composed: all clauses satisfied spends' },

      // One clause violated at a time. Each must fail on its own.
      { ...base, name: 'composed: wrong destination is refused',
        actualPayTo: stranger, shouldFail: true },
      { ...base, name: 'composed: wrong amount is refused',
        actualPayAmount: 899, shouldFail: true },
      { ...base, name: 'composed: nLockTime below the floor is refused',
        grindFrom: 900000, shouldFail: true },
      { ...base, name: 'composed: final sequence is refused',
        sequenceNumber: 0xffffffff, shouldFail: true },
      { ...base, name: 'composed: SIGHASH_SINGLE is refused',
        sighashType: SIG.SIGHASH_SINGLE | SIG.SIGHASH_FORKID, shouldFail: true },

      // Drop a clause and the matching attack lands: proof each one is load-bearing.
      { ...base, name: 'composed: without the sequence clause, a final input passes',
        omit: ['sequence'], sequenceNumber: 0xffffffff },
      { ...base, name: 'composed: without the locktime clause, an early spend passes',
        omit: ['locktime'], grindFrom: 900000 },
      { ...base, name: 'composed: without the outputs clause, funds can be redirected',
        omit: ['outputs'], actualPayTo: stranger },

      // Same clauses, different order. Only holds if every clause restores the stack.
      { ...base, name: 'composed: clause order reversed still spends',
        order: ['outputs', 'locktime', 'sequence', 'sighash'] },
      { ...base, name: 'composed: another order still spends',
        order: ['locktime', 'outputs', 'sighash', 'sequence'] },
      { ...base, name: 'composed: reordered, wrong destination still refused',
        order: ['outputs', 'locktime', 'sequence', 'sighash'],
        actualPayTo: stranger, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/metered'), (() => {
    const metered = require('./src/predicates/metered')
    const settleTo = bsv.PrivateKey.fromRandom().toAddress()
    const base = { maxHops: 3, hopFee: 150, satoshis: 1000, redeemTo: settleTo }
    return [
      { ...base, name: 'metered: hop 0 -> 1 spends', counter: 0 },
      { ...base, name: 'metered: hop 1 -> 2 spends', counter: 1, satoshis: 850 },
      { ...base, name: 'metered: hop 2 -> 3 spends', counter: 2, satoshis: 700 },

      // The meter is the point. At the limit nothing moves it, whatever the spend.
      { ...base, name: 'metered: at maxHops the hop branch is closed',
        counter: 3, satoshis: 550, shouldFail: true },

      // The counter must advance by exactly one. Not zero, not two, not back.
      { ...base, name: 'metered: leaving the counter unchanged is refused',
        counter: 0, actualCounter: 0, shouldFail: true },
      { ...base, name: 'metered: skipping the counter forward is refused',
        counter: 0, actualCounter: 2, shouldFail: true },
      { ...base, name: 'metered: winding the counter back is refused',
        counter: 1, satoshis: 850, actualCounter: 0, shouldFail: true },

      // Escaping the meter: strip the state, or rewrite the terms.
      { ...base, name: 'metered: paying a plain address is refused',
        counter: 0, shouldFail: true,
        actualScript: bsv.Script.buildPublicKeyHashOut(stranger) },
      { ...base, name: 'metered: raising maxHops in the successor is refused',
        counter: 0, shouldFail: true,
        actualScript: metered.buildScript({ counter: 1, maxHops: 99, hopFee: 150, redeemTo: settleTo }) },
      { ...base, name: 'metered: lowering the hop fee in the successor is refused',
        counter: 0, shouldFail: true,
        actualScript: metered.buildScript({ counter: 1, maxHops: 3, hopFee: 1, redeemTo: settleTo }) },

      { ...base, name: 'metered: redirecting the settlement address is refused',
        counter: 0, shouldFail: true,
        actualScript: metered.buildScript({ counter: 1, maxHops: 3, hopFee: 150, redeemTo: stranger }) },
      { ...base, name: 'metered: skimming value is refused',
        counter: 0, actualAmount: 800, shouldFail: true },
      { ...base, name: 'metered: SIGHASH_NONE is refused', counter: 0, shouldFail: true,
        sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID },

      // The redemption branch. The two guards are exact complements, so every
      // counter value admits exactly one branch — no state is stuck, and no
      // state opens both paths.
      { ...base, name: 'metered: at maxHops it redeems to the settlement address',
        counter: 3, satoshis: 550, branch: 'redeem' },
      { ...base, name: 'metered: redeeming before maxHops is refused',
        counter: 1, satoshis: 850, branch: 'redeem', shouldFail: true },
      { ...base, name: 'metered: redeeming to a different address is refused',
        counter: 3, satoshis: 550, branch: 'redeem', shouldFail: true,
        actualScript: bsv.Script.buildPublicKeyHashOut(stranger) },
      { ...base, name: 'metered: redeeming the wrong amount is refused',
        counter: 3, satoshis: 550, branch: 'redeem', actualAmount: 500, shouldFail: true },
      { ...base, name: 'metered: hopping past maxHops is still refused',
        counter: 3, satoshis: 550, branch: 'hop', shouldFail: true }
    ]
  })()],
  [require('./src/predicates/titled'), (() => {
    const titled = require('./src/predicates/titled')
    const alice = bsv.PrivateKey.fromRandom()
    const bob = bsv.PrivateKey.fromRandom()
    const mallory = bsv.PrivateKey.fromRandom()
    const base = {
      owner: alice.toAddress(), newOwner: bob.toAddress(),
      transferFee: 300, satoshis: 2000, ownerKey: alice
    }
    return [
      { ...base, name: 'titled: the owner hands the title to a new owner' },
      { ...base, name: 'titled: the owner may hand it to themselves',
        newOwner: alice.toAddress() },

      // Possession of the UTXO is not authority. The key named inside it is.
      { ...base, name: 'titled: a stranger cannot transfer it',
        signWith: mallory, shouldFail: true },
      { ...base, name: 'titled: a stranger cannot redeem it',
        branch: 'redeem', signWith: mallory, shouldFail: true },

      // Only the owner field is free. Every other byte of the contract is not.
      { ...base, name: 'titled: rewriting the fee in the successor is refused',
        shouldFail: true,
        actualScript: titled.buildScript({ owner: bob.toAddress(), transferFee: 1 }) },
      { ...base, name: 'titled: escaping to a plain address is refused',
        shouldFail: true,
        actualScript: bsv.Script.buildPublicKeyHashOut(stranger) },
      // The signature commits to the outputs, so a third party cannot redirect
      // a transfer: claiming one successor while paying another fails.
      { ...base, name: 'titled: claiming a successor the payment does not match is refused',
        pushNewOwner: mallory.toAddress(), shouldFail: true },
      { ...base, name: 'titled: skimming value is refused',
        actualAmount: 1500, shouldFail: true },

      // The exit: a title can always leave, but only to the key holding it.
      { ...base, name: 'titled: the owner cashes out to their own key',
        branch: 'redeem' },
      { ...base, name: 'titled: redeeming to somebody else is refused',
        branch: 'redeem', shouldFail: true,
        actualScript: bsv.Script.buildPublicKeyHashOut(stranger) },
      { ...base, name: 'titled: redeeming the wrong amount is refused',
        branch: 'redeem', actualAmount: 1000, shouldFail: true },

      { ...base, name: 'titled: SIGHASH_NONE is refused', shouldFail: true,
        sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID },

      // Second hop: bob now holds it and alice does not.
      { ...base, name: 'titled: after transfer, the new owner can move it',
        owner: bob.toAddress(), newOwner: mallory.toAddress(), ownerKey: bob, satoshis: 1700 },
      { ...base, name: 'titled: after transfer, the old owner cannot',
        owner: bob.toAddress(), newOwner: mallory.toAddress(), ownerKey: bob,
        signWith: alice, satoshis: 1700, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/royalty'), (() => {
    const royalty = require('./src/predicates/royalty')
    const alice = bsv.PrivateKey.fromRandom()
    const bob = bsv.PrivateKey.fromRandom()
    const mallory = bsv.PrivateKey.fromRandom()
    const creator = bsv.PrivateKey.fromRandom().toAddress()
    const base = {
      owner: alice.toAddress(), newOwner: bob.toAddress(), beneficiary: creator,
      royaltyBps: 250, transferFee: 400, satoshis: 4000, ownerKey: alice
    }
    return [
      { ...base, name: 'royalty: transfer pays the creator and moves the title' },

      // The new mechanic: hashOutputs is a hash over the outputs IN SEQUENCE.
      { ...base, name: 'royalty: dropping the royalty output is refused',
        dropRoyalty: true, shouldFail: true },
      { ...base, name: 'royalty: the same two outputs in the wrong ORDER is refused',
        swapOutputs: true, shouldFail: true },

      // The amount is computed by the script, so neither direction is available.
      { ...base, name: 'royalty: underpaying the creator is refused',
        actualRoyalty: 99, shouldFail: true },
      { ...base, name: 'royalty: overpaying the creator is refused',
        actualRoyalty: 101, shouldFail: true },
      { ...base, name: 'royalty: paying the royalty to somebody else is refused',
        actualBeneficiary: mallory.toAddress(), shouldFail: true },
      { ...base, name: 'royalty: skimming the remainder is refused',
        actualAmount: 3600, shouldFail: true },

      // The terms travel with the title and a spender cannot edit them.
      { ...base, name: 'royalty: lowering the rate in the successor is refused',
        shouldFail: true,
        actualScript: royalty.buildScript({ owner: bob.toAddress(), beneficiary: creator,
          royaltyBps: 1, transferFee: 400 }) },
      { ...base, name: 'royalty: redirecting future royalties is refused',
        shouldFail: true,
        actualScript: royalty.buildScript({ owner: bob.toAddress(), beneficiary: mallory.toAddress(),
          royaltyBps: 250, transferFee: 400 }) },
      { ...base, name: 'royalty: escaping to a plain address is refused',
        actualScript: bsv.Script.buildPublicKeyHashOut(stranger), shouldFail: true },

      { ...base, name: 'royalty: a stranger cannot transfer it',
        signWith: mallory, shouldFail: true },

      // Leaving the covenant is a sale too.
      { ...base, name: 'royalty: cashing out also pays the creator', branch: 'redeem' },
      { ...base, name: 'royalty: cashing out without paying is refused',
        branch: 'redeem', dropRoyalty: true, shouldFail: true },
      { ...base, name: 'royalty: a stranger cannot cash it out',
        branch: 'redeem', signWith: mallory, shouldFail: true },

      { ...base, name: 'royalty: SIGHASH_NONE is refused', shouldFail: true,
        sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID },

      // Second hop: the rate is proportional, so the royalty falls with the value.
      { ...base, name: 'royalty: second hop, creator paid again on the lower value',
        owner: bob.toAddress(), newOwner: mallory.toAddress(), ownerKey: bob, satoshis: 3500 },
      { ...base, name: 'royalty: after transfer the old owner cannot move it',
        owner: bob.toAddress(), newOwner: mallory.toAddress(), ownerKey: bob,
        signWith: alice, satoshis: 3500, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/registry'), (() => {
    const R = require('./src/predicates/registry')
    const alice = bsv.PrivateKey.fromRandom()
    const bob = bsv.PrivateKey.fromRandom()
    const mallory = bsv.PrivateKey.fromRandom()
    const rec = (o) => ({ owner: alice.toAddress(), edition: 7, transfers: 0, maxTransfers: 3, ...o })
    const base = { record: rec(), newOwner: bob.toAddress(), transferFee: 400,
                   satoshis: 5000, ownerKey: alice }
    const alt = (over, fee = 400) =>
      R.buildScript({ record: rec({ owner: bob.toAddress(), transfers: 1, ...over }), transferFee: fee })
    return [
      { ...base, name: 'registry: transfer advances the record' },
      { ...base, name: 'registry: transfers 1 -> 2 spends',
        record: rec({ transfers: 1 }) },
      { ...base, name: 'registry: transfers 2 -> 3 spends (the last one allowed)',
        record: rec({ transfers: 2 }) },
      { ...base, name: 'registry: at maxTransfers the record cannot advance',
        record: rec({ transfers: 3 }), shouldFail: true },

      // INCREMENT: computed, so only one successor exists.
      { ...base, name: 'registry: leaving transfers unchanged is refused',
        actualScript: alt({ transfers: 0 }), shouldFail: true },
      { ...base, name: 'registry: skipping transfers forward is refused',
        actualScript: alt({ transfers: 2 }), shouldFail: true },

      // KEEP: immutable fields must survive the hop untouched.
      { ...base, name: 'registry: editing the edition is refused',
        actualScript: alt({ edition: 8 }), shouldFail: true },
      { ...base, name: 'registry: raising maxTransfers is refused',
        actualScript: alt({ maxTransfers: 99 }), shouldFail: true },
      { ...base, name: 'registry: rewriting the fee is refused',
        actualScript: alt({}, 1), shouldFail: true },

      // REPLACE: free, but only the owner may exercise it.
      { ...base, name: 'registry: a stranger cannot transfer',
        signWith: mallory, shouldFail: true },
      { ...base, name: 'registry: claiming an owner the payment does not match is refused',
        pushNewOwner: mallory.toAddress(), shouldFail: true },

      { ...base, name: 'registry: escaping to a plain address is refused',
        actualScript: bsv.Script.buildPublicKeyHashOut(stranger), shouldFail: true },
      { ...base, name: 'registry: skimming value is refused',
        actualAmount: 4000, shouldFail: true },
      { ...base, name: 'registry: SIGHASH_NONE is refused', shouldFail: true,
        sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID },

      { ...base, name: 'registry: the owner cashes out', branch: 'redeem' },
      { ...base, name: 'registry: a stranger cannot cash out',
        branch: 'redeem', signWith: mallory, shouldFail: true },
      { ...base, name: 'registry: cashing out is allowed even at maxTransfers',
        record: rec({ transfers: 3 }), branch: 'redeem' },

      { ...base, name: 'registry: after transfer the old owner cannot move it',
        record: rec({ owner: bob.toAddress(), transfers: 1 }), ownerKey: bob,
        newOwner: mallory.toAddress(), signWith: alice, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/multisig'), (() => {
    const multisig = require('./src/predicates/multisig')
    const keys = multisig.example().keys
    const outsider = bsv.PrivateKey.fromRandom()
    const base = { m: 2, keys, satoshis: 5000 }
    return [
      { ...base, name: 'multisig: two of three signs' },
      { ...base, name: 'multisig: a different valid pair also signs', signWith: [0, 2] },
      { ...base, name: 'multisig: the last two sign', signWith: [1, 2] },

      // The one that surprises people: CHECKMULTISIG walks both lists in a
      // single pass, so a signature that does not match the key it is looking
      // at is never retried against the others.
      { ...base, name: 'multisig: two VALID signatures in the wrong order are refused',
        signWith: [1, 0], shouldFail: true },

      { ...base, name: 'multisig: one signature short is refused',
        signWith: [0], shouldFail: true },
      { ...base, name: 'multisig: the same key twice is refused',
        signWith: [0, 0], shouldFail: true },
      { ...base, name: 'multisig: an outsider cannot substitute for a signer',
        signWith: [0, 1], impostor: { at: 1, key: outsider }, shouldFail: true },

      // The off-by-one element CHECKMULTISIG pops but does not use.
      { ...base, name: 'multisig: a non-empty dummy is refused',
        dummy: bsv.Opcode.OP_1, shouldFail: true },

      // Unlike every covenant here, a bare multisig constrains no outputs — so
      // it has no reason to care which sighash type was used, and does not.
      // Asserting a refusal here was a wrong premise, not a missing guard.
      { ...base, name: 'multisig: SIGHASH_NONE also spends, since no outputs are constrained',
        sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID },

      { ...base, name: 'multisig: 1-of-3 spends with any single key', m: 1, signWith: [2] },
      { ...base, name: 'multisig: 3-of-3 needs all three', m: 3, signWith: [0, 1, 2] },
      { ...base, name: 'multisig: 3-of-3 with two is refused', m: 3, signWith: [0, 1], shouldFail: true }
    ]
  })()],
  [require('./src/predicates/htlc'), (() => {
    const htlc = require('./src/predicates/htlc')
    const ex = htlc.example()
    const mallory = bsv.PrivateKey.fromRandom()
    const base = { ...ex, satoshis: 5000, sequenceNumber: 0xfffffffe }
    return [
      // The claim path: immediate, cheap, and needs no preimage at all.
      { ...base, name: 'htlc: the recipient claims by revealing the secret' },
      { ...base, name: 'htlc: claiming works regardless of the locktime floor',
        notBefore: 4000000000 },
      { ...base, name: 'htlc: a wrong secret is refused', revealed: 'guess', shouldFail: true },
      { ...base, name: 'htlc: the sender cannot take the claim path',
        signWith: ex.sender, shouldFail: true },
      { ...base, name: 'htlc: a stranger cannot claim even with the secret',
        signWith: mallory, shouldFail: true },

      // The refund path: gated on nLockTime, which on BSV means OP_PUSH_TX.
      { ...base, name: 'htlc: the sender refunds at the floor', branch: 'refund' },
      { ...base, name: 'htlc: refunding below the floor is refused',
        branch: 'refund', actualNotBefore: 900000, shouldFail: true },
      { ...base, name: 'htlc: the recipient cannot take the refund path',
        branch: 'refund', signWith: ex.recipient, shouldFail: true },
      { ...base, name: 'htlc: a stranger cannot refund',
        branch: 'refund', signWith: mallory, shouldFail: true },
      { ...base, name: 'htlc: refunding with a FINAL sequence is refused',
        branch: 'refund', sequenceNumber: 0xffffffff, shouldFail: true },
      { ...base, name: 'htlc: SIGHASH_NONE on the refund path is refused',
        branch: 'refund', shouldFail: true,
        sighashType: bsv.crypto.Signature.SIGHASH_NONE | bsv.crypto.Signature.SIGHASH_FORKID }
    ]
  })()],
  [require('./src/predicates/rpuzzle'), [
    { name: 'rpuzzle: the committed nonce spends',
      nonce: 'the session key', key },

    { name: 'rpuzzle: a different nonce is refused',
      nonce: 'the session key', key, wrongNonce: 'some other key', shouldFail: true },

    // Not a loophole — the design. The lock commits to k, never to a key, so
    // whoever holds k can sign under any identity they like. That is what lets
    // a payer verify the spend without knowing who the streaming server is.
    { name: 'rpuzzle: a completely unrelated key signs, and it spends',
      nonce: 'the session key', key, signingKey: other },

    // And the cost of that: once k is known the coin is anyone's. This is the
    // same case from the attacker's side.
    { name: 'rpuzzle: an attacker who learned k spends it out from under you',
      nonce: 'the session key', key, signingKey: bsv.PrivateKey.fromRandom() },

    { name: 'rpuzzle: right nonce, pubkey that did not sign, is refused',
      nonce: 'the session key', key, mismatchedPubKey: other, shouldFail: true },

    // WP1605 Claim 2, as an attack. This PASSES, and it is the most important
    // case in the block: one signature observed in the mempool is replayed into
    // a different transaction under a public key solved for rather than owned.
    // No k, no d, no private key anywhere.
    { name: 'rpuzzle: an observed signature is replayed onto another transaction (Claim 2)',
      nonce: 'the session key', key, forge: true }
  ]],
  [require('./src/predicates/companion'), (() => {
    // Real, non-palindromic txids — the reversal bug hides behind symmetric ones.
    const comp = { prevTxId: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', outputIndex: 1 }
    const other = { prevTxId: 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100', outputIndex: 0 }
    const third = { prevTxId: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', outputIndex: 2 }
    return [
      { name: 'companion: spends beside the required input', companion: comp },
      { name: 'companion: still spends with an extra input trailing (companion mid-vector)',
        companion: comp, extraSiblings: [third] },

      { name: 'companion: refused when a DIFFERENT input is present instead',
        companion: comp, wrongCompanion: other, shouldFail: true },
      { name: 'companion: refused when the spender lies about the outpoint layout',
        companion: comp, claimAbsent: true, shouldFail: true },

      // groupSize pins the batch size: no padding the transaction with extra inputs.
      { name: 'companion: groupSize=2 spends with exactly two inputs',
        companion: comp, groupSize: 2 },
      { name: 'companion: groupSize=2 refuses a third, padded input',
        companion: comp, groupSize: 2, extraSiblings: [third], shouldFail: true }
    ]
  })()],
  [require('./src/predicates/token'), (() => {
    const merge = { branch: 'merge', balance: 300, sibBalance: 200 }
    const split = { branch: 'split', balance: 500, splitA: 300, splitB: 200 }
    // a sibling that itself came from a split (a two-output funding tx)
    const fromSplit = { branch: 'merge', balance: 300, sibSplit: true, sibB0: 70, sibB1: 130 }
    return [
      // --- merge: a mint/merge-sourced sibling (single-output funding) ---
      { ...merge, name: 'token: merge sums the balances, 300+200 -> 500' },
      { ...merge, name: 'token: a different split of the same total merges, 450+50 -> 500',
        balance: 450, sibBalance: 50 },
      { ...merge, name: 'token: lying the sibling holds more is refused (the inflation attack)',
        claimSibBalance: 999999, shouldFail: true },
      { ...merge, name: 'token: a merge output over the true sum is refused',
        actualOutBalance: 999999, shouldFail: true },
      { ...merge, name: 'token: a merge output under the true sum is refused',
        actualOutBalance: 400, shouldFail: true },
      { ...merge, name: 'token: merging a sibling not in hashPrevouts is refused',
        wrongSibTxid: true, shouldFail: true },

      // --- merge: a split-sourced sibling (two-output funding), the closed asymmetry ---
      { ...fromSplit, name: 'token: merge a split-sourced sibling at vout 1 (130), 300+130 -> 430',
        sibVout: 1 },
      { ...fromSplit, name: 'token: merge a split-sourced sibling at vout 0 (70), 300+70 -> 370',
        sibVout: 0 },
      { ...fromSplit, name: 'token: lying about a split-sourced siblings balance is refused',
        sibVout: 1, claimSibBalance: 999, shouldFail: true },

      // --- split: one token -> two ---
      { ...split, name: 'token: split conserves the balance, 500 -> 300+200' },
      { ...split, name: 'token: an uneven split conserves too, 500 -> 1+499',
        splitA: 1, splitB: 499 },
      { ...split, name: 'token: a split that mints from nothing is refused, 500 -> 300+300',
        splitB: 300, shouldFail: true },
      { ...split, name: 'token: a split that destroys balance is refused, 500 -> 300+199',
        splitB: 199, shouldFail: true },
      { ...split, name: 'token: declaring one split but emitting another is refused',
        actualSplitA: 400, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/asset'), (() => {
    const A = bsv.PrivateKey.fromRandom(), B = bsv.PrivateKey.fromRandom(), X = bsv.PrivateKey.fromRandom()
    const oA = A.toAddress().toString(), oB = B.toAddress().toString(), oX = X.toAddress().toString()
    return [
      // --- transfer: owner-authorised, balance preserved ---
      { name: 'asset: the owner transfers to a new owner', branch: 'transfer',
        owner: oA, balance: 300, ownerKey: A, newOwner: oB },
      { name: 'asset: a non-owner cannot transfer', branch: 'transfer',
        owner: oA, balance: 300, ownerKey: X, newOwner: oB, shouldFail: true },
      { name: 'asset: a transfer cannot change the balance', branch: 'transfer',
        owner: oA, balance: 300, ownerKey: A, newOwner: oB, actualBalance: 999, shouldFail: true },

      // --- split: owner-authorised, balance conserved ---
      { name: 'asset: the owner splits 500 -> 300+200', branch: 'split',
        owner: oA, balance: 500, ownerKey: A, ownerA: oA, ownerB: oB, splitA: 300, splitB: 200 },
      { name: 'asset: a non-owner cannot split', branch: 'split',
        owner: oA, balance: 500, ownerKey: X, ownerA: oA, ownerB: oB, splitA: 300, splitB: 200, shouldFail: true },
      { name: 'asset: a split that mints from nothing is refused', branch: 'split',
        owner: oA, balance: 500, ownerKey: A, ownerA: oA, ownerB: oB, splitA: 300, splitB: 300, shouldFail: true },
      { name: 'asset: declaring one split but emitting another is refused', branch: 'split',
        owner: oA, balance: 500, ownerKey: A, ownerA: oA, ownerB: oB, splitA: 300, splitB: 200,
        actualBalA: 400, shouldFail: true },

      // --- merge: EACH input's owner must sign; balance summed, sibling proven ---
      { name: 'asset: merge 300(A)+200(B) -> 500 to A, owner A signs', branch: 'merge',
        owner: oA, balance: 300, ownerKey: A, sibOwner: oB, sibBalance: 200, newOwner: oA },
      { name: 'asset: a non-owner cannot merge', branch: 'merge',
        owner: oA, balance: 300, ownerKey: X, sibOwner: oB, sibBalance: 200, newOwner: oA, shouldFail: true },
      { name: 'asset: lying about the sibling balance is refused', branch: 'merge',
        owner: oA, balance: 300, ownerKey: A, sibOwner: oB, sibBalance: 200, newOwner: oA,
        claimSibBalance: 999, shouldFail: true },
      { name: 'asset: lying about the sibling owner is refused', branch: 'merge',
        owner: oA, balance: 300, ownerKey: A, sibOwner: oB, sibBalance: 200, newOwner: oA,
        claimSibOwner: oX, shouldFail: true },
      { name: 'asset: an inflated merge output is refused', branch: 'merge',
        owner: oA, balance: 300, ownerKey: A, sibOwner: oB, sibBalance: 200, newOwner: oA,
        actualOutBalance: 999999, shouldFail: true },
      { name: 'asset: merging a sibling not in hashPrevouts is refused', branch: 'merge',
        owner: oA, balance: 300, ownerKey: A, sibOwner: oB, sibBalance: 200, newOwner: oA,
        wrongSibTxid: true, shouldFail: true },
      { name: 'asset: merge a split-sourced sibling (owner B, 130 @ vout 1)', branch: 'merge',
        owner: oA, balance: 300, ownerKey: A, newOwner: oA,
        sibSplit: true, sibR0: { owner: oX, balance: 70 }, sibR1: { owner: oB, balance: 130 }, sibVout: 1 },

      // --- swap: two assets change hands in one tx, each output pinned by its own owner ---
      { name: 'asset: A swaps her asset to B (my output at index 0)', branch: 'swap',
        owner: oA, balance: 300, ownerKey: A, newOwner: oB, myIndex: 0,
        swapOtherOwner: oA, swapOtherBalance: 200 },
      { name: 'asset: swap works with my output at index 1', branch: 'swap',
        owner: oA, balance: 300, ownerKey: A, newOwner: oB, myIndex: 1,
        swapOtherOwner: oA, swapOtherBalance: 200 },
      { name: 'asset: a non-owner cannot swap the asset away', branch: 'swap',
        owner: oA, balance: 300, ownerKey: X, newOwner: oB, myIndex: 0,
        swapOtherOwner: oA, swapOtherBalance: 200, shouldFail: true },
      { name: 'asset: a swap cannot change the balance', branch: 'swap',
        owner: oA, balance: 300, ownerKey: A, newOwner: oB, myIndex: 0, actualBalance: 999,
        swapOtherOwner: oA, swapOtherBalance: 200, shouldFail: true },
      { name: 'asset: a swap cannot redirect to an owner the signer did not choose', branch: 'swap',
        owner: oA, balance: 300, ownerKey: A, newOwner: oB, myIndex: 0, actualNewOwner: oX,
        swapOtherOwner: oA, swapOtherBalance: 200, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/lineage'), (() => {
    const lineage = require('./src/predicates/lineage')
    const G = lineage.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const base = { genesis: G }
    return [
      // the unbroken chain: each proves descent from the one genesis mint
      { ...base, name: 'lineage: the genesis token spends (its funding spent G)', kind: 'genesis' },
      { ...base, name: 'lineage: a child spends (parent is a genuine lineage token)', kind: 'child' },
      { ...base, name: 'lineage: a grandchild spends (descent proven three hops in)', kind: 'grandchild' },

      // the counterfeit: lineage bytes minted from a plain UTXO can never be spent
      { ...base, name: 'lineage: a counterfeit minted from a plain UTXO is refused', kind: 'counterfeit', shouldFail: true }
    ]
  })()],
  [require('./src/predicates/provenance'), (() => {
    const provenance = require('./src/predicates/provenance')
    const G = provenance.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const X = bsv.PrivateKey.fromRandom()
    const base = { genesis: G }
    return [
      // owner-authorised transfer down an authentic chain, owners rotating
      { ...base, name: 'provenance: the genesis owner transfers (its funding spent G)', kind: 'genesis' },
      { ...base, name: 'provenance: a child transfers (parent proven, owner rotated)', kind: 'child' },
      { ...base, name: 'provenance: a grandchild transfers (descent three hops in)', kind: 'grandchild' },

      // ownership: only the current owner may move it
      { ...base, name: 'provenance: a non-owner cannot transfer', kind: 'child', signWith: X, shouldFail: true },

      // authenticity: a counterfeit and a lie about the parent are both refused
      { ...base, name: 'provenance: a counterfeit minted from a plain UTXO is refused', kind: 'counterfeit', shouldFail: true },
      { ...base, name: 'provenance: lying about the parent owner is refused', kind: 'child',
        wrongParentOwner: X.toAddress().toString(), shouldFail: true }
    ]
  })()],
  [require('./src/predicates/sovereign'), (() => {
    const sov = require('./src/predicates/sovereign')
    const G = sov.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const X = bsv.PrivateKey.fromRandom()
    return [
      // the full divisible lifecycle: mint -> split -> merge, all three checks each
      { genesis: G, name: 'sovereign: the genesis token transfers (balance 500 carried)', kind: 'genesis', balance: 500 },
      { genesis: G, name: 'sovereign: split 500 -> 300+200 (conserved, owner-signed, descent proven)', kind: 'split', a: 300, b: 200 },
      { genesis: G, name: 'sovereign: merge two split-children 300+200 -> 500', kind: 'merge', a: 300, b: 200 },
      // spending a token whose parent was a split child exercises the MULTI-OUTPUT descent
      { genesis: G, name: 'sovereign: a grandchild of a split transfers (multi-output descent)', kind: 'grandchild', a: 300, b: 200 },

      // authenticity: a counterfeit can be created but never spent, in any branch
      { genesis: G, name: 'sovereign: a counterfeit cannot be transferred', kind: 'counterfeit', balance: 500, shouldFail: true },

      // ownership
      { genesis: G, name: 'sovereign: a non-owner cannot split', kind: 'split', a: 300, b: 200, signWith: X, shouldFail: true },
      { genesis: G, name: 'sovereign: a non-owner cannot merge', kind: 'merge', a: 300, b: 200, signWith: X, shouldFail: true },

      // conservation
      { genesis: G, name: 'sovereign: a split that mints value is refused', kind: 'split', a: 300, b: 200, actualSplitA: 600, shouldFail: true },
      { genesis: G, name: 'sovereign: an inflated merge output is refused', kind: 'merge', a: 300, b: 200, actualOutBalance: 999999, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/oracle'), (() => {
    const winner = bsv.PrivateKey.fromRandom()
    const funder = bsv.PrivateKey.fromRandom()
    const wPKH = bsv.crypto.Hash.sha256ripemd160(winner.publicKey.toBuffer())
    const fPKH = bsv.crypto.Hash.sha256ripemd160(funder.publicKey.toBuffer())
    const base = {
      feed: 'BSVUSD', threshold: 6000, winnerPKH: wPKH, funderPKH: fPKH,
      deadline: 964000, winnerKey: winner, funderKey: funder, satoshis: 2000
    }
    return [
      // CLAIM: the winner spends only on a valid oracle attestation >= threshold
      { ...base, name: 'oracle: winner claims when the oracle signs 6543 >= 6000', kind: 'claim', attestValue: 6543 },
      { ...base, name: 'oracle: a value exactly at the threshold claims', kind: 'claim', attestValue: 6000 },
      // a uint32 with its high bit set (>= 2^31) must still claim — the value is
      // read unsigned, not as a negative int32
      { ...base, name: 'oracle: a high-bit-set uint32 value (3e9) claims', kind: 'claim', attestValue: 3000000000, threshold: 1000000000 },

      // the Rabin signature is the whole point — every way of faking it is refused
      { ...base, name: 'oracle: a value below the threshold cannot claim', kind: 'claim', attestValue: 5999, shouldFail: true },
      { ...base, name: 'oracle: a forged value (signed 6000, presented 9999) is refused', kind: 'claim', attestValue: 6000, forgeValue: 9999, shouldFail: true },
      { ...base, name: 'oracle: an attestation for a different feed is refused', kind: 'claim', attestValue: 6543, attestFeed: 'AAPLXX', shouldFail: true },
      { ...base, name: 'oracle: a bystander with the attestation cannot claim (wrong key)', kind: 'claim', attestValue: 6543, winnerKey: funder, shouldFail: true },

      // REFUND: the funder recovers after the deadline, enforced the proper way
      { ...base, name: 'oracle: the funder refunds after the deadline', kind: 'refund' },
      { ...base, name: 'oracle: a premature refund (nLockTime below the deadline) is refused', kind: 'refund', pinLockTime: 963999, shouldFail: true },
      { ...base, name: 'oracle: a refund with a FINAL sequence is refused (nLockTime inert)', kind: 'refund', sequenceNumber: 0xffffffff, shouldFail: true },
      { ...base, name: 'oracle: a stranger cannot refund (wrong key)', kind: 'refund', funderKey: winner, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/settlement'), (() => {
    const h = require('@smartledger/bsv/lib/covenant/helpers')
    const addr = (pkh) => bsv.Address.fromPublicKeyHash(pkh)
    const L = Buffer.alloc(20, 1)
    const S = Buffer.alloc(20, 2)
    const base = { feed: 'BSVUSD', low: 4000, high: 8000, pkhL: L, pkhS: S, fee: 300, satoshis: 1000 }
    // pot = 1000 - 300 = 700
    return [
      // the payout ramp: v drives the split, conserved to the pot every time
      { ...base, name: 'settlement: v=6000 splits the pot 50/50', attestValue: 6000 },
      { ...base, name: 'settlement: v=5000 pays the long 25%', attestValue: 5000 },
      { ...base, name: 'settlement: v at the low bound pays the long nothing', attestValue: 4000 },
      { ...base, name: 'settlement: v below the low bound still pays the long nothing', attestValue: 3000 },
      { ...base, name: 'settlement: v at the high bound pays the long the whole pot', attestValue: 8000 },
      { ...base, name: 'settlement: v above the high bound is clamped to the whole pot', attestValue: 9000 },

      // the oracle value is bound — a forged value cannot skew the split
      { ...base, name: 'settlement: a forged value (signed 4000, presented 8000) is refused', attestValue: 4000, forgeValue: 8000, presentValue: 8000, shouldFail: true },
      { ...base, name: 'settlement: an attestation for a different feed is refused', attestValue: 6000, attestFeed: 'AAPLXX', shouldFail: true },

      // the split is forced by hashOutputs — no other payout is accepted
      { ...base, name: 'settlement: paying the long the whole pot when v=6000 is refused', attestValue: 6000, shouldFail: true,
        actualOutputs: ({ pot }) => [h.p2pkhOutput(addr(L), pot), h.p2pkhOutput(addr(S), 0)] },
      { ...base, name: 'settlement: a split that mints value (both paid the pot) is refused', attestValue: 6000, shouldFail: true,
        actualOutputs: ({ pot }) => [h.p2pkhOutput(addr(L), pot), h.p2pkhOutput(addr(S), pot)] },
      { ...base, name: 'settlement: redirecting the long payout to a stranger is refused', attestValue: 6000, shouldFail: true,
        actualOutputs: ({ payL, payS, S }) => [h.p2pkhOutput(addr(Buffer.alloc(20, 9)), payL), h.p2pkhOutput(addr(S), payS)] }
    ]
  })()],
  [require('./src/predicates/quorum'), (() => {
    const winner = bsv.PrivateKey.fromRandom()
    const wPKH = bsv.crypto.Hash.sha256ripemd160(winner.publicKey.toBuffer())
    const base = { feed: 'BSVUSD', threshold: 6000, winnerPKH: wPKH, m: 2, winnerKey: winner, satoshis: 1000 }
    return [
      // any m of the n panel oracles suffices, in any combination
      { ...base, name: 'quorum: 2 of 3 oracles (0,1) attest and the winner claims', signers: [0, 1], attestValue: 6543 },
      { ...base, name: 'quorum: a different pair (0,2) also suffices', signers: [0, 2], attestValue: 6543 },
      { ...base, name: 'quorum: all three agreeing claims', signers: [0, 1, 2], attestValue: 6543 },

      // fewer than m, or no genuine quorum, is refused
      { ...base, name: 'quorum: a single oracle is not enough', signers: [0], attestValue: 6543, shouldFail: true },
      { ...base, name: 'quorum: no oracle at all is refused', signers: [], attestValue: 6543, shouldFail: true },
      // the distinct-oracle property: one oracle cannot fill two slots
      { ...base, name: 'quorum: one oracle replayed into two slots counts once', slotKeys: [0, 0, null], attestValue: 6543, shouldFail: true },

      // the shared message binds them to the SAME value and feed
      { ...base, name: 'quorum: a value below the threshold is refused', signers: [0, 1], attestValue: 5999, shouldFail: true },
      { ...base, name: 'quorum: a forged value (signed 6543, presented 9999) is refused', signers: [0, 1], attestValue: 6543, forgeValue: 9999, shouldFail: true },
      { ...base, name: 'quorum: attestations for a different feed are refused', signers: [0, 1], attestValue: 6543, attestFeed: 'AAPLXX', shouldFail: true },

      // the winner key still gates who acts on the public attestations
      { ...base, name: 'quorum: a bystander cannot claim with the quorum (wrong key)', signers: [0, 1], attestValue: 6543, winnerKey: other, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/resolution'), (() => {
    const R = require('./src/predicates/resolution')
    const resolver = bsv.PrivateKey.fromRandom()
    const rPKH = bsv.crypto.Hash.sha256ripemd160(resolver.publicKey.toBuffer())
    const foreign = bsv.crypto.Hash.sha256ripemd160(other.publicKey.toBuffer())
    const base = { question: Buffer.alloc(32, 7), resolver: rPKH, resolverKey: resolver, m: 2, satoshis: 5000, fee: 250 }
    return [
      // a quorum of the panel resolves the market to the outcome they agree on
      { ...base, name: 'resolution: 2 of 3 oracles (0,1) resolve to outcome YES(1)', signers: [0, 1], attestOutcome: 1, branch: 'resolve' },
      { ...base, name: 'resolution: the same market resolves to NO(0) just as well', signers: [0, 2], attestOutcome: 0, branch: 'resolve' },
      { ...base, name: 'resolution: all three agreeing resolves', signers: [0, 1, 2], attestOutcome: 1, branch: 'resolve' },
      { ...base, name: 'resolution: a different pair (1,2) also suffices', signers: [1, 2], attestOutcome: 1, branch: 'resolve' },

      // fewer than m, or no genuine quorum, cannot move the market
      { ...base, name: 'resolution: a single oracle is not a quorum', signers: [0], attestOutcome: 1, branch: 'resolve', shouldFail: true },
      { ...base, name: 'resolution: no oracle at all is refused', signers: [], attestOutcome: 1, branch: 'resolve', shouldFail: true },
      { ...base, name: 'resolution: one oracle replayed into two slots counts once', slotKeys: [0, 0, null], attestOutcome: 1, branch: 'resolve', shouldFail: true },

      // the outcome the market records is exactly the one the oracles signed, for THIS question
      { ...base, name: 'resolution: a forged outcome (signed YES, presented NO) is refused', signers: [0, 1], attestOutcome: 1, forgeOutcome: 0, branch: 'resolve', shouldFail: true },
      { ...base, name: 'resolution: an out-of-range outcome (o=2) is refused', signers: [0, 1], attestOutcome: 2, branch: 'resolve', shouldFail: true },
      { ...base, name: 'resolution: attestations for a different question are refused', signers: [0, 1], attestOutcome: 1, attestQuestion: Buffer.alloc(32, 9), branch: 'resolve', shouldFail: true },

      // the immutable core: a resolve cannot rewrite the question or the resolver
      { ...base, name: 'resolution: the successor may not change the resolver', signers: [0, 1], attestOutcome: 1, tamperResolver: foreign, branch: 'resolve', shouldFail: true },
      { ...base, name: 'resolution: the successor may not change the question', signers: [0, 1], attestOutcome: 1, tamperQuestion: Buffer.alloc(32, 9), branch: 'resolve', shouldFail: true },

      // RESOLVED is terminal on the resolve path: a settled market cannot be re-resolved
      { ...base, name: 'resolution: an already-RESOLVED market cannot be re-resolved', status: R.RESOLVED, outcome: 1, signers: [0, 1], attestOutcome: 0, branch: 'resolve', shouldFail: true },

      // the exit: once RESOLVED, the resolver sweeps the dust — and only then, and only them
      { ...base, name: 'resolution: the resolver sweeps a RESOLVED market (the exit)', status: R.RESOLVED, outcome: 1, branch: 'sweep' },
      { ...base, name: 'resolution: an OPEN market cannot be swept', status: R.OPEN, branch: 'sweep', shouldFail: true },
      { ...base, name: 'resolution: a bystander cannot sweep (wrong key)', status: R.RESOLVED, outcome: 1, resolverKey: other, branch: 'sweep', shouldFail: true }
    ]
  })()],
  [require('./src/predicates/market'), (() => {
    const helpers = require('@smartledger/bsv/lib/covenant/helpers')
    const yPKH = bsv.crypto.Hash.sha256ripemd160(bsv.PrivateKey.fromRandom().publicKey.toBuffer())
    const nPKH = bsv.crypto.Hash.sha256ripemd160(bsv.PrivateKey.fromRandom().publicKey.toBuffer())
    const base = { question: Buffer.alloc(32, 7), yesPKH: yPKH, noPKH: nPKH, m: 2, satoshis: 10000, fee: 300 }
    return [
      // the quorum decides the outcome and the WHOLE pot is forced to the winner
      { ...base, name: 'market: YES wins — 2 of 3 oracles attest, the pot goes to the YES owner', signers: [0, 1], attestOutcome: 1 },
      { ...base, name: 'market: NO wins — the same market pays the NO owner', signers: [0, 2], attestOutcome: 0 },
      { ...base, name: 'market: all three agreeing settles', signers: [0, 1, 2], attestOutcome: 1 },

      // no genuine quorum, no settlement
      { ...base, name: 'market: a single oracle cannot settle', signers: [0], attestOutcome: 1, shouldFail: true },
      { ...base, name: 'market: no oracle at all is refused', signers: [], attestOutcome: 1, shouldFail: true },
      { ...base, name: 'market: one oracle replayed into two slots counts once', slotKeys: [0, 0, null], attestOutcome: 1, shouldFail: true },

      // the outcome is the oracles', for THIS question — not the spender's to choose
      { ...base, name: 'market: a forged outcome (signed YES, presented NO) is refused', signers: [0, 1], attestOutcome: 1, forgeOutcome: 0, shouldFail: true },
      { ...base, name: 'market: an out-of-range outcome (o=2) is refused', signers: [0, 1], attestOutcome: 2, shouldFail: true },
      { ...base, name: 'market: attestations for a different question are refused', signers: [0, 1], attestOutcome: 1, attestQuestion: Buffer.alloc(32, 9), shouldFail: true },

      // the payout is forced: you cannot pay the loser, and you cannot skim the pot
      { ...base, name: 'market: paying the loser (YES attested, NO paid) is refused', signers: [0, 1], attestOutcome: 1, actualOutputs: ({ pot }) => [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(nPKH), pot)], shouldFail: true },
      { ...base, name: 'market: skimming the pot (short-paying the winner) is refused', signers: [0, 1], attestOutcome: 1, actualOutputs: ({ pot }) => [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(yPKH), pot - 1000)], shouldFail: true },

      // binding outputs, it must assert SIGHASH_ALL — a SINGLE|ANYONECANPAY core is refused (pitfall 8)
      { ...base, name: 'market: a SINGLE|ANYONECANPAY settlement is refused', signers: [0, 1], attestOutcome: 1, sighashType: (bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_ANYONECANPAY | bsv.crypto.Signature.SIGHASH_FORKID), shouldFail: true },

      // the refund path: after the deadline, both parties reclaim their half — so a vanished panel cannot strand the pot
      { ...base, name: 'market: after the deadline, both parties reclaim half (the refund)', branch: 'refund' },
      { ...base, name: 'market: refund before the deadline (nLockTime < floor) is refused', branch: 'refund', refundAt: 899000, shouldFail: true },
      { ...base, name: 'market: refund with a FINAL sequence (nLockTime inert) is refused', branch: 'refund', sequenceNumber: 0xffffffff, shouldFail: true },
      { ...base, name: 'market: a refund that is not an even 50/50 split is refused', branch: 'refund', actualOutputs: ({ pot }) => [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(yPKH), pot - 100), helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(nPKH), 100)], shouldFail: true },
      // the deadline is a HEIGHT: a past unix TIMESTAMP is numerically larger but makes the input final now — refused (BIP-65 domain guard)
      { ...base, name: 'market: a refund with a timestamp-domain nLockTime beating a height deadline is refused', branch: 'refund', refundAt: 1600000000, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/marketN'), (() => {
    const helpers = require('@smartledger/bsv/lib/covenant/helpers')
    const owners = [0, 1, 2].map(() => bsv.crypto.Hash.sha256ripemd160(bsv.PrivateKey.fromRandom().publicKey.toBuffer()))
    const four = [0, 1, 2, 3].map(() => bsv.crypto.Hash.sha256ripemd160(bsv.PrivateKey.fromRandom().publicKey.toBuffer()))
    const base = { question: Buffer.alloc(32, 7), owners, m: 2, satoshis: 12000, fee: 400 }
    return [
      // the quorum names one of K outcomes; the whole pot goes to that outcome's owner
      { ...base, name: 'marketN: K=3, outcome 0 wins — the pot goes to owner 0', signers: [0, 1], attestOutcome: 0 },
      { ...base, name: 'marketN: K=3, outcome 1 wins — a middle index selects owner 1', signers: [0, 2], attestOutcome: 1 },
      { ...base, name: 'marketN: K=3, outcome 2 wins — the last index (cascade fall-through) selects owner 2', signers: [1, 2], attestOutcome: 2 },
      { ...base, name: 'marketN: K=4, outcome 3 wins — the selection generalises to any K', owners: four, signers: [0, 1, 2], attestOutcome: 3 },

      // no genuine quorum, no settlement
      { ...base, name: 'marketN: a single oracle cannot settle', signers: [0], attestOutcome: 1, shouldFail: true },
      { ...base, name: 'marketN: one oracle replayed into two slots counts once', slotKeys: [0, 0, null], attestOutcome: 1, shouldFail: true },

      // the index is the oracles', for THIS question, and must be a real outcome
      { ...base, name: 'marketN: a forged index (signed 1, presented 2) is refused', signers: [0, 1], attestOutcome: 1, forgeOutcome: 2, shouldFail: true },
      { ...base, name: 'marketN: an out-of-range index (o=3 with K=3) is refused', signers: [0, 1], attestOutcome: 3, shouldFail: true },
      { ...base, name: 'marketN: attestations for a different question are refused', signers: [0, 1], attestOutcome: 1, attestQuestion: Buffer.alloc(32, 9), shouldFail: true },

      // the payout is forced to the named winner
      { ...base, name: 'marketN: paying a losing outcome’s owner is refused', signers: [0, 1], attestOutcome: 0, actualOutputs: ({ pot }) => [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(owners[2]), pot)], shouldFail: true },
      { ...base, name: 'marketN: a SINGLE|ANYONECANPAY settlement is refused', signers: [0, 1], attestOutcome: 1, sighashType: (bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_ANYONECANPAY | bsv.crypto.Signature.SIGHASH_FORKID), shouldFail: true },

      // the refund: after the deadline, the pot splits into K equal shares, one per owner
      { ...base, name: 'marketN: after the deadline, the pot splits equally among all K owners', branch: 'refund' },
      { ...base, name: 'marketN: a refund before the deadline is refused', branch: 'refund', refundAt: 899000, shouldFail: true },
      { ...base, name: 'marketN: a refund that is not an even K-way split is refused', branch: 'refund', actualOutputs: ({ pot, share }) => owners.map((o, i) => helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(o), i === 0 ? pot - share * (owners.length - 1) + 100 : share)), shouldFail: true }
    ]
  })()],
  [require('./src/predicates/marketScalar'), (() => {
    const helpers = require('@smartledger/bsv/lib/covenant/helpers')
    const L = bsv.crypto.Hash.sha256ripemd160(bsv.PrivateKey.fromRandom().publicKey.toBuffer())
    const S = bsv.crypto.Hash.sha256ripemd160(bsv.PrivateKey.fromRandom().publicKey.toBuffer())
    const base = { question: Buffer.alloc(32, 7), low: 6000, high: 7000, pkhL: L, pkhS: S, m: 2, satoshis: 20000, fee: 400 }
    return [
      // the quorum attests a value; the pot is split piecewise-linearly between LONG and SHORT
      { ...base, name: 'marketScalar: v in range (6500) splits the pot linearly', signers: [0, 1], attestValue: 6500 },
      { ...base, name: 'marketScalar: v at a quarter (6250) splits one-quarter to LONG', signers: [0, 2], attestValue: 6250 },
      { ...base, name: 'marketScalar: v ≤ LOW (5000) gives the whole pot to SHORT', signers: [1, 2], attestValue: 5000 },
      { ...base, name: 'marketScalar: v ≥ HIGH (8000) gives the whole pot to LONG', signers: [0, 1], attestValue: 8000 },

      // no genuine quorum, no settlement
      { ...base, name: 'marketScalar: a single oracle cannot settle', signers: [0], attestValue: 6500, shouldFail: true },
      { ...base, name: 'marketScalar: one oracle replayed into two slots counts once', slotKeys: [0, 0, null], attestValue: 6500, shouldFail: true },

      // the value is the oracles', for THIS question, and the split is forced
      { ...base, name: 'marketScalar: a forged value (signed 6500, presented 9999) is refused', signers: [0, 1], attestValue: 6500, forgeValue: 9999, shouldFail: true },
      { ...base, name: 'marketScalar: attestations for a different question are refused', signers: [0, 1], attestValue: 6500, attestQuestion: Buffer.alloc(32, 9), shouldFail: true },
      { ...base, name: 'marketScalar: a split that pays LONG more than the rule is refused', signers: [0, 1], attestValue: 6500, actualOutputs: ({ payL, payS }) => [helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(L), payL + 500), helpers.p2pkhOutput(bsv.Address.fromPublicKeyHash(S), payS - 500)], shouldFail: true },
      { ...base, name: 'marketScalar: a SINGLE|ANYONECANPAY settlement is refused', signers: [0, 1], attestValue: 6500, sighashType: (bsv.crypto.Signature.SIGHASH_SINGLE | bsv.crypto.Signature.SIGHASH_ANYONECANPAY | bsv.crypto.Signature.SIGHASH_FORKID), shouldFail: true },

      // the refund: after the deadline, both parties reclaim their half
      { ...base, name: 'marketScalar: after the deadline, both parties reclaim half', branch: 'refund' },
      { ...base, name: 'marketScalar: a refund before the deadline is refused', branch: 'refund', refundAt: 899000, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/bulletin'), (() => {
    const B = require('./src/predicates/bulletin')
    const base = { question: Buffer.alloc(32, 7), m: 2, satoshis: 5000, fee: 250 }
    return [
      // the quorum establishes the outcome once, then the fact persists
      { ...base, name: 'bulletin: 2 of 3 oracles resolve it to YES(1)', signers: [0, 1], attestOutcome: 1, branch: 'resolve' },
      { ...base, name: 'bulletin: the same bulletin resolves to NO(0) just as well', signers: [0, 2], attestOutcome: 0, branch: 'resolve' },
      { ...base, name: 'bulletin: a single oracle is not a quorum', signers: [0], attestOutcome: 1, branch: 'resolve', shouldFail: true },
      { ...base, name: 'bulletin: a forged outcome is refused', signers: [0, 1], attestOutcome: 1, forgeOutcome: 0, branch: 'resolve', shouldFail: true },
      { ...base, name: 'bulletin: attestations for a different question are refused', signers: [0, 1], attestOutcome: 1, attestQuestion: Buffer.alloc(32, 9), branch: 'resolve', shouldFail: true },
      // once RESOLVED it recreates itself, unchanged, so positions can read it forever
      { ...base, name: 'bulletin: a RESOLVED bulletin recreates itself on a read', status: B.RESOLVED, outcome: 1, branch: 'read' },
      { ...base, name: 'bulletin: an OPEN bulletin cannot be read (not resolved yet)', status: B.OPEN, outcome: 0, branch: 'read', shouldFail: true },
      { ...base, name: 'bulletin: a read may not change the committed outcome', status: B.RESOLVED, outcome: 1, branch: 'read', actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: B.buildScript({ question: Buffer.alloc(32, 7), status: B.RESOLVED, outcome: 0 }), satoshis: 5000 - fee })], shouldFail: true }
    ]
  })()],
  [require('./src/predicates/position'), (() => {
    const P = require('./src/predicates/position')
    const Q = Buffer.alloc(32, 7)
    const owner = bsv.PrivateKey.fromRandom()
    const cp = bsv.PrivateKey.fromRandom()
    const oPKH = bsv.crypto.Hash.sha256ripemd160(owner.publicKey.toBuffer())
    const cPKH = bsv.crypto.Hash.sha256ripemd160(cp.publicKey.toBuffer())
    const srcYes = P.bulletinSourceTx({ question: Q, outcome: 1 })
    const srcNo = P.bulletinSourceTx({ question: Q, outcome: 0 })
    const base = { question: Q, owner: oPKH, counterparty: cPKH, satoshis: 3000 }
    return [
      // the party who called the outcome right takes the collateral
      { ...base, name: 'position: a YES stake on a bulletin that resolved YES — the owner claims', side: 1, _src: srcYes, claimantKey: owner },
      { ...base, name: 'position: a YES stake on a bulletin that resolved NO — the counterparty claims', side: 1, _src: srcNo, claimantKey: cp },
      { ...base, name: 'position: a NO stake on a bulletin that resolved NO — the owner claims', side: 0, _src: srcNo, claimantKey: owner },
      // the loser cannot take the winner's payout
      { ...base, name: 'position: the counterparty cannot claim when the owner was right', side: 1, _src: srcYes, claimantKey: cp, shouldFail: true },
      { ...base, name: 'position: the owner cannot claim when they were wrong', side: 1, _src: srcNo, claimantKey: owner, shouldFail: true },
      { ...base, name: 'position: a stranger cannot claim the winner’s payout', side: 1, _src: srcYes, claimantKey: bsv.PrivateKey.fromRandom(), shouldFail: true },
      // it cannot be settled against another market's bulletin
      { ...base, name: 'position: a bulletin for a different question is refused', side: 1, _src: P.bulletinSourceTx({ question: Buffer.alloc(32, 8), outcome: 1 }), claimantKey: owner, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/descentbulletin'), (() => {
    const D = require('./src/predicates/descentbulletin')
    const G = D.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const base = { genesis: G, m: 2, satoshis: D.DUST }
    return [
      // resolve the OPEN bulletin minted by spending the genesis outpoint (the mint hop, parent == G)
      { ...base, name: 'descentbulletin: resolve the genesis-minted bulletin — the quorum sets the outcome', kind: 'resolve', signers: [0, 1], attestOutcome: 1 },
      { ...base, name: 'descentbulletin: a sub-quorum cannot resolve it', kind: 'resolve', signers: [0], attestOutcome: 1, shouldFail: true },
      { ...base, name: 'descentbulletin: an attestation for a different genesis is refused', kind: 'resolve', signers: [0, 1], attestOutcome: 1, attestGenesis: Buffer.alloc(36, 9), shouldFail: true },

      // read a RESOLVED bulletin whose parent was the OPEN bulletin — DESCENT ACROSS THE STATE CHANGE
      { ...base, name: 'descentbulletin: read a RESOLVED bulletin whose parent is the same-genesis OPEN bulletin (descent across the state change)', kind: 'read', attestOutcome: 1 },

      // a counterfeit RESOLVED bulletin, minted from a plain UTXO, carries the genesis bytes but did NOT descend from the one spend of G
      { ...base, name: 'descentbulletin: a counterfeit minted from a plain UTXO can be created but never read', kind: 'counterfeit', attestOutcome: 1, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/descentmarket'), (() => {
    const G = require('./src/predicates/descentbulletin').genesisOutpoint('b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1', 0)
    const payScript = bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(Buffer.alloc(20, 8)))
    const payOut = new bsv.Transaction.Output({ script: payScript, satoshis: 1500 })
    const myPTail = payOut.toBufferWriter().toBuffer()
    const base = { genesis: G, m: 2, satoshis: 2000 }
    return [
      // the unification: descent-proven on every hop, AND a pTail of position payouts
      { ...base, name: 'descentmarket: resolve the genesis-minted bulletin (quorum + descent from G)', kind: 'resolve', signers: [0, 1], attestOutcome: 1 },
      { ...base, name: 'descentmarket: read carrying a position payout in its tail (recreate at output 0, co-settle in the tail)', kind: 'read', attestOutcome: 1, myPTail, tailOutputs: [payOut] },
      { ...base, name: 'descentmarket: read whose parent’s funding was itself a co-settlement (multi-output-parent backtrace)', kind: 'read-of-read', attestOutcome: 1 },

      // both halves still bite: the descent and the tail binding
      { ...base, name: 'descentmarket: a sub-quorum cannot resolve it', kind: 'resolve', signers: [0], attestOutcome: 1, shouldFail: true },
      { ...base, name: 'descentmarket: a counterfeit minted from a plain UTXO cannot be spent', kind: 'counterfeit', attestOutcome: 1, shouldFail: true },
      { ...base, name: 'descentmarket: a tampered payout tail (not matching hashOutputs) is refused', kind: 'read', attestOutcome: 1, myPTail, tailOutputs: [new bsv.Transaction.Output({ script: payScript, satoshis: 1600 })], shouldFail: true }
    ]
  })()],
  [require('./src/predicates/positionv2'), (() => {
    const PV = require('./src/predicates/positionv2')
    const D = require('./src/predicates/descentbulletin')
    const G = D.genesisOutpoint('c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2', 0)
    const owner = bsv.PrivateKey.fromRandom()
    const cp = bsv.PrivateKey.fromRandom()
    const oPKH = bsv.crypto.Hash.sha256ripemd160(owner.publicKey.toBuffer())
    const cPKH = bsv.crypto.Hash.sha256ripemd160(cp.publicKey.toBuffer())
    const base = { genesis: G, owner: oPKH, counterparty: cPKH, satoshis: 2000 }
    return [
      // written against the market's IDENTITY (not an outpoint) and settled against any genuine descentmarket of it
      { ...base, name: 'positionv2: a YES stake settles against a descentmarket resolved YES — the owner claims (by identity)', side: 1, outcome: 1, claimantKey: owner },
      { ...base, name: 'positionv2: a YES stake against a descentmarket resolved NO — the counterparty claims', side: 1, outcome: 0, claimantKey: cp },
      { ...base, name: 'positionv2: a NO stake against a descentmarket resolved NO — the owner claims', side: 0, outcome: 0, claimantKey: owner },
      // the identity check and the winner check both bite
      { ...base, name: 'positionv2: the loser cannot claim when the owner was right', side: 1, outcome: 1, claimantKey: cp, shouldFail: true },
      { ...base, name: 'positionv2: a stranger cannot claim', side: 1, outcome: 1, claimantKey: bsv.PrivateKey.fromRandom(), shouldFail: true },
      { ...base, name: 'positionv2: a coin from a DIFFERENT market (wrong genesis) is refused by the identity check', side: 1, outcome: 1, claimantKey: owner, srcGenesis: D.genesisOutpoint('d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3', 0), shouldFail: true }
    ]
  })()],
  [require('./src/predicates/ticker'), (() => {
    const bsvL = require('@smartledger/bsv')
    const funder = bsvL.PrivateKey.fromRandom()
    const fPKH = bsvL.crypto.Hash.sha256ripemd160(funder.publicKey.toBuffer())
    const base = { round: 5, price: 6000, tag: 'BSVUSD', funderPKH: fPKH, fee: 300, funderKey: funder, satoshis: 5000 }
    return [
      // an update advances the ticker to any strictly-higher round the oracle signs
      { ...base, name: 'ticker: a fresher attestation advances round 5 -> 6', branch: 'update', newRound: 6, newPrice: 6300 },
      { ...base, name: 'ticker: rounds may jump (5 -> 100)', branch: 'update', newRound: 100, newPrice: 7777 },

      // FRESHNESS — the anti-replay guard, the reason state and an oracle need care
      { ...base, name: 'ticker: replaying the same round is refused', branch: 'update', newRound: 5, newPrice: 9999, shouldFail: true },
      { ...base, name: 'ticker: rolling back to an older round is refused', branch: 'update', newRound: 4, newPrice: 1, shouldFail: true },

      // the new state is bound to the signature and recreated faithfully
      { ...base, name: 'ticker: a forged price (signed 6300, presented 9999) is refused', branch: 'update', newRound: 6, newPrice: 6300, presentPrice: 9999, shouldFail: true },
      { ...base, name: 'ticker: an attestation for another feed is refused', branch: 'update', newRound: 6, newPrice: 6300, attestTag: 'AAPLXX', shouldFail: true },
      { ...base, name: 'ticker: a valid attestation with a tampered successor state is refused', branch: 'update', newRound: 6, newPrice: 6300, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({
          script: require('./src/predicates/ticker').buildScript({ round: 6, price: 1, tag: 'BSVUSD', funderPKH: fPKH, fee }),
          satoshis: 5000 - fee })] },
      { ...base, name: 'ticker: skimming extra value on an update is refused', branch: 'update', newRound: 6, newPrice: 6300, shouldFail: true,
        actualOutputs: ({ fee, script }) => [new bsv.Transaction.Output({ script, satoshis: 5000 - fee - 100 })] },

      // the exit: the funder can sweep the remainder and terminate the ticker
      { ...base, name: 'ticker: the funder redeems the remainder', branch: 'redeem' },
      { ...base, name: 'ticker: a stranger cannot redeem the remainder', branch: 'redeem', funderKey: other, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/vesting'), (() => {
    const bsvL = require('@smartledger/bsv')
    const h = require('@smartledger/bsv/lib/covenant/helpers')
    const ben = bsvL.PrivateKey.fromRandom()
    const bPKH = bsvL.crypto.Hash.sha256ripemd160(ben.publicKey.toBuffer())
    const V = require('./src/predicates/vesting')
    const base = { total: 10000, start: 1750000000, end: 1760000000, beneficiaryPKH: bPKH, fee: 300, beneficiaryKey: ben, satoshis: 10000 }
    return [
      // the vesting curve: the covenant retains exactly the unvested remainder
      { ...base, name: 'vesting: withdraw at 50% retains 5000 unvested', branch: 'withdraw', atTime: 1755000000 },
      { ...base, name: 'vesting: withdraw at 30% retains 7000 unvested', branch: 'withdraw', atTime: 1753000000 },
      { ...base, name: 'vesting: withdraw at 70% retains 3000 unvested', branch: 'withdraw', atTime: 1757000000 },
      { ...base, name: 'vesting: at the end the grant finishes and pays out fully', branch: 'finish', atTime: 1760000000 },

      // soundness: only the beneficiary, only at a real time, only the vested amount
      { ...base, name: 'vesting: a stranger cannot withdraw', branch: 'withdraw', atTime: 1755000000, beneficiaryKey: other, shouldFail: true },
      { ...base, name: 'vesting: a final sequence (nLockTime inert) is refused', branch: 'withdraw', atTime: 1755000000, sequenceNumber: 0xffffffff, shouldFail: true },
      { ...base, name: 'vesting: retaining LESS than the unvested amount is refused', branch: 'withdraw', atTime: 1755000000, shouldFail: true,
        actualOutputs: ({ B, u, fee, benAddr }) => [new bsv.Transaction.Output({ script: V.buildScript(base), satoshis: u - 500 }), h.p2pkhOutput(benAddr, B - (u - 500) - fee)] },
      { ...base, name: 'vesting: paying the beneficiary a different address is refused', branch: 'withdraw', atTime: 1755000000, shouldFail: true,
        actualOutputs: ({ B, u, fee }) => [new bsv.Transaction.Output({ script: V.buildScript(base), satoshis: u }), h.p2pkhOutput(bsvL.Address.fromPublicKeyHash(Buffer.alloc(20, 9)), B - u - fee)] },

      // the two branches are partitioned by the schedule, not spender choice
      { ...base, name: 'vesting: finishing while still vesting is refused', branch: 'finish', atTime: 1755000000, shouldFail: true },
      { ...base, name: 'vesting: a withdraw once fully vested is refused', branch: 'withdraw', atTime: 1760000000, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/journal'), (() => {
    const bsvL = require('@smartledger/bsv')
    const J = require('./src/predicates/journal')
    const pub = bsvL.PrivateKey.fromRandom()
    const pPKH = bsvL.crypto.Hash.sha256ripemd160(pub.publicKey.toBuffer())
    const base = { publisher: pPKH, fee: 250, publisherKey: pub, satoshis: 5000 }
    const rec1 = Buffer.alloc(32, 0xaa)
    const head1 = J.chain(J.GENESIS_HEAD, rec1)
    return [
      // append advances the sequence AND the hash-chained head
      { ...base, name: 'journal: append the first record (seq 0 -> 1)', branch: 'append', seq: 0, head: J.GENESIS_HEAD, recordHash: rec1 },
      { ...base, name: 'journal: append a second record (seq 1 -> 2)', branch: 'append', seq: 1, head: head1, recordHash: Buffer.alloc(32, 0xbb) },

      // the chain is append-only: the successor head must be HASH256(head ‖ record)
      { ...base, name: 'journal: a tampered successor head is refused', branch: 'append', seq: 0, head: J.GENESIS_HEAD, recordHash: rec1, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: J.buildScript({ seq: 1, head: Buffer.alloc(32, 0xff), publisher: pPKH, fee }), satoshis: 4750 })] },
      { ...base, name: 'journal: skipping the sequence is refused', branch: 'append', seq: 0, head: J.GENESIS_HEAD, recordHash: rec1, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: J.buildScript({ seq: 5, head: head1, publisher: pPKH, fee }), satoshis: 4750 })] },
      { ...base, name: 'journal: keeping the sequence flat is refused', branch: 'append', seq: 0, head: J.GENESIS_HEAD, recordHash: rec1, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: J.buildScript({ seq: 0, head: head1, publisher: pPKH, fee }), satoshis: 4750 })] },

      // only the publisher, fixed in state, may append or close
      { ...base, name: 'journal: only the publisher may append', branch: 'append', seq: 0, head: J.GENESIS_HEAD, recordHash: rec1, publisherKey: other, shouldFail: true },

      // the exit: the publisher sweeps the remainder and stops
      { ...base, name: 'journal: the publisher closes the log and sweeps', branch: 'close', seq: 2, head: Buffer.alloc(32, 0xcc) },
      { ...base, name: 'journal: a stranger cannot close it', branch: 'close', seq: 2, head: Buffer.alloc(32, 0xcc), publisherKey: other, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/lifecycle'), (() => {
    const bsvL = require('@smartledger/bsv')
    const L = require('./src/predicates/lifecycle')
    const iss = bsvL.PrivateKey.fromRandom()
    const issPKH = bsvL.crypto.Hash.sha256ripemd160(iss.publicKey.toBuffer())
    const genesis = Buffer.alloc(32, 7)
    const base = { genesis, issuer: issPKH, issuerKey: iss, fee: 250, satoshis: 5000 }
    return [
      // the certificate walks its state machine: ISSUED -> ACTIVE -> SUSPENDED -> ACTIVE -> REVOKED
      { ...base, name: 'lifecycle: ISSUED -> ACTIVE', branch: 'transition', status: L.ISSUED, to: L.ACTIVE },
      { ...base, name: 'lifecycle: ACTIVE -> SUSPENDED', branch: 'transition', status: L.ACTIVE, to: L.SUSPENDED },
      { ...base, name: 'lifecycle: SUSPENDED -> ACTIVE (reinstated)', branch: 'transition', status: L.SUSPENDED, to: L.ACTIVE },
      { ...base, name: 'lifecycle: ACTIVE -> REVOKED', branch: 'transition', status: L.ACTIVE, to: L.REVOKED },

      // a move not in the transition set is refused
      { ...base, name: 'lifecycle: an illegal transition (ISSUED -> SUSPENDED) is refused', branch: 'transition', status: L.ISSUED, to: L.SUSPENDED, shouldFail: true },

      // REVOKED is TERMINAL: no move leaves it, and a move cannot lie about where it starts
      { ...base, name: 'lifecycle: REVOKED is terminal (-> ACTIVE refused)', branch: 'transition', status: L.REVOKED, to: L.ACTIVE, shouldFail: true },
      { ...base, name: 'lifecycle: REVOKED is terminal (-> REVOKED refused)', branch: 'transition', status: L.REVOKED, to: L.REVOKED, shouldFail: true },
      { ...base, name: 'lifecycle: a move that lies about the old state is refused', branch: 'transition', status: L.REVOKED, to: L.SUSPENDED, presentMove: Buffer.from([L.ACTIVE, L.SUSPENDED]), shouldFail: true },

      // the constitution: genesis and issuer are immutable, no transition may rewrite them
      { ...base, name: 'lifecycle: rewriting the immutable genesis is refused', branch: 'transition', status: L.ACTIVE, to: L.SUSPENDED, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: L.buildScript({ genesis: Buffer.alloc(32, 9), status: L.SUSPENDED, issuer: issPKH, fee }), satoshis: 4750 })] },
      { ...base, name: 'lifecycle: rewriting the immutable issuer is refused', branch: 'transition', status: L.ACTIVE, to: L.SUSPENDED, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: L.buildScript({ genesis, status: L.SUSPENDED, issuer: Buffer.alloc(20, 9), fee }), satoshis: 4750 })] },

      // only the issuer, fixed in the object's state, may move it or retire it
      { ...base, name: 'lifecycle: only the issuer may transition', branch: 'transition', status: L.ACTIVE, to: L.SUSPENDED, issuerKey: other, shouldFail: true },
      { ...base, name: 'lifecycle: the issuer retires the object and sweeps', branch: 'retire', status: L.REVOKED },
      { ...base, name: 'lifecycle: a stranger cannot retire it', branch: 'retire', status: L.REVOKED, issuerKey: other, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/delegation'), (() => {
    const bsvL = require('@smartledger/bsv')
    const D = require('./src/predicates/delegation')
    const A = bsvL.PrivateKey.fromRandom()          // owner of this node
    const Bk = bsvL.PrivateKey.fromRandom()         // the delegate
    const aPKH = bsvL.crypto.Hash.sha256ripemd160(A.publicKey.toBuffer())
    const bPKH = bsvL.crypto.Hash.sha256ripemd160(Bk.publicKey.toBuffer())
    const root = Buffer.alloc(32, 7)
    const base = { root, owner: aPKH, ownerKey: A, fee: 350, satoshis: 8000 }
    return [
      // delegate splits a child off the budget; self keeps the remainder — the split CONSERVES
      { ...base, name: 'delegation: delegate 40 of a 100 budget', branch: 'delegate', budget: 100, childBudget: 40, delegate: bPKH },
      { ...base, name: 'delegation: delegate the entire budget', branch: 'delegate', budget: 100, childBudget: 100, delegate: bPKH },

      // the budget bounds: 1 ≤ b ≤ budget
      { ...base, name: 'delegation: delegating zero is refused', branch: 'delegate', budget: 100, childBudget: 0, delegate: bPKH, presentChild4: D.budgetLE(0), shouldFail: true },
      { ...base, name: 'delegation: delegating more than the budget is refused', branch: 'delegate', budget: 100, childBudget: 101, delegate: bPKH, shouldFail: true },

      // Σ ≤ parent: a self that keeps more than (budget − b) does not conserve — refused
      { ...base, name: 'delegation: a non-conserving split (70+40 of 100) is refused', branch: 'delegate', budget: 100, childBudget: 40, delegate: bPKH, shouldFail: true,
        actualOutputs: ({ fee, root, owner }) => [
          new bsv.Transaction.Output({ script: D.buildScript({ root, budget: 70, owner, fee }), satoshis: 8000 - fee - D.CHILD_SATS }),
          new bsv.Transaction.Output({ script: D.buildScript({ root, budget: 40, owner: bPKH, fee }), satoshis: D.CHILD_SATS })] },

      // the root is immutable — a child that rewrites it breaks descent, refused
      { ...base, name: 'delegation: rewriting the root in the child is refused', branch: 'delegate', budget: 100, childBudget: 40, delegate: bPKH, shouldFail: true,
        actualOutputs: ({ fee, root, owner }) => [
          new bsv.Transaction.Output({ script: D.buildScript({ root, budget: 60, owner, fee }), satoshis: 8000 - fee - D.CHILD_SATS }),
          new bsv.Transaction.Output({ script: D.buildScript({ root: Buffer.alloc(32, 9), budget: 40, owner: bPKH, fee }), satoshis: D.CHILD_SATS })] },

      { ...base, name: 'delegation: only the owner may delegate', branch: 'delegate', budget: 100, childBudget: 40, delegate: bPKH, ownerKey: other, shouldFail: true },

      // exercise consumes budget: the capability being used (leaf case = a use-counter)
      { ...base, name: 'delegation: exercise 30 of a 100 budget', branch: 'exercise', budget: 100, spend: 30 },
      { ...base, name: 'delegation: exercise the whole budget down to zero', branch: 'exercise', budget: 100, spend: 100 },
      { ...base, name: 'delegation: exercising zero is refused', branch: 'exercise', budget: 100, spend: 0, presentSpend4: D.budgetLE(0), shouldFail: true },
      { ...base, name: 'delegation: exercising more than the budget is refused', branch: 'exercise', budget: 100, spend: 101, shouldFail: true },
      { ...base, name: 'delegation: only the owner may exercise', branch: 'exercise', budget: 100, spend: 30, ownerKey: other, shouldFail: true },
      { ...base, name: 'delegation: an exercise that reduces by the wrong amount is refused', branch: 'exercise', budget: 100, spend: 30, shouldFail: true,
        actualOutputs: ({ fee, root, owner }) => [new bsv.Transaction.Output({ script: D.buildScript({ root, budget: 90, owner, fee }), satoshis: 8000 - fee })] },

      // revoke: the owner sweeps the remainder and stops (the exit)
      { ...base, name: 'delegation: the owner revokes and sweeps', branch: 'revoke', budget: 100 },
      { ...base, name: 'delegation: a stranger cannot revoke', branch: 'revoke', budget: 100, ownerKey: other, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/witness'), (() => {
    const bsvL = require('@smartledger/bsv')
    const W = require('./src/predicates/witness')
    const bene = bsvL.PrivateKey.fromRandom()
    const benePKH = bsvL.crypto.Hash.sha256ripemd160(bene.publicKey.toBuffer())
    const ownerB = bsvL.crypto.Hash.sha256ripemd160(bsvL.PrivateKey.fromRandom().publicKey.toBuffer())
    const ownerC = bsvL.crypto.Hash.sha256ripemd160(bsvL.PrivateKey.fromRandom().publicKey.toBuffer())
    const base = { beneficiary: benePKH, beneficiaryKey: bene, satoshis: 5000 }
    const mk = ({ requiredFlag, actualFlag, extraOutputs = 1 }) => {
      const src = W.taggedCoinTx({ flag: actualFlag ?? requiredFlag, ownerPKH: ownerB, extraOutputs })
      return { sibling: { prevTxId: src.tx.id, outputIndex: 0 }, _src: src, requiredFlag }
    }
    // absent: demand a coin owned by B, but the tx spends a different coin (owned by C)
    const demanded = W.taggedCoinTx({ flag: 1, ownerPKH: ownerB })
    const spent = W.taggedCoinTx({ flag: 1, ownerPKH: ownerC })
    // forged: the real co-spent coin has flag 2; a forged source tx claims flag 1
    const real2 = W.taggedCoinTx({ flag: 2, ownerPKH: ownerB })
    const forged1 = W.taggedCoinTx({ flag: 1, ownerPKH: ownerB })
    return [
      // release only when the named sibling coin is co-spent AND carries the required flag
      { ...base, name: 'witness: releases when the sibling shows the required flag', ...mk({ requiredFlag: 1 }) },
      { ...base, name: 'witness: releases on a different flag value too', ...mk({ requiredFlag: 7 }) },
      { ...base, name: 'witness: reads output 0 past extra source outputs', ...mk({ requiredFlag: 3, extraOutputs: 2 }) },

      // the state gate: a sibling carrying the wrong flag is refused
      { ...base, name: 'witness: a sibling with the wrong flag is refused', ...mk({ requiredFlag: 1, actualFlag: 2 }), shouldFail: true },

      // the identity gate: the demanded sibling must actually be a co-input
      { ...base, name: 'witness: refused when the demanded sibling is absent', sibling: { prevTxId: demanded.tx.id, outputIndex: 0 }, _src: spent, requiredFlag: 1, shouldFail: true },

      // the backtrace gate: a forged source tx cannot hash to the real coin's txid
      { ...base, name: 'witness: a forged source tx is refused', sibling: { prevTxId: real2.tx.id, outputIndex: 0 }, _src: { ...forged1, tx: real2.tx }, requiredFlag: 1, shouldFail: true },

      // the beneficiary gate: only the beneficiary may trigger the release
      { ...base, name: 'witness: a stranger cannot trigger the release', ...mk({ requiredFlag: 1 }), beneficiaryKey: bsvL.PrivateKey.fromRandom(), shouldFail: true }
    ]
  })()],
  [require('./src/predicates/conserve'), (() => {
    const bsvL = require('@smartledger/bsv')
    const CV = require('./src/predicates/conserve')
    const OA = bsvL.PrivateKey.fromRandom(); const OB = bsvL.PrivateKey.fromRandom()
    const G = CV.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const Gother = CV.genesisOutpoint('b'.repeat(64), 0)
    const base = { genesis: G, ownerA: OA, ownerB: OB, satoshis: CV.DUST }
    return [
      // a rebalance moves quantity between the two coins; the sum is invariant
      { ...base, name: 'conserve: genesis rebalance (60,40) -> (45,55), spend side 0', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA },
      { ...base, name: 'conserve: genesis rebalance (60,40) -> (70,30), spend side 1', kind: 'genesis', a0: 60, b0: 40, newA: 70, newB: 30, spendSide: 1, ownerKey: OB },
      // induction: a pair whose parent was itself a rebalance still proves descent
      { ...base, name: 'conserve: a second-generation rebalance, spend side 0', kind: 'child', a0: 60, b0: 40, a1: 50, b1: 50, newA: 20, newB: 80, spendSide: 0, ownerKey: OA },
      { ...base, name: 'conserve: a second-generation rebalance, spend side 1', kind: 'child', a0: 60, b0: 40, a1: 50, b1: 50, newA: 80, newB: 20, spendSide: 1, ownerKey: OB },

      // conservation: the new balances must sum to the old
      { ...base, name: 'conserve: a rebalance that does not conserve the sum is refused', kind: 'genesis', a0: 60, b0: 40, newA: 60, newB: 60, spendSide: 0, ownerKey: OA, shouldFail: true },

      // uncounterfeitable: a pair not descending from the genesis outpoint cannot spend
      { ...base, name: 'conserve: a counterfeit pair (never minted from G) is refused', kind: 'genesis', counterfeit: true, a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true },

      // authority: each coin is moved only by its own owner
      { ...base, name: 'conserve: a rebalance signed by the wrong owner is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: bsvL.PrivateKey.fromRandom(), shouldFail: true },

      // atomicity: the canonical partner must be co-spent, not left behind
      { ...base, name: 'conserve: refused when the pair partner is not co-spent', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, omitSibling: true, shouldFail: true },

      // the pair identity and owners are immutable across a rebalance
      { ...base, name: 'conserve: a successor that rewrites the genesis is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true,
        actualOutputs: ({ oa, ob }) => [
          new bsv.Transaction.Output({ script: CV.buildScript({ genesis: Gother, side: 0, balance: 45, owner: oa }), satoshis: CV.DUST }),
          new bsv.Transaction.Output({ script: CV.buildScript({ genesis: G, side: 1, balance: 55, owner: ob }), satoshis: CV.DUST })] },
      { ...base, name: 'conserve: a successor that changes an owner is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true,
        actualOutputs: ({ oa, ob }) => [
          new bsv.Transaction.Output({ script: CV.buildScript({ genesis: G, side: 0, balance: 45, owner: oa }), satoshis: CV.DUST }),
          new bsv.Transaction.Output({ script: CV.buildScript({ genesis: G, side: 1, balance: 55, owner: Buffer.alloc(20, 3) }), satoshis: CV.DUST })] }
    ]
  })()],
  [require('./src/predicates/guarded'), (() => {
    const bsvL = require('@smartledger/bsv')
    const GD = require('./src/predicates/guarded')
    const OA = bsvL.PrivateKey.fromRandom(); const OB = bsvL.PrivateKey.fromRandom()
    const G = GD.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const base = { genesis: G, ownerA: OA, ownerB: OB, satoshis: GD.DUST, requiredFlag: 1 }
    return [
      // conserve ∧ witness: the pair rebalances only while the oracle coin is co-spent with the flag
      { ...base, name: 'guarded: rebalance while the oracle shows flag 1, spend side 0', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA },
      { ...base, name: 'guarded: rebalance, spend side 1', kind: 'genesis', a0: 60, b0: 40, newA: 70, newB: 30, spendSide: 1, ownerKey: OB },
      { ...base, name: 'guarded: a second-generation rebalance still gated', kind: 'child', a0: 60, b0: 40, a1: 50, b1: 50, newA: 20, newB: 80, spendSide: 0, ownerKey: OA },

      // the witness half: the oracle must be present and carry the required flag
      { ...base, name: 'guarded: refused when the oracle carries the wrong flag', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, presentOracleFlag: 2, shouldFail: true },
      { ...base, name: 'guarded: refused when the oracle is not co-spent', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, omitOracle: true, shouldFail: true },

      // the conserve half still bites: conservation, descent, and ownership
      { ...base, name: 'guarded: a rebalance that breaks the sum is refused', kind: 'genesis', a0: 60, b0: 40, newA: 60, newB: 60, spendSide: 0, ownerKey: OA, shouldFail: true },
      { ...base, name: 'guarded: a counterfeit pair is refused', kind: 'genesis', counterfeit: true, a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true },
      { ...base, name: 'guarded: the wrong owner is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: bsvL.PrivateKey.fromRandom(), shouldFail: true }
    ]
  })()],
  [require('./src/predicates/pool'), (() => {
    const bsvL = require('@smartledger/bsv')
    const PL = require('./src/predicates/pool')
    const k = Array.from({ length: 4 }, () => bsvL.PrivateKey.fromRandom())
    const G = PL.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const b3 = { genesis: G, N: 3, owners: k.slice(0, 3), satoshis: PL.DUST }
    const b4 = { genesis: G, N: 4, owners: k, satoshis: PL.DUST }
    return [
      // N coins whose balances always sum to the same constant, rebalanced atomically
      { ...b3, name: 'pool: N=3 rebalance (50,30,20) -> (40,40,20)', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0] },
      { ...b3, name: 'pool: N=3 move all into one bucket (50,30,20) -> (0,0,100)', kind: 'genesis', start: [50, 30, 20], next: [0, 0, 100], spendIndex: 0, ownerKey: k[0] },
      { ...b3, name: 'pool: N=3 second-generation rebalance (induction)', kind: 'child', start: [50, 30, 20], mid: [40, 40, 20], next: [10, 40, 50], spendIndex: 0, ownerKey: k[0] },
      { ...b4, name: 'pool: N=4 rebalance (40,30,20,10) -> (25,25,25,25)', kind: 'genesis', start: [40, 30, 20, 10], next: [25, 25, 25, 25], spendIndex: 0, ownerKey: k[0] },

      // conservation across the WHOLE group: Σ must be preserved
      { ...b3, name: 'pool: a rebalance that inflates the total is refused', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 30], spendIndex: 0, ownerKey: k[0], shouldFail: true },

      // the whole group must be co-spent — a missing member is refused
      { ...b3, name: 'pool: refused when a member is not co-spent', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0], omitMember: true, shouldFail: true },

      // ownership and descent, as in conserve
      { ...b3, name: 'pool: a rebalance signed by the wrong owner is refused', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: bsvL.PrivateKey.fromRandom(), shouldFail: true },
      { ...b3, name: 'pool: a counterfeit group is refused', kind: 'genesis', counterfeit: true, start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0], shouldFail: true }
    ]
  })()],
  [require('./src/predicates/audited'), (() => {
    const bsvL = require('@smartledger/bsv')
    const AU = require('./src/predicates/audited')
    const OA = bsvL.PrivateKey.fromRandom(); const OB = bsvL.PrivateKey.fromRandom()
    const G = AU.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const base = { genesis: G, ownerA: OA, ownerB: OB, satoshis: AU.DUST }
    return [
      // conserve ∧ journal: a rebalance conserves the sum AND appends to the audit chain
      { ...base, name: 'audited: rebalance (60,40)->(45,55), audit seq 0->1', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA },
      { ...base, name: 'audited: rebalance side 1', kind: 'genesis', a0: 60, b0: 40, newA: 70, newB: 30, spendSide: 1, ownerKey: OB },
      { ...base, name: 'audited: second rebalance, audit seq 1->2 (chain + descent)', kind: 'child', a0: 60, b0: 40, a1: 50, b1: 50, newA: 20, newB: 80, spendSide: 0, ownerKey: OA },

      // the conserve half still bites
      { ...base, name: 'audited: a rebalance that breaks the sum is refused', kind: 'genesis', a0: 60, b0: 40, newA: 60, newB: 60, spendSide: 0, ownerKey: OA, shouldFail: true },
      { ...base, name: 'audited: a counterfeit pair is refused', kind: 'genesis', counterfeit: true, a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true },
      { ...base, name: 'audited: the wrong owner is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: bsvL.PrivateKey.fromRandom(), shouldFail: true },

      // the journal half: the audit chain must advance and chain correctly
      { ...base, name: 'audited: a successor that does not advance the audit seq is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true,
        actualOutputs: ({ oa, ob, nhead }) => [
          new bsv.Transaction.Output({ script: AU.buildScript({ genesis: G, side: 0, balance: 45, owner: oa, seq: 0, head: nhead }), satoshis: AU.DUST }),
          new bsv.Transaction.Output({ script: AU.buildScript({ genesis: G, side: 1, balance: 55, owner: ob, seq: 0, head: nhead }), satoshis: AU.DUST })] },
      { ...base, name: 'audited: a tampered audit head is refused', kind: 'genesis', a0: 60, b0: 40, newA: 45, newB: 55, spendSide: 0, ownerKey: OA, shouldFail: true,
        actualOutputs: ({ oa, ob, nseq }) => [
          new bsv.Transaction.Output({ script: AU.buildScript({ genesis: G, side: 0, balance: 45, owner: oa, seq: nseq, head: Buffer.alloc(32, 0xff) }), satoshis: AU.DUST }),
          new bsv.Transaction.Output({ script: AU.buildScript({ genesis: G, side: 1, balance: 55, owner: ob, seq: nseq, head: Buffer.alloc(32, 0xff) }), satoshis: AU.DUST })] }
    ]
  })()],
  [require('./src/predicates/ledger'), (() => {
    const bsvL = require('@smartledger/bsv')
    const LG = require('./src/predicates/ledger')
    const k = Array.from({ length: 4 }, () => bsvL.PrivateKey.fromRandom())
    const G = LG.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
    const b3 = { genesis: G, N: 3, owners: k.slice(0, 3), satoshis: LG.DUST }
    const b4 = { genesis: G, N: 4, owners: k, satoshis: LG.DUST }
    return [
      // pool ∧ journal: an N-body conserved treasury that also appends every rebalance to an audit chain
      { ...b3, name: 'ledger: N=3 rebalance (50,30,20) -> (40,40,20), audit seq 0->1', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0] },
      { ...b4, name: 'ledger: N=4 rebalance, audit seq 0->1', kind: 'genesis', start: [40, 30, 20, 10], next: [25, 25, 25, 25], spendIndex: 0, ownerKey: k[0] },
      { ...b3, name: 'ledger: second-generation rebalance, audit seq 1->2 (chain + descent)', kind: 'child', start: [50, 30, 20], mid: [40, 40, 20], next: [10, 40, 50], spendIndex: 0, ownerKey: k[0] },

      // the conserve half
      { ...b3, name: 'ledger: a rebalance that inflates the total is refused', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 30], spendIndex: 0, ownerKey: k[0], shouldFail: true },
      { ...b3, name: 'ledger: refused when a member is not co-spent', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0], omitMember: true, shouldFail: true },
      { ...b3, name: 'ledger: a counterfeit group is refused', kind: 'genesis', counterfeit: true, start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0], shouldFail: true },
      { ...b3, name: 'ledger: the wrong owner is refused', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: bsvL.PrivateKey.fromRandom(), shouldFail: true },

      // the journal half: every member's audit chain must advance and chain correctly
      { ...b3, name: 'ledger: a member that does not advance its audit seq is refused', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0], shouldFail: true,
        actualOutputs: ({ owners, nhead }) => [40, 40, 20].map((b, i) => new bsv.Transaction.Output({ script: LG.buildScript({ genesis: G, index: i, balance: b, owner: owners[i], seq: 0, head: nhead, N: 3 }), satoshis: LG.DUST })) },
      { ...b3, name: 'ledger: a tampered audit head is refused', kind: 'genesis', start: [50, 30, 20], next: [40, 40, 20], spendIndex: 0, ownerKey: k[0], shouldFail: true,
        actualOutputs: ({ owners, nseq }) => [40, 40, 20].map((b, i) => new bsv.Transaction.Output({ script: LG.buildScript({ genesis: G, index: i, balance: b, owner: owners[i], seq: nseq, head: Buffer.alloc(32, 0xff), N: 3 }), satoshis: LG.DUST })) }
    ]
  })()],
  [require('./src/predicates/turns'), (() => {
    const bsvL = require('@smartledger/bsv')
    const T = require('./src/predicates/turns')
    const A = bsvL.PrivateKey.fromRandom(); const B = bsvL.PrivateKey.fromRandom(); const S = bsvL.PrivateKey.fromRandom()
    const s1 = Buffer.alloc(32, 1); const s2 = Buffer.alloc(32, 2)
    const base = { a: A, b: B, aKey: A, bKey: B, satoshis: 5000 }
    return [
      // the player whose turn it is moves; the turn alternates
      { ...base, name: 'turns: player a moves on turn 0, flipping to turn 1', branch: 'move', turn: 0, gstate: Buffer.alloc(32), to: s1, moverKey: A },
      { ...base, name: 'turns: player b moves on turn 1, flipping to turn 0', branch: 'move', turn: 1, gstate: s1, to: s2, moverKey: B },

      // authority is turn-bound — the wrong player cannot move
      { ...base, name: 'turns: b cannot move on a\'s turn', branch: 'move', turn: 0, gstate: Buffer.alloc(32), to: s1, moverKey: B, shouldFail: true },
      { ...base, name: 'turns: a cannot move on b\'s turn', branch: 'move', turn: 1, gstate: s1, to: s2, moverKey: A, shouldFail: true },
      { ...base, name: 'turns: a stranger cannot move', branch: 'move', turn: 0, gstate: Buffer.alloc(32), to: s1, moverKey: S, shouldFail: true },

      // the turn must alternate — a successor that keeps the same turn is refused
      { ...base, name: 'turns: a move that does not flip the turn is refused', branch: 'move', turn: 0, gstate: Buffer.alloc(32), to: s1, moverKey: A, shouldFail: true,
        actualOutputs: ({ fee }) => [new bsv.Transaction.Output({ script: T.buildScript({ a: A, b: B, turn: 0, gstate: s1, fee }), satoshis: 5000 - fee })] },

      // settle: both players agree, paying the winner (the exit)
      { ...base, name: 'turns: both players settle and pay the winner', branch: 'settle', turn: 1, gstate: s2, winner: A },
      { ...base, name: 'turns: settle with only one signature is refused', branch: 'settle', turn: 1, gstate: s2, winner: A, bKey: S, shouldFail: true }
    ]
  })()],
  [require('./src/predicates/ticket'), (() => {
    const base = {
      key,
      owner: key.toAddress().toString(),
      newOwner: other.toAddress().toString(),
      venue: beneficiary,
      event: 'Barbican 2026-11-04',
      seat: 'K12',
      maxPrice: 50000,
      venueBps: 1000,
      ticketValue: 600,
      satoshis: 100000,
      price: 40000
    }
    const outsider = bsv.PrivateKey.fromRandom()

    return [
      { ...base, name: 'ticket: a resale under the cap spends' },
      { ...base, name: 'ticket: a resale exactly at the cap spends', price: 50000 },

      { ...base, name: 'ticket: one satoshi over the cap is refused',
        price: 50001, shouldFail: true },

      // The declared price is what the script reasons about; hashOutputs is
      // what it must match. Declaring less than you pay breaks the tie.
      { ...base, name: 'ticket: declaring a lower price than the tx pays is refused',
        pushPrice: 100, shouldFail: true },

      { ...base, name: 'ticket: short-changing the venue is refused',
        actualCut: 1, shouldFail: true },
      { ...base, name: 'ticket: dropping the venue output entirely is refused',
        dropVenueOutput: true, shouldFail: true },
      { ...base, name: 'ticket: paying the venue somewhere else is refused',
        actualVenue: stranger, shouldFail: true },

      // hashOutputs commits to order, so the same three outputs rearranged are
      // a different transaction.
      { ...base, name: 'ticket: the right outputs in the wrong order are refused',
        swapOutputs: true, shouldFail: true },

      { ...base, name: 'ticket: pocketing the proceeds instead of paying the seller is refused',
        actualSeller: stranger, shouldFail: true },
      { ...base, name: 'ticket: inflating the ticket’s own carried value is refused',
        actualTicketValue: 5000, shouldFail: true },
      { ...base, name: 'ticket: handing it to someone other than the declared buyer is refused',
        actualNewOwner: stranger, shouldFail: true },

      // Possession of the UTXO is not authority; the key named inside it is.
      { ...base, name: 'ticket: a stranger cannot resell a ticket they do not hold',
        signWith: outsider, shouldFail: true },

      // ---- and the one that passes, which is the point ----
      // Ten satoshis is under the cap, and a tenth of ten is one, so the venue
      // is paid exactly what the contract demands. The other £400 changes hands
      // by bank transfer. Nothing in Script can see it.
      { ...base, name: 'ticket: a 10-satoshi declared price clears the cap (the rest settles off-chain)',
        price: 10 },

      // ---- check-in: the terminal branch ----
      { ...base, name: 'ticket: the holder burns it at the door', branch: 'checkin' },

      { ...base, name: 'ticket: a stranger cannot burn someone else’s ticket',
        branch: 'checkin', signWith: outsider, shouldFail: true },

      { ...base, name: 'ticket: burning under another seat’s tag is refused',
        branch: 'checkin', shouldFail: true,
        actualBurnScript: new bsv.Script()
          .add(bsv.Opcode.OP_FALSE).add(bsv.Opcode.OP_RETURN)
          .add(require('./src/predicates/ticket').eventTag('Barbican 2026-11-04', 'K13')) },

      // The nullifier only nullifies if the output is genuinely unspendable.
      { ...base, name: 'ticket: checking in to a spendable output instead of a burn is refused',
        branch: 'checkin', shouldFail: true,
        actualBurnScript: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromString(stranger)) }
    ]
  })()],
  [require('./src/predicates/merkle'), (() => {
    const H = (b) => bsv.crypto.Hash.sha256sha256(b)

    // A real 4-level tree over 16 leaves, built the way Bitcoin builds them.
    const leaves = []
    for (let i = 0; i < 16; i++) leaves.push(H(Buffer.from('leaf' + i)))
    const levels = [leaves]
    while (levels[levels.length - 1].length > 1) {
      const prev = levels[levels.length - 1]
      const next = []
      for (let i = 0; i < prev.length; i += 2) next.push(H(Buffer.concat([prev[i], prev[i + 1]])))
      levels.push(next)
    }
    const root = levels[levels.length - 1][0]

    /** The sibling path for leaf `index`, from the leaf upward. */
    const proofFor = (index) => {
      const path = []
      let i = index
      for (let d = 0; d < levels.length - 1; d++) {
        const sib = levels[d][i ^ 1]
        path.push({ sibling: sib, right: (i % 2) === 0 })   // even index -> sibling on the right
        i = i >> 1
      }
      return path
    }

    const base = { root, depth: 4, satoshis: 2000 }
    const p5 = proofFor(5)
    return [
      { ...base, name: 'merkle: a leaf with its correct path spends',
        leaf: leaves[5], path: p5 },
      { ...base, name: 'merkle: a different leaf with its own path also spends',
        leaf: leaves[12], path: proofFor(12) },
      { ...base, name: 'merkle: the first leaf spends', leaf: leaves[0], path: proofFor(0) },
      { ...base, name: 'merkle: the last leaf spends', leaf: leaves[15], path: proofFor(15) },

      { ...base, name: 'merkle: a leaf not in the tree is refused',
        leaf: H(Buffer.from('not a leaf')), path: p5, shouldFail: true },
      { ...base, name: 'merkle: the right leaf with the wrong path is refused',
        leaf: leaves[5], path: proofFor(6), shouldFail: true },

      // The direction bits are half the proof. Flipping one keeps every hash
      // valid and lands on a different root.
      { ...base, name: 'merkle: the same siblings with a flipped direction bit are refused',
        leaf: leaves[5], shouldFail: true,
        actualPath: p5.map((n, i) => i === 1 ? { ...n, right: !n.right } : n) },

      { ...base, name: 'merkle: a truncated path is refused',
        leaf: leaves[5], path: p5.slice(0, 3), shouldFail: true }
    ]
  })()]
]

module.exports = { runs }
