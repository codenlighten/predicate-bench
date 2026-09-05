#!/usr/bin/env node
'use strict'

const path = require('path')
const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const root = path.join(__dirname, '..')
const { compile, invariants, deriveRefusals } = require(path.join(root, 'src/compile'))
const hasCode = (problems, code) => problems.some((p) => p.code === code)

// The compiler is only trustworthy if it emits EXACTLY what the hand-written,
// mainnet-deployed predicates emit. This proves that byte-for-byte, then shows
// the invariant pass refusing specs that reproduce real pitfalls.

const covenant = require(path.join(root, 'src/predicates/covenant'))
const perpetual = require(path.join(root, 'src/predicates/perpetual'))
const metered = require(path.join(root, 'src/predicates/metered'))
const vesting = require(path.join(root, 'src/predicates/vesting'))
const token = require(path.join(root, 'src/predicates/token'))
const lineage = require(path.join(root, 'src/predicates/lineage'))
const provenance = require(path.join(root, 'src/predicates/provenance'))
const sovereign = require(path.join(root, 'src/predicates/sovereign'))
const timelock = require(path.join(root, 'src/predicates/timelock'))
const asset = require(path.join(root, 'src/predicates/asset'))

let failed = 0
function ok (cond, msg) { console.log((cond ? '  ok  ' : 'FAIL  ') + msg); if (!cond) failed++ }

// ---- 1. byte identity with the deployed predicates -------------------------

const covExample = covenant.example()
const covExpected = PushTx.hashOutputs(covenant.outputs(covExample))
const covSpec = {
  name: 'covenant',
  body: [
    { op: 'auth' },
    { op: 'requireOutputs', expected: covExpected },
    { op: 'dropTrue' }
  ]
}
ok(compile(covSpec).toHex() === covenant.lock(covExample).toHex(),
  'covenant: compiled spec is byte-identical to the deployed predicate')

const perpExample = perpetual.example()
const perpSpec = {
  name: 'perpetual',
  terminates: 'fee-exhaustion',   // perpetual has no exit BY DESIGN; it must say so
  body: [
    { op: 'auth' },
    { op: 'assertSighashAll' },
    { op: 'recreateSelfMinusFee', fee: perpExample.hopFee }
  ]
}
ok(compile(perpSpec).toHex() === perpetual.lock(perpExample).toHex(),
  'perpetual: compiled spec is byte-identical to the deployed predicate')

// metered: a stateful, two-branch covenant (counter, hop/redeem) — raw-Script steps
const mEx = metered.example()
const HB = { headBytes: 4, counterBytes: 4 }
const meteredSpec = {
  name: 'metered',
  state: metered.counterBuf(mEx.counter),
  branch: {
    style: 'raw',
    if: {
      steps: [
        { op: 'meteredReadCounterKeep', ...HB },
        { op: 'meteredGuardBelow', max: mEx.maxHops },
        { op: 'meteredIncrementRecreate', counterBytes: 4, fee: mEx.hopFee }
      ]
    },
    else: {
      steps: [
        { op: 'meteredReadCounterDrop', ...HB },
        { op: 'meteredGuardAtLeast', max: mEx.maxHops },
        { op: 'meteredPayFixed', address: bsv.Address.fromString(mEx.redeemTo), fee: mEx.hopFee }
      ]
    }
  }
}
ok(compile(meteredSpec).toHex() === metered.lock(mEx).toHex(),
  'metered: compiled spec is byte-identical to the predicate (state + hop/redeem branches)')

// vesting: a two-branch covenant over StackAsm — withdraw/finish
const vEx = vesting.example()
const vP = { benPKH: vEx.beneficiaryPKH, total: vEx.total, start: vEx.start, end: vEx.end, fee: vEx.fee, dust: 546 }
const vestingSpec = {
  name: 'vesting',
  branch: {
    style: 'asm', given: ['bsig', 'bpub', 'preimage'],
    // decomposed: gate → read inputs → compute unvested → guard → pay
    if: {
      steps: [
        { op: 'vestGate', ...vP }, { op: 'vestReadValueParkChunk' }, { op: 'vestComputeUnvested', ...vP },
        { op: 'vestGuardVesting', ...vP }, { op: 'vestPayWithdraw', ...vP }
      ]
    },
    else: {
      steps: [
        { op: 'vestGate', ...vP }, { op: 'vestReadValueOnly' }, { op: 'vestComputeUnvested', ...vP },
        { op: 'vestGuardVested', ...vP }, { op: 'vestPayFinish', ...vP }
      ]
    }
  }
}
ok(compile(vestingSpec).toHex() === vesting.lock(vEx).toHex(),
  'vesting: compiled spec is byte-identical to the predicate (finer withdraw/finish steps)')

// token: the cross-input backtrace — merge (self-terminating body) / split
const mergeSteps = [
  { op: 'tokMergeReadSelf' }, { op: 'tokMergeConserve' }, { op: 'tokVerifySiblingVector' },
  { op: 'tokVerifySibSlice' }, { op: 'tokVerifyFunding' }, { op: 'tokBindMergeOutput' }, { op: 'tokFinishBranch' }
]
const tokenSpec = {
  name: 'token',
  state: token.balanceLE(300),
  branch: {
    style: 'asm',
    if: { given: ['lt4', 'iblob', 'outsBlob', 'sibBal8', 'sibling', 'preimage'], epilogue: false, steps: mergeSteps },
    else: { given: ['balA8', 'balB8', 'preimage'], epilogue: false, steps: [{ op: 'tokSplitReadSelf' }, { op: 'tokSplitConserve' }, { op: 'tokBindSplitOutputs' }, { op: 'tokFinishBranch' }] }
  }
}
ok(compile(tokenSpec).toHex() === token.lock({ balance: 300 }).toHex(),
  'token: compiled spec is byte-identical to the predicate (merge backtrace + split)')

// lineage: authenticity by descent — a linear-asm body (state + preamble + steps)
const G = lineage.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
const lineageSteps = [
  { op: 'linReadSelf' }, { op: 'linSuccessor' }, { op: 'descentReadParent' },
  { op: 'linGenesisOrParent' }, { op: 'tokFinishBranch' }
]
const lineageSpec = {
  name: 'lineage',
  state: G,
  preamble: 'authenticate',
  body: { style: 'asm', given: ['raw1', 'iblob2', 'lt2', 'preimage'], epilogue: false, steps: lineageSteps }
}
ok(compile(lineageSpec).toHex() === lineage.buildScript({ genesis: G }).toHex(),
  'lineage: compiled spec is byte-identical to the predicate (descent, linear-asm body)')

// provenance: authenticity + ownership — the composition, as one spec
const provSteps = [
  { op: 'provReadSelf' }, { op: 'provAuthorise' }, { op: 'provSuccessor' },
  { op: 'descentReadParent' }, { op: 'provGenesisOrParent' }, { op: 'tokFinishBranch' }
]
const provSpec = {
  name: 'provenance',
  state: Buffer.concat([G, provenance.hash160Of('1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS')]),
  preamble: 'authenticate',
  body: { style: 'asm', given: ['raw1', 'iblob2', 'lt2', 'parentOwner', 'newOwner', 'sig', 'pubkey', 'preimage'], epilogue: false, steps: provSteps }
}
ok(compile(provSpec).toHex() === provenance.buildScript({ genesis: G, owner: '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS' }).toHex(),
  'provenance: compiled spec is byte-identical to the predicate (authenticity + ownership)')

// sovereign: all three properties at once — a 3-way selector dispatch
const OWNER_ADDR = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'
const sovState = Buffer.concat([G, sovereign.hash160Of(OWNER_ADDR), sovereign.balanceLE(500)])
const sovereignSpec = {
  name: 'sovereign',
  state: sovState,
  dispatch: {
    cases: [
      { selector: 2, given: ['sibIblob', 'sibLt', 'sibOutsBlob', 'sibVout', 'sibling', 'raw1', 'iblob2', 'lt2', 'parentOutsBlob', 'newOwner', 'sig', 'pubkey'],
        steps: [{ op: 'sovExtractState' }, { op: 'sovRequireOwnerSig' }, { op: 'sovNewOwnerCheck' }, { op: 'sovMergeVector' }, { op: 'sovMergeSiblingBacktrace' }, { op: 'sovMergeConserve' }, { op: 'sovDescent' }, { op: 'tokFinishBranch' }] },
      { selector: 1, given: ['raw1', 'iblob2', 'lt2', 'parentOutsBlob', 'ownerA', 'ownerB', 'balA8', 'balB8', 'sig', 'pubkey'],
        steps: [{ op: 'sovExtractState' }, { op: 'sovRequireOwnerSig' }, { op: 'sovSplitConserve' }, { op: 'sovSplitOutputs' }, { op: 'sovDescent' }, { op: 'tokFinishBranch' }] },
      { selector: 0, given: ['raw1', 'iblob2', 'lt2', 'parentOutsBlob', 'newOwner', 'sig', 'pubkey'],
        steps: [{ op: 'sovExtractState' }, { op: 'sovRequireOwnerSig' }, { op: 'sovTransferSuccessor' }, { op: 'sovDescent' }, { op: 'tokFinishBranch' }] }
    ]
  }
}
ok(compile(sovereignSpec).toHex() === sovereign.buildScript({ genesis: G, owner: OWNER_ADDR, balance: 500 }).toHex(),
  'sovereign: compiled spec is byte-identical to the predicate (conservation + ownership + authenticity)')

// timelock: the semantic-type showcase. nLockTime read + compared is an inert
// value until the non-final-sequence guard makes an EnforceableLockTime.
const tlEx = timelock.example()
const timelockSpec = { name: 'timelock', body: [{ op: 'auth' }, { op: 'timelockSeqNonFinal' }, { op: 'timelockAtLeast', floor: tlEx.notBefore }, { op: 'dropTrue' }] }
ok(compile(timelockSpec).toHex() === timelock.lock(tlEx).toHex(),
  'timelock: compiled spec is byte-identical to the predicate (locktime + sequence guard)')
// remove the sequence guard: EnforceableLockTime cannot be derived; the lock is inert
const noSeq = { name: 'bad-inert-lock', body: [{ op: 'auth' }, { op: 'timelockAtLeast', floor: tlEx.notBefore }, { op: 'dropTrue' }] }
ok(hasCode(invariants(noSeq), 'E_LOCKTIME_INERT'),
  'E_LOCKTIME_INERT: nLockTime used without a non-final sequence — the derived type does not exist')

// asset: conservation + ownership over a 4-way dispatch, with the atomic swap
const assetState = Buffer.concat([asset.hash160Of(OWNER_ADDR), asset.balanceLE(500)])
const assetSpec = {
  name: 'asset',
  state: assetState,
  dispatch: {
    cases: [
      { selector: 3, given: ['outsBlob', 'myIndex', 'newOwner', 'sig', 'pubkey'],
        steps: [{ op: 'assetExtractState' }, { op: 'assetStride' }, { op: 'assetRequireOwnerSig' }, { op: 'assetSwapPin' }, { op: 'tokFinishBranch' }] },
      { selector: 2, given: ['lt4', 'iblob', 'outsBlob', 'sibOwner', 'sibBal8', 'sibling', 'newOwner', 'sig', 'pubkey'],
        steps: [{ op: 'assetExtractState' }, { op: 'assetStride' }, { op: 'assetRequireOwnerSig' }, { op: 'assetMergeConserve' }, { op: 'assetMergeVector' }, { op: 'assetMergeSibSlice' }, { op: 'assetVerifyFunding' }, { op: 'assetBindMergeOutput' }, { op: 'tokFinishBranch' }] },
      { selector: 1, given: ['ownerA', 'ownerB', 'balA8', 'balB8', 'sig', 'pubkey'],
        steps: [{ op: 'assetExtractState' }, { op: 'assetRequireOwnerSig' }, { op: 'assetSplitConserve' }, { op: 'assetSplitOutputs' }, { op: 'tokFinishBranch' }] },
      { selector: 0, given: ['newOwner', 'sig', 'pubkey'],
        steps: [{ op: 'assetExtractState' }, { op: 'assetRequireOwnerSig' }, { op: 'assetTransferSuccessor' }, { op: 'tokFinishBranch' }] }
    ]
  }
}
ok(compile(assetSpec).toHex() === asset.buildScript({ owner: OWNER_ADDR, balance: 500 }).toHex(),
  'asset: compiled spec is byte-identical to the predicate (conservation + ownership + swap)')
// the merge case alone trips ALL THREE invariants and satisfies each
ok(invariants(sovereignSpec).length === 0,
  'sovereign: the merge case satisfies conservation, authenticity AND ownership at once')

// ---- 2. structural invariants — the compiler refuses malformed specs -------

const openBind = { name: 'bad-open', body: [{ op: 'authOpen' }, { op: 'requireOutputs', expected: covExpected }, { op: 'dropTrue' }] }
ok(hasCode(invariants(openBind), 'E_REPLAYABLE_OUTPUTS'),
  'E_REPLAYABLE_OUTPUTS: outputs bound under a SINGLE|ANYONECANPAY core (pitfall 8)')

const noExit = { name: 'bad-noexit', body: [{ op: 'auth' }, { op: 'assertSighashAll' }, { op: 'recreateSelfMinusFee', fee: 150 }] }
ok(hasCode(invariants(noExit), 'E_STATE_STRANDING'),
  'E_STATE_STRANDING: self-recreating drainer with no exit / terminates (pitfall 18)')

const dirty = { name: 'bad-dirty', body: [{ op: 'auth' }, { op: 'requireOutputs', expected: covExpected }] }
ok(hasCode(invariants(dirty), 'E_DIRTY_STACK'),
  'E_DIRTY_STACK: no terminal step — the final stack would not be clean (CLEANSTACK)')

const noAuth = { name: 'bad-noauth', body: [{ op: 'requireOutputs', expected: covExpected }, { op: 'dropTrue' }] }
ok(hasCode(invariants(noAuth), 'E_UNVERIFIED_PREIMAGE'),
  'E_UNVERIFIED_PREIMAGE: no auth step — the preimage is unverified')

const oneBranch = { name: 'bad-onebranch', branch: { style: 'raw', if: meteredSpec.branch.if, else: null } }
ok(hasCode(invariants(oneBranch), 'E_MALFORMED_BRANCH'),
  'E_MALFORMED_BRANCH: a branch covenant with only one branch')

// ---- 3. THE SOURCE IS THE SECURITY SPEC ------------------------------------
// For every sound spec, the compiler derives — from its own structure — the
// adversarial mutations its invariants must reject: remove any proof of an
// obligation the spec claims, and the matching typed code must fire. These are
// the negative tests a developer would otherwise hand-write, generated instead.
const allSpecs = [
  ['covenant', covSpec], ['perpetual', perpSpec], ['metered', meteredSpec], ['vesting', vestingSpec],
  ['token', tokenSpec], ['lineage', lineageSpec], ['provenance', provSpec], ['sovereign', sovereignSpec],
  ['timelock', timelockSpec], ['asset', assetSpec]
]
let derivedTotal = 0
let derivedOk = true
for (const [name, sp] of allSpecs) {
  for (const r of deriveRefusals(sp)) {
    derivedTotal++
    if (!hasCode(invariants(r.mutant), r.code)) {
      derivedOk = false
      console.log(`      ${name}: dropping ${r.removed} from ${r.label} did NOT fire ${r.code}`)
    }
  }
}
ok(derivedOk && derivedTotal >= 11,
  `derived ${derivedTotal} adversarial tests from the specs; every one is refused with its typed code`)
// spot-check that the sovereign merge case alone yields all three composition refusals
const sovCodes = deriveRefusals(sovereignSpec).filter((r) => r.label === 'case 2').map((r) => r.code).sort()
ok(JSON.stringify(sovCodes) === JSON.stringify(['E_COUNTERFEIT', 'E_INFLATION', 'E_THEFT']),
  'the sovereign merge case derives all three: E_INFLATION, E_COUNTERFEIT, E_THEFT')

// and the sound specs themselves pass every invariant
ok(allSpecs.every(([, sp]) => invariants(sp).length === 0),
  'accepts: all ten sound specs pass every invariant')

if (failed) {
  console.log(`\n${failed} compile-selftest failure(s)`)
  process.exit(1)
}
console.log('\ncompiler emits the deployed bytes, and refuses every seeded pitfall')
