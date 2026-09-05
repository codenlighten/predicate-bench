'use strict'

const bsv = require('@smartledger/bsv')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('./clauses')
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// Branch-body steps, shared by the predicates and the compiler.
//
// A single-body covenant reads as a straight clause list ([covenant],
// [perpetual]). A branching, stateful one ([metered], [vesting]) has two bodies
// with real stack choreography inside each. Rather than let those bodies exist in
// two places — once hand-written in the predicate, once re-emitted in the compiler
// — they live here once, as named steps, and BOTH callers use them. Byte identity
// is then guaranteed by construction, and the compiler's spec for these families
// is a genuine list of operations, not a per-predicate macro.
//
// Two emission styles, because the predicates that use them were written in two
// eras: the `metered*` steps append raw opcodes to a Script; the `vesting*` steps
// drive a StackAsm. Both are just fragments — a step emits a contiguous slice of a
// branch body and leaves the stack where the next step expects it.

// ---- metered: a carried counter, incremented or redeemed --------------------

/** Read the counter, KEEPING head+rest parked for recreation (the hop branch). */
function meteredReadCounterKeep (s, { headBytes, counterBytes }) {
  C.selfChunk(s)
  s.add(n(headBytes)).add(Opcode.OP_SPLIT)
  s.add(n(counterBytes)).add(Opcode.OP_SPLIT)
  s.add(Opcode.OP_TOALTSTACK)                                  // park rest
  s.add(Buffer.from([0])).add(Opcode.OP_CAT).add(Opcode.OP_BIN2NUM)
}
/** Read the counter, DISCARDING the surrounding bytes (the redeem branch). */
function meteredReadCounterDrop (s, { headBytes, counterBytes }) {
  C.selfChunk(s)
  s.add(n(headBytes)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
  s.add(n(counterBytes)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
  s.add(Buffer.from([0])).add(Opcode.OP_CAT).add(Opcode.OP_BIN2NUM)
}
function meteredGuardBelow (s, { max }) {
  s.add(Opcode.OP_DUP).add(n(max)).add(Opcode.OP_LESSTHAN).add(Opcode.OP_VERIFY)
}
function meteredGuardAtLeast (s, { max }) {
  s.add(n(max)).add(Opcode.OP_GREATERTHANOREQUAL).add(Opcode.OP_VERIFY)
}
/** counter+1, spliced back into the script, recreated minus the fee. */
function meteredIncrementRecreate (s, { counterBytes, fee }) {
  s.add(Opcode.OP_1ADD)
  s.add(n(counterBytes)).add(Opcode.OP_NUM2BIN)
  s.add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)            // head ‖ counter+1 ‖ rest
  s.add(Opcode.OP_OVER)
  C.newValueLE(s, fee)
  s.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)                    // value ‖ nextChunk
  C.requireOutputIs(s)
}
/** Settle the whole value (minus fee) to a fixed address. */
function meteredPayFixed (s, { address, fee }) {
  s.add(Opcode.OP_DUP)
  C.newValueLE(s, fee)
  s.add(C.txOutChunk(bsv.Script.buildPublicKeyHashOut(address))).add(Opcode.OP_CAT)
  C.requireOutputIs(s)
}

// ---- vesting: linear release over time (StackAsm) ---------------------------

function vestingBeneficiaryGate (asm, { benPKH }) {
  asm.pick('bpub'); asm.hash160('bh'); asm.data(benPKH, 'BPKH'); asm.equalVerify()
  asm.pick('bsig'); asm.pick('bpub'); asm.checkSigVerify()
}
function vestingReadValue (asm) {                              // preimage on top -> leaves B
  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.VALUE, 8), 0, ['Braw'])
  asm.data(Buffer.from([0]), 'zb'); asm.cat('Bpad'); asm.bin2num('B')
}
function vestingReadTime (asm) {                               // preimage on top -> leaves T
  asm.clause(C.requireSequenceNonFinal, 0, [])                // or nLockTime is no lower bound
  asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.LOCKTIME, 4), 0, ['Traw'])
  asm.data(Buffer.from([0]), 'zt'); asm.cat('Tpad'); asm.bin2num('T')
}
function vestingUnvested (asm, { total, start, end }) {        // consumes T -> leaves unvested
  const dur = end - start
  asm.num(end, 'END'); asm.swap(); asm.sub('rem0')
  asm.num(0, 'z0'); asm.max('rem1')
  asm.num(dur, 'DUR1'); asm.min('rem')
  asm.num(total, 'TOT'); asm.mul('prod')
  asm.num(dur, 'DUR2'); asm.div('unvested')
}
function vestingBindOutput (asm, outName) {                    // HASH256(outName) == preimage hashOutputs
  asm.pick(outName); asm.hash256('hOut')
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['hoField'])
  asm.nip(); asm.equalVerify()
}
function beneficiaryChunk (pkh) {
  return C.txOutChunk(bsv.Script.buildPublicKeyHashOut(bsv.Address.fromPublicKeyHash(pkh)))
}
// The two vesting branches, decomposed into the finer steps a spec lists:
//   gate → read inputs → compute unvested → guard → pay.
// The `vestingWithdraw`/`vestingFinish` compositions below keep the predicate's
// call site unchanged (and byte-identical); the compiler lists the finer steps.

function vestGate (asm, { benPKH }) { vestingBeneficiaryGate(asm, { benPKH }) }

/** withdraw reads the input value AND parks its own chunk (it will recreate). */
function vestReadValueParkChunk (asm) {
  vestingReadValue(asm); asm.toAlt()                         // park B
  asm.clause(C.selfChunk, 0, ['chunk']); asm.toAlt()         // park my own script chunk
}
/** finish reads the input value only (it does not recreate). */
function vestReadValueOnly (asm) {
  vestingReadValue(asm); asm.toAlt()                         // park B
}
/** read the time (non-final), and compute unvested(T). */
function vestComputeUnvested (asm, { total, start, end }) {
  vestingReadTime(asm)
  vestingUnvested(asm, { total, start, end })
}
/** withdraw guard: still vesting, unvested ≥ DUST (keeps unvested for the payout). */
function vestGuardVesting (asm, { dust }) {
  asm.pick('unvested'); asm.num(dust, 'D'); asm.geVerify()
}
/** finish guard: essentially fully vested, unvested < DUST (then drop it). */
function vestGuardVested (asm, { dust }) {
  asm.pick('unvested'); asm.num(dust, 'D'); asm.ltVerify()
  asm.drop()
}
/** withdraw payout: recreate self@unvested, pay the beneficiary the rest. */
function vestPayWithdraw (asm, { benPKH, fee }) {
  asm.fromAlt()                                              // chunk
  asm.pick('unvested'); asm.num2bin(8, 'u8'); asm.pick('chunk'); asm.cat('out0')
  asm.fromAlt()                                              // B
  asm.pick('unvested'); asm.sub('bMinusU'); asm.num(fee, 'FEE'); asm.sub('payout')
  asm.num2bin(8, 'p8'); asm.data(beneficiaryChunk(benPKH), 'bc'); asm.cat('out1')
  asm.pick('out0'); asm.pick('out1'); asm.cat('outs'); asm.hash256('hOut')
  asm.pick('preimage'); asm.clause((x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32), 0, ['hoField'])
  asm.nip(); asm.equalVerify()
}
/** finish payout: pay the whole remainder to the beneficiary. */
function vestPayFinish (asm, { benPKH, fee }) {
  asm.fromAlt()                                              // B
  asm.num(fee, 'FEE'); asm.sub('payout')
  asm.num2bin(8, 'p8'); asm.data(beneficiaryChunk(benPKH), 'bc'); asm.cat('outF')
  vestingBindOutput(asm, 'outF')
}

/** withdraw: recreate self@unvested, pay the beneficiary the rest (unvested ≥ DUST). */
function vestingWithdraw (asm, p) {
  vestGate(asm, p); vestReadValueParkChunk(asm); vestComputeUnvested(asm, p)
  vestGuardVesting(asm, p); vestPayWithdraw(asm, p)
}
/** finish: pay the whole remainder to the beneficiary (unvested < DUST). */
function vestingFinish (asm, p) {
  vestGate(asm, p); vestReadValueOnly(asm); vestComputeUnvested(asm, p)
  vestGuardVested(asm, p); vestPayFinish(asm, p)
}

// ---- token: a balance conserved across merge and split ----------------------
//
// The merge branch is the bench's cross-input proof: a covenant cannot read a
// sibling's balance from its own preimage, so it BACKTRACES — rebuilds the
// sibling's funding tx with the CLAIMED balance spliced in and requires it to hash
// to the sibling's real txid. `tokMergeConserve` uses the pushed sibling balance;
// `tokVerifyFunding` is the backtrace that proves it. The compiler refuses a spec
// that has the first without the second — the naive-merge inflation attack, caught
// before it is ever built (docs/cross-input.md).

const TOK_BAL = 8
const TOK_HEAD = 4                                        // varint(3) ‖ 0x08 push-op
const TOK_DUST = 2000
const TOK_VERSION = Buffer.from('01000000', 'hex')
function tokDustLE () { const b = Buffer.alloc(8); b.writeUIntLE(TOK_DUST, 0, 6); return b }
const TOK_EXTRACT = {
  selfChunk: C.selfChunk,
  hashPrevouts: C.hashPrevoutsFromFront,
  hashOutputs: (x) => C.fieldFromEnd(x, C.FROM_END.HASH_OUTPUTS, 32),
  ownOutpoint: (x) => x.add(Opcode.OP_DUP).add(n(68)).add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
    .add(n(36)).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
}
/** Read one preimage field (the preimage stays parked on the altstack). */
function tokReadField (asm, which, name) {
  asm.fromAlt(); asm.clause(TOK_EXTRACT[which], 0, [name]); asm.swap(); asm.toAlt()
}
/** header ‖ <8-byte balance> ‖ tail, from a balance already on the stack. */
function tokChunkFrom (asm, balName, name) {
  asm.pick('header'); asm.pick(balName); asm.cat(name + '_h')
  asm.pick('tail'); asm.cat(name)
}
function tokFinishBranch (asm) {
  while (asm.main.length) asm.drop()
  asm.fromAlt(); asm.drop()
  asm.raw(Opcode.OP_1, 0, ['true'])
}

// merge steps: [lt4, iblob, outsBlob, sibBal8, sibling, preimage]
function tokMergeReadSelf (asm) {
  asm.toAlt()                                            // park preimage
  tokReadField(asm, 'selfChunk', 'chunk')
  asm.sizeOf('chunk', 'chunkLen')
  asm.pick('chunkLen'); asm.num(8, 'eight'); asm.add('stride')     // stride = 8 + chunkLen
  asm.roll('chunk'); asm.splitAt(TOK_HEAD, 'header', 'r1'); asm.splitAt(TOK_BAL, 'ownBal8', 'tail')
}
function tokMergeConserve (asm) {                        // reads the PUSHED sibling balance
  asm.pick('ownBal8'); asm.bin2num('ownNum')
  asm.pick('sibBal8'); asm.bin2num('sibNum'); asm.add('outNum'); asm.num2bin(TOK_BAL, 'balanceOut8')
  tokChunkFrom(asm, 'balanceOut8', 'outChunk')
  tokChunkFrom(asm, 'sibBal8', 'sibChunk')
}
function tokVerifySiblingVector (asm) {                  // sibling is really the other input
  tokReadField(asm, 'ownOutpoint', 'ownOutpoint')
  asm.pick('sibling'); asm.splitAt(32, 'txidB', 'vout4'); asm.bin2num('voutNum')
  asm.pick('ownOutpoint'); asm.pick('sibling'); asm.cat('vA'); asm.hash256('hvA')
  tokReadField(asm, 'hashPrevouts', 'hpA'); asm.equal('eqA')
  asm.pick('sibling'); asm.pick('ownOutpoint'); asm.cat('vB'); asm.hash256('hvB')
  tokReadField(asm, 'hashPrevouts', 'hpB'); asm.equal('eqB')
  asm.raw(Opcode.OP_BOOLOR, 2, ['vecOk']); asm.verify()
}
function tokVerifySibSlice (asm) {                       // sibling output at its vout is what we claim
  asm.sizeOf('outsBlob', 'outsSize')
  asm.pick('outsSize'); asm.pick('stride'); asm.div('count')
  asm.pick('count'); asm.pick('stride'); asm.mul('cs'); asm.pick('outsSize'); asm.numEqualVerify()
  asm.pick('count'); asm.num(1, 'one1'); asm.geVerify()
  asm.pick('count'); asm.num(2, 'two2'); asm.leVerify()
  asm.pick('count'); asm.num2bin(1, 'countByte')
  asm.pick('voutNum'); asm.pick('stride'); asm.mul('offset')
  asm.pick('outsBlob'); asm.pick('offset'); asm.split('pre', 'rest')
  asm.pick('stride'); asm.split('sibSlice', 'post')
  asm.drop(); asm.nip()
  asm.data(tokDustLE(), 'dustE'); asm.pick('sibChunk'); asm.cat('expectedSib')
  asm.equalVerify()
}
function tokVerifyFunding (asm) {                        // THE BACKTRACE: rebuild funding, hash == txidB
  asm.data(TOK_VERSION, 'ver'); asm.pick('iblob'); asm.cat('vi')
  asm.pick('countByte'); asm.cat('vic')
  asm.pick('outsBlob'); asm.cat('vico')
  asm.pick('lt4'); asm.size('ltsz'); asm.num(4, 'four'); asm.equalVerify()
  asm.cat('funding'); asm.hash256('fhash')
  asm.pick('txidB'); asm.equalVerify()
}
function tokBindMergeOutput (asm) {
  asm.data(tokDustLE(), 'dust2'); asm.pick('outChunk'); asm.cat('outTxOut')
  asm.hash256('outHash')
  tokReadField(asm, 'hashOutputs', 'hashOutputs'); asm.equalVerify()
}
function tokEmitMerge (asm) {
  tokMergeReadSelf(asm); tokMergeConserve(asm); tokVerifySiblingVector(asm)
  tokVerifySibSlice(asm); tokVerifyFunding(asm); tokBindMergeOutput(asm); tokFinishBranch(asm)
}

// split steps: [balA8, balB8, preimage]
function tokSplitReadSelf (asm) {
  asm.toAlt()
  tokReadField(asm, 'selfChunk', 'chunk')
  asm.splitAt(TOK_HEAD, 'header', 'r1'); asm.splitAt(TOK_BAL, 'ownBal8', 'tail')
}
function tokSplitConserve (asm) {
  asm.pick('balA8'); asm.bin2num('aNum')
  asm.pick('balB8'); asm.bin2num('bNum'); asm.add('abNum')
  asm.pick('ownBal8'); asm.bin2num('ownNum')
  asm.numEqualVerify()
}
function tokBindSplitOutputs (asm) {
  tokChunkFrom(asm, 'balA8', 'chunkA')
  asm.data(tokDustLE(), 'dA'); asm.pick('chunkA'); asm.cat('out0')
  tokChunkFrom(asm, 'balB8', 'chunkB')
  asm.data(tokDustLE(), 'dB'); asm.pick('chunkB'); asm.cat('out1')
  asm.pick('out0'); asm.pick('out1'); asm.cat('outs')
  asm.hash256('outsHash')
  tokReadField(asm, 'hashOutputs', 'hashOutputs'); asm.equalVerify()
}
function tokEmitSplit (asm) {
  tokSplitReadSelf(asm); tokSplitConserve(asm); tokBindSplitOutputs(asm); tokFinishBranch(asm)
}

// ---- lineage: authenticity by bounded backtrace to a genesis -----------------
//
// A token carries its GENESIS outpoint in its scriptCode and, on every spend,
// proves its IMMEDIATE parent was a genuine token of the same genesis — OR that it
// is the mint (its funding tx spent the genesis outpoint directly). Induction does
// the rest: the parent's own covenant already ran when it was spent. The step that
// binds the successor to carry the genesis (`linSuccessor`) is authenticity CLAIMED;
// `linGenesisOrParent` is authenticity PROVEN. A covenant with the first and not
// the second is a self-perpetuating counterfeit — the compiler refuses it.
//
// Reuses the token-family field reader, finish, dust and version; a genesis is 36
// bytes and its push-op makes the same 4-byte head as a balance chunk.
const LIN_G = 36

function linReadSelf (asm) {
  asm.toAlt()                                            // park preimage
  tokReadField(asm, 'selfChunk', 'myChunk')
  asm.pick('myChunk'); asm.splitAt(TOK_HEAD, 'gh', 'gr'); asm.splitAt(LIN_G, 'G', 'gtail')
  asm.drop(); asm.nip()                                  // keep G, myChunk preserved
}
function linSuccessor (asm) {                            // successor is my exact self, same genesis
  asm.data(tokDustLE(), 'd'); asm.pick('myChunk'); asm.cat('myTxOut')
  asm.pick('myTxOut'); asm.hash256('outHash')
  tokReadField(asm, 'hashOutputs', 'ho'); asm.equalVerify()
}
// Recover my own funding txid from the preimage, hash raw1 to it, and split out my
// parent's outpoint (input 0 of raw1). Context-adaptive — StackAsm emits the right
// depths for whatever stack it runs in — so lineage and provenance share it.
function descentReadParent (asm) {
  tokReadField(asm, 'ownOutpoint', 'myOutpoint')
  asm.pick('myOutpoint'); asm.splitAt(32, 'myTxid', 'myVout'); asm.drop()
  asm.pick('raw1'); asm.hash256('r1h'); asm.pick('myTxid'); asm.equalVerify()
  asm.pick('raw1'); asm.splitAt(5, 'p5', 'r1rest'); asm.nip()      // drop version + inCount(1)
  asm.splitAt(LIN_G, 'parentOutpoint', 'ptail'); asm.drop()
}
function linGenesisOrParent (asm) {                      // authentic if mint OR parent was genuine
  asm.pick('parentOutpoint'); asm.pick('G'); asm.equal('genesisMatch')
  asm.pick('parentOutpoint'); asm.splitAt(32, 'pTxid', 'pv'); asm.drop()
  asm.data(TOK_VERSION, 'ver'); asm.pick('iblob2'); asm.cat('vi')
  asm.raw(Opcode.OP_1, 0, ['oc']); asm.cat('vio')                  // output count 0x01
  asm.pick('myTxOut'); asm.cat('viot')                            // parent output == lineage+G == mine
  asm.pick('lt2'); asm.size('ltsz'); asm.num(4, 'four'); asm.equalVerify(); asm.cat('raw2')
  asm.hash256('r2h'); asm.pick('pTxid'); asm.equal('parentValid')
  asm.pick('genesisMatch'); asm.pick('parentValid'); asm.raw(Opcode.OP_BOOLOR, 2, ['ok']); asm.verify()
}
function linEmit (asm) {
  linReadSelf(asm); linSuccessor(asm); descentReadParent(asm); linGenesisOrParent(asm); tokFinishBranch(asm)
}

// ---- provenance: authenticity + ownership (lineage descent + titled owner) ----
//
// State is genesis(36) ‖ owner(20). Every transfer both AUTHORISES (the current
// owner signed) and PROVES DESCENT (parent was a genuine token of the same
// genesis). The owner is spender-chosen and spliced into the successor, so
// `provSuccessor` is tagged `writesOwner` (must be authorised — the titled
// "possession is not authority" rule) AND `recreatesGenesis` (must prove descent).
const PROV_OWNER = 20

/** header ‖ genesis ‖ <owner> ‖ tail — a full provenance chunk for `ownerName`. */
function provChunkWith (asm, ownerName, out) {
  asm.pick('header'); asm.pick('genesis'); asm.cat(out + '_hg')
  asm.pick(ownerName); asm.cat(out + '_hgo'); asm.pick('tail'); asm.cat(out)
}
function provReadSelf (asm) {
  asm.toAlt()
  tokReadField(asm, 'selfChunk', 'myChunk')
  asm.roll('myChunk'); asm.splitAt(TOK_HEAD, 'header', 'r1')
  asm.splitAt(LIN_G, 'genesis', 'r2'); asm.splitAt(PROV_OWNER, 'owner', 'tail')
}
function provAuthorise (asm) {                           // the current owner signed
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('owner'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
}
function provSuccessor (asm) {                           // same genesis, spender-chosen new owner
  asm.pick('newOwner'); asm.size('noSz'); asm.num(PROV_OWNER, 'ob'); asm.equalVerify()
  provChunkWith(asm, 'newOwner', 'outChunk')
  asm.data(tokDustLE(), 'd'); asm.pick('outChunk'); asm.cat('outTxOut')
  asm.hash256('outHash'); tokReadField(asm, 'hashOutputs', 'ho'); asm.equalVerify()
}
function provGenesisOrParent (asm) {                     // mint, or a genuine parent of the same genesis
  asm.pick('parentOutpoint'); asm.pick('genesis'); asm.equal('genesisMatch')
  asm.pick('parentOutpoint'); asm.splitAt(32, 'pTxid', 'pv'); asm.drop()
  provChunkWith(asm, 'parentOwner', 'parentChunk')
  asm.data(tokDustLE(), 'pd'); asm.pick('parentChunk'); asm.cat('parentTxOut')
  asm.data(TOK_VERSION, 'ver'); asm.pick('iblob2'); asm.cat('vi')
  asm.raw(Opcode.OP_1, 0, ['oc']); asm.cat('vio')
  asm.pick('parentTxOut'); asm.cat('viot')
  asm.pick('lt2'); asm.size('ltsz'); asm.num(4, 'four'); asm.equalVerify(); asm.cat('raw2')
  asm.hash256('r2h'); asm.pick('pTxid'); asm.equal('parentValid')
  asm.pick('genesisMatch'); asm.pick('parentValid'); asm.raw(Opcode.OP_BOOLOR, 2, ['ok']); asm.verify()
}
function provEmit (asm) {
  provReadSelf(asm); provAuthorise(asm); provSuccessor(asm)
  descentReadParent(asm); provGenesisOrParent(asm); tokFinishBranch(asm)
}

// ---- sovereign: conservation + ownership + authenticity, divisible -----------
//
// State is genesis(36) ‖ owner(20) ‖ balance(8). Three ops (transfer/split/merge),
// each running all three checks. The descent is MULTI-OUTPUT (a split child has a
// two-output parent), so it reconstructs the parent's whole output section and pins
// the child's slice by vout — token's backtrace, checking the slice is a sovereign
// of my genesis — with the genesis case an OP_IF/OP_ELSE alternative to it.
const SOV_PREFIX = 8 + TOK_HEAD + LIN_G                  // dust ‖ head ‖ genesis, before the owner

function sovChunk5 (asm, ownerName, balName, out) {
  asm.pick('header'); asm.pick('genesis'); asm.cat(out + '_hg')
  asm.pick(ownerName); asm.cat(out + '_hgo'); asm.pick(balName); asm.cat(out + '_hgob')
  asm.pick('tail'); asm.cat(out)
}
function sovTxOut (asm, chunkName, out) {
  asm.data(tokDustLE(), out + '_d'); asm.pick(chunkName); asm.cat(out)
}
function sovExtractState (asm) {
  tokReadField(asm, 'selfChunk', 'myChunk')
  asm.pick('myChunk'); asm.size('chunkLen'); asm.nip()
  asm.pick('chunkLen'); asm.num(8, 'eight'); asm.add('stride')
  asm.data(tokDustLE(), 'pfxD')
  asm.roll('myChunk'); asm.splitAt(TOK_HEAD, 'header', 'r1')
  asm.splitAt(LIN_G, 'genesis', 'r2'); asm.splitAt(PROV_OWNER, 'owner', 'r3')
  asm.splitAt(TOK_BAL, 'balance8', 'tail')
  asm.pick('pfxD'); asm.pick('header'); asm.cat('pfxDh')
  asm.pick('genesis'); asm.cat('prefix')
}
function sovRequireOwnerSig (asm) {
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('owner'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
}
/** Multi-output backtrace: reconstruct the parent/sibling funding, pin the slice at
 *  `vout` as a sovereign of my genesis, leave its balance as `outBal`. */
function sovSliceBacktrace (asm, P, { iblob, lt, outsBlob, vout, txid, outBal }) {
  const entryLen = asm.main.length
  asm.pick(outsBlob); asm.size(P + 'Size'); asm.nip()
  asm.pick(P + 'Size'); asm.pick('stride'); asm.div(P + 'Count')
  asm.pick(P + 'Count'); asm.pick('stride'); asm.mul(P + 'cs'); asm.pick(P + 'Size'); asm.numEqualVerify()
  asm.pick(P + 'Count'); asm.num2bin(1, P + 'CountByte')
  asm.data(TOK_VERSION, P + 'ver'); asm.pick(iblob); asm.cat(P + 'vi')
  asm.pick(P + 'CountByte'); asm.cat(P + 'vic'); asm.pick(outsBlob); asm.cat(P + 'vico')
  asm.pick(lt); asm.size(P + 'ltsz'); asm.num(4, P + 'four'); asm.equalVerify(); asm.cat(P + 'funding')
  asm.hash256(P + 'fh'); asm.pick(txid); asm.equalVerify()
  asm.pick(vout); asm.pick('stride'); asm.mul(P + 'off')
  asm.pick(outsBlob); asm.pick(P + 'off'); asm.split(P + 'pre', P + 'rest')
  asm.pick('stride'); asm.split(P + 'slice', P + 'post'); asm.drop(); asm.nip()
  asm.splitAt(SOV_PREFIX, P + 'sPfx', P + 'sr')
  asm.pick('prefix'); asm.pick(P + 'sPfx'); asm.equalVerify()
  asm.splitAt(PROV_OWNER, P + 'sOwner', P + 'sr2'); asm.nip()
  asm.splitAt(TOK_BAL, outBal, P + 'sTail')
  asm.pick('tail'); asm.pick(P + 'sTail'); asm.equalVerify()
  asm.roll(outBal)
  while (asm.main.length > entryLen + 1) asm.nip()
}
/** Descent: genesis case (mint spent G), or the multi-output parent backtrace. */
function sovDescent (asm) {
  descentReadParent(asm)                                 // shared: my funding, my parent's outpoint
  asm.pick('parentOutpoint'); asm.splitAt(32, 'pTxid', 'pVoutRaw'); asm.bin2num('pVout')
  asm.pick('parentOutpoint'); asm.pick('genesis'); asm.equal('genesisMatch')
  asm.beginIf()
  asm.elseBranch()
  sovSliceBacktrace(asm, 'd', { iblob: 'iblob2', lt: 'lt2', outsBlob: 'parentOutsBlob', vout: 'pVout', txid: 'pTxid', outBal: 'dBal' })
  asm.drop()                                             // descent ignores the balance
  asm.endIf()
}
function sovNewOwnerCheck (asm) {
  asm.pick('newOwner'); asm.size('noSz'); asm.num(PROV_OWNER, 'ob'); asm.equalVerify()
}
function sovTransferSuccessor (asm) {
  sovNewOwnerCheck(asm)
  sovChunk5(asm, 'newOwner', 'balance8', 'outChunk')
  sovTxOut(asm, 'outChunk', 'outTxOut')
  asm.hash256('outHash'); tokReadField(asm, 'hashOutputs', 'ho'); asm.equalVerify()
}
function sovSplitConserve (asm) {
  asm.pick('balA8'); asm.bin2num('aNum')
  asm.pick('balB8'); asm.bin2num('bNum'); asm.add('abNum')
  asm.pick('balance8'); asm.bin2num('ownNum'); asm.numEqualVerify()
}
function sovSplitOutputs (asm) {
  sovChunk5(asm, 'ownerA', 'balA8', 'chunkA'); sovTxOut(asm, 'chunkA', 'out0')
  sovChunk5(asm, 'ownerB', 'balB8', 'chunkB'); sovTxOut(asm, 'chunkB', 'out1')
  asm.pick('out0'); asm.pick('out1'); asm.cat('outs'); asm.hash256('outsHash')
  tokReadField(asm, 'hashOutputs', 'ho'); asm.equalVerify()
}
function sovMergeVector (asm) {
  tokReadField(asm, 'ownOutpoint', 'myOutpoint')
  asm.pick('sibling'); asm.splitAt(32, 'sibTxid', 'sibVoutBytes'); asm.drop()
  asm.pick('myOutpoint'); asm.pick('sibling'); asm.cat('vA'); asm.hash256('hvA')
  tokReadField(asm, 'hashPrevouts', 'hpA'); asm.equal('eqA')
  asm.pick('sibling'); asm.pick('myOutpoint'); asm.cat('vB'); asm.hash256('hvB')
  tokReadField(asm, 'hashPrevouts', 'hpB'); asm.equal('eqB')
  asm.raw(Opcode.OP_BOOLOR, 2, ['vecOk']); asm.verify()
}
function sovMergeSiblingBacktrace (asm) {
  sovSliceBacktrace(asm, 's', { iblob: 'sibIblob', lt: 'sibLt', outsBlob: 'sibOutsBlob', vout: 'sibVout', txid: 'sibTxid', outBal: 'sibBal8' })
}
function sovMergeConserve (asm) {
  asm.pick('balance8'); asm.bin2num('ownNum')
  asm.pick('sibBal8'); asm.bin2num('sibNum'); asm.add('outNum'); asm.num2bin(TOK_BAL, 'balanceOut8')
  sovChunk5(asm, 'newOwner', 'balanceOut8', 'outChunk')
  sovTxOut(asm, 'outChunk', 'outTxOut')
  asm.hash256('outHash'); tokReadField(asm, 'hashOutputs', 'ho'); asm.equalVerify()
}
function sovEmitTransfer (asm) {
  sovExtractState(asm); sovRequireOwnerSig(asm); sovTransferSuccessor(asm); sovDescent(asm); tokFinishBranch(asm)
}
function sovEmitSplit (asm) {
  sovExtractState(asm); sovRequireOwnerSig(asm); sovSplitConserve(asm); sovSplitOutputs(asm); sovDescent(asm); tokFinishBranch(asm)
}
function sovEmitMerge (asm) {
  sovExtractState(asm); sovRequireOwnerSig(asm); sovNewOwnerCheck(asm)
  sovMergeVector(asm); sovMergeSiblingBacktrace(asm); sovMergeConserve(asm); sovDescent(asm); tokFinishBranch(asm)
}

// ---- asset: conservation + ownership, divisible, with an atomic swap ----------
//
// owner(20) ‖ balance(8) — no genesis, so no authenticity; conservation (token)
// and ownership (titled) only. Four ops in a 4-way dispatch. The swap pins only
// ITS OWN output among a spender-supplied set, so two assets trade in one tx; each
// owner signs under SIGHASH_ALL, so signing IS consenting to the whole trade —
// atomicity for free, no cross-input logic.
function assetChunkFrom (asm, ownerName, balName, out) {
  asm.pick('header'); asm.pick(ownerName); asm.cat(out + '_ho')
  asm.pick(balName); asm.cat(out + '_hob'); asm.pick('tail'); asm.cat(out)
}
function assetTxOut (asm, chunkName, out) {
  asm.data(tokDustLE(), out + '_d'); asm.pick(chunkName); asm.cat(out)
}
function assetExtractState (asm) {
  tokReadField(asm, 'selfChunk', 'chunk')
  asm.sizeOf('chunk', 'chunkLen')
  asm.roll('chunk')
  asm.splitAt(TOK_HEAD, 'header', 'r1')
  asm.splitAt(PROV_OWNER, 'owner', 'r2')
  asm.splitAt(TOK_BAL, 'balance8', 'tail')
}
function assetStride (asm) { asm.pick('chunkLen'); asm.num(8, 'eight'); asm.add('stride') }
function assetRequireOwnerSig (asm) {
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('owner'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
}
function assetNewOwnerCheck (asm) {
  asm.pick('newOwner'); asm.size('noSz'); asm.num(PROV_OWNER, 'ob'); asm.equalVerify()
}
function assetTransferSuccessor (asm) {
  assetNewOwnerCheck(asm)
  assetChunkFrom(asm, 'newOwner', 'balance8', 'outChunk')
  assetTxOut(asm, 'outChunk', 'outTxOut')
  asm.hash256('outHash'); tokReadField(asm, 'hashOutputs', 'hashOutputs'); asm.equalVerify()
}
function assetSplitConserve (asm) {
  asm.pick('balA8'); asm.bin2num('aNum')
  asm.pick('balB8'); asm.bin2num('bNum'); asm.add('abNum')
  asm.pick('balance8'); asm.bin2num('ownNum'); asm.numEqualVerify()
}
function assetSplitOutputs (asm) {
  assetChunkFrom(asm, 'ownerA', 'balA8', 'chunkA'); assetTxOut(asm, 'chunkA', 'out0')
  assetChunkFrom(asm, 'ownerB', 'balB8', 'chunkB'); assetTxOut(asm, 'chunkB', 'out1')
  asm.pick('out0'); asm.pick('out1'); asm.cat('outs'); asm.hash256('outsHash')
  tokReadField(asm, 'hashOutputs', 'hashOutputs'); asm.equalVerify()
}
function assetMergeConserve (asm) {
  asm.pick('balance8'); asm.bin2num('ownNum')
  asm.pick('sibBal8'); asm.bin2num('sibNum'); asm.add('outNum'); asm.num2bin(TOK_BAL, 'balanceOut8')
  assetChunkFrom(asm, 'newOwner', 'balanceOut8', 'outChunk')
  assetChunkFrom(asm, 'sibOwner', 'sibBal8', 'sibChunk')
}
function assetMergeVector (asm) {
  tokReadField(asm, 'ownOutpoint', 'ownOutpoint')
  asm.pick('sibling'); asm.splitAt(32, 'txidB', 'vout4'); asm.bin2num('voutNum')
  asm.pick('ownOutpoint'); asm.pick('sibling'); asm.cat('vA'); asm.hash256('hvA')
  tokReadField(asm, 'hashPrevouts', 'hpA'); asm.equal('eqA')
  asm.pick('sibling'); asm.pick('ownOutpoint'); asm.cat('vB'); asm.hash256('hvB')
  tokReadField(asm, 'hashPrevouts', 'hpB'); asm.equal('eqB')
  asm.raw(Opcode.OP_BOOLOR, 2, ['vecOk']); asm.verify()
}
function assetMergeSibSlice (asm) {
  asm.sizeOf('outsBlob', 'outsSize')
  asm.pick('outsSize'); asm.pick('stride'); asm.div('count')
  asm.pick('count'); asm.pick('stride'); asm.mul('cs'); asm.pick('outsSize'); asm.numEqualVerify()
  asm.pick('count'); asm.num(1, 'one1'); asm.geVerify()
  asm.pick('count'); asm.num(2, 'two2'); asm.leVerify()
  asm.pick('count'); asm.num2bin(1, 'countByte')
  asm.pick('voutNum'); asm.pick('stride'); asm.mul('offset')
  asm.pick('outsBlob'); asm.pick('offset'); asm.split('pre', 'rest')
  asm.pick('stride'); asm.split('sibSlice', 'post')
  asm.drop(); asm.nip()
  assetTxOut(asm, 'sibChunk', 'expectedSib'); asm.equalVerify()
}
function assetVerifyFunding (asm) {
  asm.data(TOK_VERSION, 'ver'); asm.pick('iblob'); asm.cat('vi')
  asm.pick('countByte'); asm.cat('vic'); asm.pick('outsBlob'); asm.cat('vico')
  asm.pick('lt4'); asm.size('ltsz'); asm.num(4, 'four'); asm.equalVerify(); asm.cat('funding')
  asm.hash256('fhash'); asm.pick('txidB'); asm.equalVerify()
}
function assetBindMergeOutput (asm) {
  assetTxOut(asm, 'outChunk', 'outTxOut'); asm.hash256('outHash')
  tokReadField(asm, 'hashOutputs', 'hashOutputs'); asm.equalVerify()
}
function assetSwapPin (asm) {                            // pin my own output in the swap set
  assetNewOwnerCheck(asm)
  asm.sizeOf('outsBlob', 'outsSize')
  asm.pick('outsSize'); asm.pick('stride'); asm.div('count')
  asm.pick('count'); asm.pick('stride'); asm.mul('cs'); asm.pick('outsSize'); asm.numEqualVerify()
  assetChunkFrom(asm, 'newOwner', 'balance8', 'myChunk')
  assetTxOut(asm, 'myChunk', 'myOut')
  asm.pick('myIndex'); asm.pick('stride'); asm.mul('offset')
  asm.pick('outsBlob'); asm.pick('offset'); asm.split('pre', 'rest')
  asm.pick('stride'); asm.split('slice', 'post')
  asm.drop(); asm.nip()
  asm.pick('myOut'); asm.equalVerify()
  asm.pick('outsBlob'); asm.hash256('oh')
  tokReadField(asm, 'hashOutputs', 'hashOutputs'); asm.equalVerify()
}
function assetEmitTransfer (asm) {
  assetExtractState(asm); assetRequireOwnerSig(asm); assetTransferSuccessor(asm); tokFinishBranch(asm)
}
function assetEmitSplit (asm) {
  assetExtractState(asm); assetRequireOwnerSig(asm); assetSplitConserve(asm); assetSplitOutputs(asm); tokFinishBranch(asm)
}
function assetEmitMerge (asm) {
  assetExtractState(asm); assetStride(asm); assetRequireOwnerSig(asm)
  assetMergeConserve(asm); assetMergeVector(asm); assetMergeSibSlice(asm); assetVerifyFunding(asm); assetBindMergeOutput(asm); tokFinishBranch(asm)
}
function assetEmitSwap (asm) {
  assetExtractState(asm); assetStride(asm); assetRequireOwnerSig(asm); assetSwapPin(asm); tokFinishBranch(asm)
}

// lifecycle — a status state machine. Two branches, each issuer-signed, the preimage kept
// on the MAIN stack (the finish drops it — no altstack parking). transition moves the status
// along an allowed pair and splices the immutable core (genesis, issuer) into the successor;
// retire is the exit. Shared verbatim with src/predicates/lifecycle.js so the two cannot drift.
const LIFE_GEN = 32
const LIFE_STATUS = 1
const LIFE_ISSUER = 20
const LIFE_HEAD = 4
const LIFE_P2PKH_PRE = Buffer.from('1976a914', 'hex')
const LIFE_P2PKH_POST = Buffer.from('88ac', 'hex')
function lifeTransKey (old, next) { return Buffer.from([old, next]) }

function lifeReadState (asm) {
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(LIFE_HEAD, 'header', 'r1')
  asm.splitAt(LIFE_GEN, 'genesis', 'r2')
  asm.splitAt(LIFE_STATUS, 'status1', 'r3')
  asm.splitAt(LIFE_ISSUER, 'issuer', 'tail')
}
function lifeRequireIssuerSig (asm) {
  asm.pick('pubkey'); asm.hash160('pkh'); asm.pick('issuer'); asm.equalVerify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
}
function lifeFinish (asm) {
  while (asm.main.length) asm.drop()
  asm.raw(Opcode.OP_1, 0, ['ok'])
}
function lifecycleTransition (asm, { transitions, fee }) {
  lifeReadState(asm)
  lifeRequireIssuerSig(asm)
  // move = old ‖ new; its first byte must equal the object's REAL status (so no move out of
  // a state the object is not in — this is what makes a terminal state unspendable).
  asm.pick('move'); asm.splitAt(1, 'moveOld', 'moveNew')
  asm.pick('moveOld'); asm.pick('status1'); asm.equalVerify()
  asm.pick('move'); asm.data(lifeTransKey(transitions[0][0], transitions[0][1]), 'k0'); asm.equal('acc')
  for (let i = 1; i < transitions.length; i++) {
    asm.pick('move'); asm.data(lifeTransKey(transitions[i][0], transitions[i][1]), 'k' + i); asm.equal('ei')
    asm.raw(Opcode.OP_BOOLOR, 2, ['acc'])
  }
  asm.verify()
  // successor: genesis and issuer UNCHANGED, status -> moveNew
  asm.pick('genesis'); asm.pick('moveNew'); asm.cat('gn'); asm.pick('issuer'); asm.cat('newState')
  asm.pick('header'); asm.pick('newState'); asm.cat('hn'); asm.pick('tail'); asm.cat('newChunk')
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('nextOutput')
  asm.bindOutput('nextOutput')
  lifeFinish(asm)
}
function lifecycleRetire (asm, { fee }) {
  lifeReadState(asm)
  lifeRequireIssuerSig(asm)
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.data(LIFE_P2PKH_PRE, 'pre'); asm.pick('issuer'); asm.cat('ik1'); asm.data(LIFE_P2PKH_POST, 'post'); asm.cat('issuerChunk')
  asm.cat('retireOutput')
  asm.bindOutput('retireOutput')
  lifeFinish(asm)
}

// turns — a two-player turn-based game. move: the player whose turn it is signs, sets a new
// 32-byte game state, flips the turn, recreates the coin; settle: both players sign and the
// pot goes to a named winner. Same MAIN-stack, drop-finish shape as lifecycle; shared
// verbatim with src/predicates/turns.js (the P2PKH constants and finish are reused).
const TURN_A = 20
const TURN_B = 20
const TURN_T = 1
const TURN_G = 32
const TURN_HEAD = 4
function turnsReadState (asm) {
  asm.clause(C.selfChunk, 0, ['chunk'])
  asm.splitAt(TURN_HEAD, 'header', 'r1')
  asm.splitAt(TURN_A, 'a', 'r2')
  asm.splitAt(TURN_B, 'b', 'r3')
  asm.splitAt(TURN_T, 'turn', 'r4')
  asm.splitAt(TURN_G, 'gstate', 'tail')
}
function turnsMove (asm, { fee }) {
  turnsReadState(asm)
  // the signer must be the player whose turn it is: (pkh==a ∧ turn==0) ∨ (pkh==b ∧ turn==1)
  asm.pick('pubkey'); asm.hash160('spkh')
  asm.pick('turn'); asm.bin2num('turnNum')
  asm.pick('spkh'); asm.pick('a'); asm.equal('isA')
  asm.pick('turnNum'); asm.num(0, 'z'); asm.numEqual('t0'); asm.raw(Opcode.OP_BOOLAND, 2, ['e1'])
  asm.pick('spkh'); asm.pick('b'); asm.equal('isB')
  asm.pick('turnNum'); asm.num(1, 'one'); asm.numEqual('t1'); asm.raw(Opcode.OP_BOOLAND, 2, ['e2'])
  asm.raw(Opcode.OP_BOOLOR, 2, ['authOk']); asm.verify()
  asm.pick('sig'); asm.pick('pubkey'); asm.checkSigVerify()
  // the next game state is spender-chosen, exactly 32 bytes
  asm.pick('newState'); asm.size('nsz'); asm.num(TURN_G, 'gb'); asm.equalVerify()
  // the turn flips: newTurn = 1 - turnNum, one byte
  asm.num(1, 'one2'); asm.pick('turnNum'); asm.sub('ntn'); asm.num2bin(TURN_T, 'newTurn')
  // successor: a ‖ b unchanged, turn flipped, new game state; everything else identical
  asm.pick('header'); asm.pick('a'); asm.cat('h1'); asm.pick('b'); asm.cat('h2')
  asm.pick('newTurn'); asm.cat('h3'); asm.pick('newState'); asm.cat('h4'); asm.pick('tail'); asm.cat('newChunk')
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.pick('newChunk'); asm.cat('moveOut')
  asm.bindOutput('moveOut')
  lifeFinish(asm)
}
function turnsSettle (asm, { fee }) {
  turnsReadState(asm)
  asm.pick('pubA'); asm.hash160('apkh'); asm.pick('a'); asm.equalVerify(); asm.pick('sigA'); asm.pick('pubA'); asm.checkSigVerify()
  asm.pick('pubB'); asm.hash160('bpkh'); asm.pick('b'); asm.equalVerify(); asm.pick('sigB'); asm.pick('pubB'); asm.checkSigVerify()
  asm.pick('winner'); asm.size('wsz'); asm.num(20, 'w20'); asm.equalVerify()
  asm.pick('preimage', 'pv'); asm.clause((x) => C.newValueLE(x, fee), 1, ['newValue8'])
  asm.data(LIFE_P2PKH_PRE, 'pre'); asm.pick('winner'); asm.cat('wk'); asm.data(LIFE_P2PKH_POST, 'post'); asm.cat('wchunk')
  asm.cat('settleOut')
  asm.bindOutput('settleOut')
  lifeFinish(asm)
}

module.exports = {
  lifecycleTransition, lifecycleRetire,
  turnsMove, turnsSettle,
  meteredReadCounterKeep, meteredReadCounterDrop, meteredGuardBelow, meteredGuardAtLeast,
  meteredIncrementRecreate, meteredPayFixed,
  vestingWithdraw, vestingFinish, beneficiaryChunk,
  vestGate, vestReadValueParkChunk, vestReadValueOnly, vestComputeUnvested,
  vestGuardVesting, vestGuardVested, vestPayWithdraw, vestPayFinish,
  // token: merge (backtrace) and split
  tokEmitMerge, tokEmitSplit,
  tokMergeReadSelf, tokMergeConserve, tokVerifySiblingVector, tokVerifySibSlice, tokVerifyFunding, tokBindMergeOutput, tokFinishBranch,
  tokSplitReadSelf, tokSplitConserve, tokBindSplitOutputs,
  // lineage: authenticity by descent
  linEmit, linReadSelf, linSuccessor, descentReadParent, linGenesisOrParent,
  // provenance: authenticity + ownership
  provEmit, provReadSelf, provAuthorise, provSuccessor, provGenesisOrParent,
  // sovereign: conservation + ownership + authenticity, divisible
  sovEmitTransfer, sovEmitSplit, sovEmitMerge,
  sovExtractState, sovRequireOwnerSig, sovDescent,
  sovTransferSuccessor, sovSplitConserve, sovSplitOutputs,
  sovNewOwnerCheck, sovMergeVector, sovMergeSiblingBacktrace, sovMergeConserve,
  // asset: conservation + ownership, divisible, with atomic swap
  assetEmitTransfer, assetEmitSplit, assetEmitMerge, assetEmitSwap,
  assetExtractState, assetStride, assetRequireOwnerSig,
  assetTransferSuccessor, assetSplitConserve, assetSplitOutputs,
  assetMergeConserve, assetMergeVector, assetMergeSibSlice, assetVerifyFunding, assetBindMergeOutput,
  assetSwapPin
}
