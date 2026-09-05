'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const { StackAsm } = require('../stackasm')
const covsteps = require('../covsteps')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// The three mechanisms in one covenant — CONSERVATION, OWNERSHIP and
// AUTHENTICITY — for a fully DIVISIBLE token. A `sovereign` carries
// `genesis ‖ owner ‖ balance` and offers three operations, each running all
// three checks side by side:
//
//   transfer  1 -> 1, new owner, balance carried
//   split     1 -> 2, balance divided, an owner for each half
//   merge     2 -> 1, balances summed, both owners sign
//
//   authorise      HASH160(pubkey) == owner, OP_CHECKSIGVERIFY the owner's sig  (titled)
//   conserve       split: x+y == balance;  merge: out == a+b                    (token)
//   prove descent  the immediate parent was a sovereign of the same genesis     (lineage)
//
// Split makes the descent MULTI-OUTPUT, and that is the whole difficulty. A split
// produces a two-output transaction, so the child of a split has a two-output
// parent funding; the descent backtrace must reconstruct the parent's whole output
// section and pin the parent's slice by vout — exactly `token`'s multi-output
// backtrace, now checking the slice is a sovereign of my genesis. And the genesis
// case (the mint spent G directly) must be an alternative to the parent backtrace,
// which needs a real OP_IF/OP_ELSE the stack assembler now models.
//
// Soundness is inductive: a token is spendable only if its funding transaction is
// a real, network-validated one, which already ran its parent's covenant — so
// re-proving one hop suffices, back to the single spend of the genesis outpoint.
// A counterfeit (sovereign bytes from a plain UTXO) can be neither transferred,
// split nor merged: every branch re-checks descent.
//
// Proves CONSERVATION, AUTHORISATION and AUTHENTICITY together, over the full
// mint -> split -> merge lifecycle.

const G_BYTES = 36
const OWNER_BYTES = 20
const BAL_BYTES = 8
const STATE_BYTES = G_BYTES + OWNER_BYTES + BAL_BYTES   // 64, push-op 0x40
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1
const PREFIX_BYTES = 8 + HEAD_BYTES + G_BYTES           // dust ‖ head ‖ genesis, before the owner
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')
const TRANSFER = 0
const SPLIT = 1
const MERGE = 2

function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
function balanceLE (v) { const b = Buffer.alloc(BAL_BYTES); b.writeUIntLE(v, 0, 6); return b }
function dustLE () { const b = Buffer.alloc(8); b.writeUIntLE(DUST, 0, 6); return b }
function varint (len) {
  if (len < 253) return Buffer.from([len])
  const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(len, 1); return b
}
function genesisOutpoint (displayTxid, vout) {
  const txid = Buffer.from(displayTxid, 'hex'); txid.reverse()
  const v = Buffer.alloc(4); v.writeUInt32LE(vout, 0)
  return Buffer.concat([txid, v])
}
function state (genesis, owner, balance) {
  const g = Buffer.isBuffer(genesis) ? genesis : Buffer.from(genesis, 'hex')
  return Buffer.concat([g, hash160Of(owner), balanceLE(balance)])
}

function buildScript ({ genesis, owner, balance }) {
  const s = new Script()
  s.add(state(genesis, owner, balance)).add(Opcode.OP_DROP)

  // The three branch bodies live in src/covsteps.js (sovEmitMerge/Split/Transfer),
  // shared with the compiler so the spec and the predicate cannot drift.
  C.authenticate(s)
  s.add(Opcode.OP_TOALTSTACK)
  s.add(Opcode.OP_DUP).add(n(MERGE)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  covsteps.sovEmitMerge(new StackAsm(s)
    .given(['sibIblob', 'sibLt', 'sibOutsBlob', 'sibVout', 'sibling', 'raw1', 'iblob2', 'lt2',
      'parentOutsBlob', 'newOwner', 'sig', 'pubkey']).seedAlt(['preimage']))
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DUP).add(n(SPLIT)).add(Opcode.OP_EQUAL).add(Opcode.OP_IF)
  s.add(Opcode.OP_DROP)
  covsteps.sovEmitSplit(new StackAsm(s)
    .given(['raw1', 'iblob2', 'lt2', 'parentOutsBlob', 'ownerA', 'ownerB', 'balA8', 'balB8', 'sig', 'pubkey'])
    .seedAlt(['preimage']))
  s.add(Opcode.OP_ELSE)
  s.add(Opcode.OP_DROP)
  covsteps.sovEmitTransfer(new StackAsm(s)
    .given(['raw1', 'iblob2', 'lt2', 'parentOutsBlob', 'newOwner', 'sig', 'pubkey'])
    .seedAlt(['preimage']))
  s.add(Opcode.OP_ENDIF)
  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- scenario construction ----

/** The output section (outsBlob) for sovereign outputs of these records. */
function outsBlobFor (recs) {
  return Buffer.concat(recs.map(r => {
    const b = buildScript(r).toBuffer()
    return Buffer.concat([dustLE(), varint(b.length), b])
  }))
}
function oneInput (prevInternal, vout, outRecs) {
  const display = Buffer.from(prevInternal); display.reverse()
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: display, outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), 5000)
  for (const r of outRecs) tx.addOutput(new bsv.Transaction.Output({ script: buildScript(r), satoshis: DUST }))
  return tx
}
/** Decompose a funding tx (any number of sovereign outputs) for a backtrace. */
function decompose (raw, recs) {
  const outsBlob = outsBlobFor(recs)
  const lt4 = raw.slice(raw.length - 4)
  const iblob = raw.slice(4, raw.length - (1 + outsBlob.length + 4))
  const reassembled = Buffer.concat([raw.slice(0, 4), iblob, Buffer.from([recs.length]), outsBlob, lt4])
  if (!reassembled.equals(raw)) throw new Error('sovereign funding reassembly mismatch')
  return { iblob, lt4, outsBlob, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}

const OWNERS = [1, 2, 3, 4, 5].map(i => bsv.PrivateKey.fromBuffer(Buffer.alloc(32, i)))
const addr = (k) => k.toAddress().toString()

/**
 * Builds a token to spend and the witnesses for it. Kinds:
 *   'genesis'      spend the mint's token; parent is G
 *   'grandchild'   spend a token whose parent was a SPLIT child (multi-output descent)
 *   'split'        spend the mint's token, splitting it (genesis descent, 2 outputs)
 *   'merge'        spend a split child, merged with its sibling
 *   'counterfeit'  spend sovereign bytes minted from a plain UTXO
 */
function scenario (kind, genesis, balance, a, b) {
  const rec = (owner, bal) => ({ genesis, owner: addr(owner), balance: bal })
  const gTxid = genesis.slice(0, 32); const gVout = genesis.readUInt32LE(32)
  // mint: spend G -> token0 (owner 0, full balance)
  const total = balance || (a + b)
  const mintRecs = [rec(OWNERS[0], total)]
  const mint = oneInput(gTxid, gVout, mintRecs)
  const mintRaw = mint.toBuffer(); const mintId = bsv.crypto.Hash.sha256sha256(mintRaw)
  const dMint = decompose(mintRaw, mintRecs)

  if (kind === 'genesis') {
    return { branch: 'transfer', raw1: mintRaw, iblob2: dMint.iblob, lt2: dMint.lt4, parentOutsBlob: dMint.outsBlob,
      tokenTxidInternal: mintId, tokenVout: 0, ownerKey: OWNERS[0], newOwner: addr(OWNERS[1]), lockRec: rec(OWNERS[0], total) }
  }
  if (kind === 'split') {
    return { branch: 'split', raw1: mintRaw, iblob2: dMint.iblob, lt2: dMint.lt4, parentOutsBlob: dMint.outsBlob,
      tokenTxidInternal: mintId, tokenVout: 0, ownerKey: OWNERS[0], lockRec: rec(OWNERS[0], total),
      ownerA: addr(OWNERS[1]), ownerB: addr(OWNERS[2]), splitA: a, splitB: b }
  }

  // split the mint token -> [tokenA(owner1, a), tokenB(owner2, b)]
  const splitRecs = [rec(OWNERS[1], a), rec(OWNERS[2], b)]
  const split = oneInput(mintId, 0, splitRecs)
  const splitRaw = split.toBuffer(); const splitId = bsv.crypto.Hash.sha256sha256(splitRaw)
  const dSplit = decompose(splitRaw, splitRecs)

  if (kind === 'merge') {
    // input 0 = tokenA (split child @0), sibling = tokenB (split child @1)
    // tokenA's parent is the mint token (mint funding, single-output)
    // input 0 = tokenA (split@0): its parent is the mint token, funded by the
    // single-output mint. sibling = tokenB (split@1): its funding is the split.
    return { branch: 'merge', raw1: splitRaw, iblob2: dMint.iblob, lt2: dMint.lt4, parentOutsBlob: dMint.outsBlob,
      tokenTxidInternal: splitId, tokenVout: 0, ownerKey: OWNERS[1], newOwner: addr(OWNERS[1]), lockRec: rec(OWNERS[1], a),
      sibIblob: dSplit.iblob, sibLt: dSplit.lt4, sibOutsBlob: dSplit.outsBlob, sibVout: 1, sibTxidInternal: splitId, a, b }
  }

  if (kind === 'grandchild') {
    // transfer tokenA (split child @0) -> tokenC (owner 3). tokenC's parent is
    // tokenA, whose funding is the SPLIT (two-output) -> multi-output descent.
    const tc = oneInput(splitId, 0, [rec(OWNERS[3], a)])
    const tcRaw = tc.toBuffer(); const tcId = bsv.crypto.Hash.sha256sha256(tcRaw)
    return { branch: 'transfer', raw1: tcRaw, iblob2: dSplit.iblob, lt2: dSplit.lt4, parentOutsBlob: dSplit.outsBlob,
      tokenTxidInternal: tcId, tokenVout: 0, ownerKey: OWNERS[3], newOwner: addr(OWNERS[4]), lockRec: rec(OWNERS[3], a) }
  }

  // counterfeit: sovereign bytes from a plain UTXO
  const plain = oneInput(Buffer.alloc(32, 7), 0, [])
  plain.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bsv.PrivateKey.fromRandom().toAddress()), satoshis: DUST }))
  const plainRaw = plain.toBuffer(); const plainId = bsv.crypto.Hash.sha256sha256(plainRaw)
  const countRecs = [rec(OWNERS[0], total)]
  const count = oneInput(plainId, 0, countRecs)
  const countRaw = count.toBuffer(); const countId = bsv.crypto.Hash.sha256sha256(countRaw)

  return { branch: 'transfer', raw1: countRaw, iblob2: dMint.iblob, lt2: dMint.lt4, parentOutsBlob: dMint.outsBlob,
    tokenTxidInternal: countId, tokenVout: 0, ownerKey: OWNERS[0], newOwner: addr(OWNERS[1]), lockRec: rec(OWNERS[0], total) }
}

const EXAMPLE_GENESIS = genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)

function scn (tc) {
  if (tc._scn) return tc._scn
  tc._scn = scenario(tc.kind || 'genesis', tc.genesis, tc.balance, tc.a, tc.b)
  return tc._scn
}

module.exports = {
  name: 'sovereign',
  describe: 'a divisible token that is conserved, owned AND provably authentic — transfer, split, merge',
  example: () => ({ genesis: EXAMPLE_GENESIS, balance: 500, kind: 'genesis' }),
  G_BYTES,
  DUST,
  buildScript,
  genesisOutpoint,
  hash160Of,
  balanceLE,
  decompose,
  outsBlobFor,
  scenario,

  lock (tc) {
    if (!tc.genesis) throw new Error('genesis is required')
    if (tc.kind) return buildScript(scn(tc).lockRec)
    if (!tc.owner || !tc.balance) throw new Error('owner and balance are required')
    return buildScript({ genesis: tc.genesis, owner: tc.owner, balance: tc.balance })
  },

  spendOutpoint (tc) {
    const sc = scn(tc)
    const display = Buffer.from(sc.tokenTxidInternal); display.reverse()
    return { prevTxId: display, prevVout: sc.tokenVout }
  },

  siblings (tc) {
    const sc = scn(tc)
    if (sc.branch !== 'merge') return undefined
    const display = Buffer.from(sc.sibTxidInternal); display.reverse()
    return [{ prevTxId: display, outputIndex: sc.sibVout, satoshis: DUST }]
  },

  outputs (tc) {
    const sc = scn(tc)
    if (sc.branch === 'split') {
      return [
        { owner: bsv.Address.fromPublicKeyHash(hash160Of(tc.actualOwnerA ?? sc.ownerA)).toString(), balance: tc.actualSplitA ?? sc.splitA },
        { owner: bsv.Address.fromPublicKeyHash(hash160Of(sc.ownerB)).toString(), balance: sc.splitB }
      ].map(r => new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis, ...r }), satoshis: DUST }))
    }
    if (sc.branch === 'merge') {
      const outBal = tc.actualOutBalance ?? (sc.a + sc.b)
      return [new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis, owner: bsv.Address.fromPublicKeyHash(hash160Of(sc.newOwner)).toString(), balance: outBal }), satoshis: DUST })]
    }
    return [new bsv.Transaction.Output({ script: buildScript({ genesis: tc.genesis, owner: bsv.Address.fromPublicKeyHash(hash160Of(tc.actualNewOwner ?? sc.newOwner)).toString(), balance: tc.actualBalance ?? sc.lockRec.balance }), satoshis: DUST })]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ?? (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sc = scn(tc)
    const signer = tc.signWith || sc.ownerKey
    const nOwner = sc.newOwner ? hash160Of(tc.wrongNewOwner ?? sc.newOwner) : null   // split has no single new owner

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      const sig = bsv.Transaction.Sighash.sign(tx, signer, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const pub = signer.publicKey.toBuffer()
      const s = new Script()
      if (sc.branch === 'merge') {
        const sibling36 = Buffer.concat([sc.sibTxidInternal, (() => { const v = Buffer.alloc(4); v.writeUInt32LE(sc.sibVout, 0); return v })()])
        ;[sc.sibIblob, sc.sibLt, sc.sibOutsBlob, n(sc.sibVout), sibling36,
          sc.raw1, sc.iblob2, sc.lt2, sc.parentOutsBlob, nOwner, sig, pub].forEach(x => s.add(x))
        return s.add(n(MERGE)).add(preimage)
      }
      if (sc.branch === 'split') {
        ;[sc.raw1, sc.iblob2, sc.lt2, sc.parentOutsBlob, hash160Of(sc.ownerA), hash160Of(sc.ownerB),
          balanceLE(sc.splitA), balanceLE(sc.splitB), sig, pub].forEach(x => s.add(x))
        return s.add(n(SPLIT)).add(preimage)
      }
      ;[sc.raw1, sc.iblob2, sc.lt2, sc.parentOutsBlob, nOwner, sig, pub].forEach(x => s.add(x))
      return s.add(n(TRANSFER)).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
