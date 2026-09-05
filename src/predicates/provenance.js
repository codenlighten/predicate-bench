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

// A PROVENANCE token — the composition of authenticity and ownership. It carries
// its genesis outpoint (immutable, proving descent, as in `lineage`) AND a
// current owner (mutable, spliced on transfer and gated by the owner's signature,
// as in `titled`). It transfers 1 -> 1, the balance-less analogue of an NFT with
// verifiable lineage.
//
// Every spend does two independent things:
//   - AUTHORISE: read the owner out of scriptCode, require HASH160(pubkey) to
//     equal it, OP_CHECKSIGVERIFY the owner's signature (`titled`);
//   - PROVE DESCENT: show the immediate parent was a provenance token of the same
//     genesis, by rebuilding the parent's single-output funding tx and hashing it
//     to the parent's txid — genesis case (the mint spent G) or parent case, by
//     induction back to genesis (`lineage`).
//
// The one new wrinkle over `lineage`: the owner changes each hop, so the parent's
// output is NOT a copy of mine. The parent's owner is supplied by the spender and
// pinned by the descent hash — a lie about it changes the rebuilt parent tx and
// misses the txid. The genesis and the logic are shared and taken from my own
// chunk, so a parent of a DIFFERENT genesis also misses.
//
// Proves AUTHENTICITY and AUTHORISATION. Balance/conservation is out of scope
// (that is `token`/`asset`); this isolates lineage + ownership.

const G_BYTES = 36                       // genesis outpoint: txid(32 internal) ‖ vout(4 LE)
const OWNER_BYTES = 20
const STATE_BYTES = G_BYTES + OWNER_BYTES          // genesis ‖ owner, one push (0x38)
const VARINT_BYTES = 3
const HEAD_BYTES = VARINT_BYTES + 1                // varint ‖ push-op ‖ state ‖ tail
const DUST = 2000
const VERSION = Buffer.from('01000000', 'hex')

function hash160Of (a) {
  if (Buffer.isBuffer(a)) return a
  return (typeof a === 'string' ? bsv.Address.fromString(a) : a).hashBuffer
}
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
function state (genesis, owner) {
  const g = Buffer.isBuffer(genesis) ? genesis : Buffer.from(genesis, 'hex')
  return Buffer.concat([g, hash160Of(owner)])
}

function buildScript ({ genesis, owner }) {
  const s = new Script()
  s.add(state(genesis, owner)).add(Opcode.OP_DROP)      // state: genesis ‖ owner

  // The composition — authorise (owner signed), bind the successor to the new
  // owner and same genesis, and prove descent — lives in src/covsteps.js (provEmit),
  // shared with the compiler so the spec and the predicate cannot drift.
  C.authenticate(s)                                      // preimage proven, on top
  covsteps.provEmit(new StackAsm(s)
    .given(['raw1', 'iblob2', 'lt2', 'parentOwner', 'newOwner', 'sig', 'pubkey', 'preimage']))

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// ---- scenario construction ----

function decomposeFunding (raw, genesis, owner) {
  const scriptBuf = buildScript({ genesis, owner }).toBuffer()
  const chunk = Buffer.concat([varint(scriptBuf.length), scriptBuf])
  const txout = Buffer.concat([dustLE(), chunk])
  const lt4 = raw.slice(raw.length - 4)
  const iblob = raw.slice(4, raw.length - (1 + txout.length + 4))
  const reassembled = Buffer.concat([raw.slice(0, 4), iblob, Buffer.from([1]), txout, lt4])
  if (!reassembled.equals(raw)) throw new Error('provenance funding is not single-output (reassembly)')
  return { iblob, lt4, txidInternal: bsv.crypto.Hash.sha256sha256(raw) }
}

function oneToOne (prevInternal, vout, outScript) {
  const display = Buffer.from(prevInternal); display.reverse()
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: display, outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), new bsv.Script().add(Opcode.OP_1), 5000)
  tx.addOutput(new bsv.Transaction.Output({ script: outScript, satoshis: DUST }))
  return tx
}

// deterministic owner chain for the scenarios
const OWNERS = [1, 2, 3, 4].map(i => bsv.PrivateKey.fromBuffer(Buffer.alloc(32, i)))

/**
 * Build one of four spends and return the harness/unlock inputs. Owners rotate
 * along the chain: token created at depth d is owned by OWNERS[d].
 *   'genesis'     — spend the mint's token (owner 0), transfer to owner 1
 *   'child'       — spend token1 (owner 1), transfer to owner 2
 *   'grandchild'  — spend token2 (owner 2), transfer to owner 3
 *   'counterfeit' — a raw provenance output (owner 0) minted from a plain UTXO
 */
function scenario (kind, genesis) {
  const scriptFor = (owner) => buildScript({ genesis, owner: owner.toAddress().toString() })
  const gTxidInternal = genesis.slice(0, 32)
  const gVout = genesis.readUInt32LE(32)

  // GEN: mint spends the genesis outpoint, creates token0 owned by OWNERS[0]
  const gen = oneToOne(gTxidInternal, gVout, scriptFor(OWNERS[0]))
  const genRaw = gen.toBuffer(); const genId = bsv.crypto.Hash.sha256sha256(genRaw)

  const owner0Hash = hash160Of(OWNERS[0].toAddress().toString())

  if (kind === 'genesis') {
    const dummy = decomposeFunding(genRaw, genesis, OWNERS[0].toAddress().toString())
    return { raw1: genRaw, iblob2: dummy.iblob, lt2: dummy.lt4, parentOwner: owner0Hash,
      tokenTxidInternal: genId, tokenVout: 0, ownerKey: OWNERS[0], newOwner: OWNERS[1].toAddress().toString() }
  }

  // token0 -> token1 (owner 0 signs, new owner 1)
  const spend0 = oneToOne(genId, 0, scriptFor(OWNERS[1]))
  const spend0Raw = spend0.toBuffer(); const spend0Id = bsv.crypto.Hash.sha256sha256(spend0Raw)

  if (kind === 'child') {
    const parent = decomposeFunding(genRaw, genesis, OWNERS[0].toAddress().toString())  // GEN funds token0(owner0)
    return { raw1: spend0Raw, iblob2: parent.iblob, lt2: parent.lt4, parentOwner: owner0Hash,
      tokenTxidInternal: spend0Id, tokenVout: 0, ownerKey: OWNERS[1], newOwner: OWNERS[2].toAddress().toString() }
  }

  // token1 -> token2 (owner 1 signs, new owner 2)
  const spend1 = oneToOne(spend0Id, 0, scriptFor(OWNERS[2]))
  const spend1Raw = spend1.toBuffer(); const spend1Id = bsv.crypto.Hash.sha256sha256(spend1Raw)

  if (kind === 'grandchild') {
    const parent = decomposeFunding(spend0Raw, genesis, OWNERS[1].toAddress().toString())  // SPEND0 funds token1(owner1)
    return { raw1: spend1Raw, iblob2: parent.iblob, lt2: parent.lt4, parentOwner: hash160Of(OWNERS[1].toAddress().toString()),
      tokenTxidInternal: spend1Id, tokenVout: 0, ownerKey: OWNERS[2], newOwner: OWNERS[3].toAddress().toString() }
  }

  // counterfeit: mint provenance bytes (owner 0) from a plain UTXO
  const plain = oneToOne(Buffer.alloc(32, 7), 0,
    bsv.Script.buildPublicKeyHashOut(bsv.PrivateKey.fromRandom().toAddress()))
  const plainRaw = plain.toBuffer(); const plainId = bsv.crypto.Hash.sha256sha256(plainRaw)
  const count = oneToOne(plainId, 0, scriptFor(OWNERS[0]))
  const countRaw = count.toBuffer(); const countId = bsv.crypto.Hash.sha256sha256(countRaw)
  const dummy = decomposeFunding(genRaw, genesis, OWNERS[0].toAddress().toString())
  return { raw1: countRaw, iblob2: dummy.iblob, lt2: dummy.lt4, parentOwner: owner0Hash,
    tokenTxidInternal: countId, tokenVout: 0, ownerKey: OWNERS[0], newOwner: OWNERS[1].toAddress().toString() }
}

const EXAMPLE_GENESIS = genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)

module.exports = {
  name: 'provenance',
  describe: 'an owned token that proves unbroken descent from its genesis on every transfer',
  example: () => ({ genesis: EXAMPLE_GENESIS, owner: OWNERS[0].toAddress().toString(), kind: 'genesis' }),
  G_BYTES,
  OWNER_BYTES,
  DUST,
  buildScript,
  genesisOutpoint,
  hash160Of,
  decomposeFunding,
  scenario,

  lock (tc) {
    if (!tc.genesis) throw new Error('genesis outpoint is required')
    // In a scenario the token being spent is owned by that hop's current owner;
    // outside one, an explicit owner (e.g. for a recorded deployment).
    if (tc.kind) {
      const sc = tc._scn || (tc._scn = scenario(tc.kind, tc.genesis))
      return buildScript({ genesis: tc.genesis, owner: sc.ownerKey.toAddress().toString() })
    }
    if (!tc.owner) throw new Error('owner is required')
    return buildScript({ genesis: tc.genesis, owner: tc.owner })
  },

  spendOutpoint (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc.kind || 'genesis', tc.genesis))
    const display = Buffer.from(sc.tokenTxidInternal); display.reverse()
    return { prevTxId: display, prevVout: sc.tokenVout }
  },

  outputs (tc) {
    const sc = tc._scn || (tc._scn = scenario(tc.kind || 'genesis', tc.genesis))
    return [new bsv.Transaction.Output({
      script: buildScript({ genesis: tc.genesis, owner: bsv.Address.fromPublicKeyHash(hash160Of(sc.newOwner)).toString() }),
      satoshis: DUST
    })]
  },

  unlock (tc) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType } = tc
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)
    const sc = tc._scn || (tc._scn = scenario(tc.kind || 'genesis', tc.genesis))

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, type)
      if (!PushTx.sFromPreimage(preimage)) continue
      // `signWith` lets a test sign as a non-owner; `wrongParentOwner` lets it
      // lie about the parent's owner in the descent proof.
      const signer = tc.signWith || sc.ownerKey
      const sig = bsv.Transaction.Sighash.sign(tx, signer, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)).toTxFormat()
      const parentOwner = tc.wrongParentOwner ? hash160Of(tc.wrongParentOwner) : hash160Of(sc.parentOwner)
      // [raw1, iblob2, lt2, parentOwner, newOwner, sig, pubkey, preimage]
      return new Script().add(sc.raw1).add(sc.iblob2).add(sc.lt2)
        .add(parentOwner).add(hash160Of(sc.newOwner))
        .add(sig).add(signer.publicKey.toBuffer()).add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
