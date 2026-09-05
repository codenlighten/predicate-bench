// asset — a four-way DISPATCH predicate: an owned, conserved token that can be
// transferred, split into two, merged with a sibling, or atomically swapped. A
// selector on the unlocking stack picks the case; each case authenticates the current
// owner and preserves value. This class compiles byte-identical to the deployed
// src/predicates/asset.js — the case order below is the on-chain dispatch order.
@contract('asset')
@dispatch
class Asset {
  // the state carried in the locking script — the compiler owns its offsets and encoding.
  owner: hash160
  balance: u64

  // swap: pin an owner-chosen counterpart output, leaving the rest of the tx free.
  @case(3) @given('outsBlob, myIndex, newOwner, sig, pubkey')
  swap() {
    assetExtractState()
    assetStride()
    assetRequireOwnerSig()
    assetSwapPin()
    finishBranch()
  }

  // merge: fold an authenticated sibling's balance into this one, conserving value.
  @case(2) @given('lt4, iblob, outsBlob, sibOwner, sibBal8, sibling, newOwner, sig, pubkey')
  merge() {
    assetExtractState()
    assetStride()
    assetRequireOwnerSig()
    assetMergeConserve()
    assetMergeVector()
    assetMergeSibSlice()
    assetVerifyFunding()
    assetBindMergeOutput()
    finishBranch()
  }

  // split: divide this coin's balance across two successors, conserving value.
  @case(1) @given('ownerA, ownerB, balA8, balB8, sig, pubkey')
  split() {
    assetExtractState()
    assetRequireOwnerSig()
    assetSplitConserve()
    assetSplitOutputs()
    finishBranch()
  }

  // transfer: reassign ownership to a single successor, balance unchanged.
  @case(0) @given('newOwner, sig, pubkey')
  transfer() {
    assetExtractState()
    assetRequireOwnerSig()
    assetTransferSuccessor()
    finishBranch()
  }
}
