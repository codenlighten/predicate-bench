// sovereign — a three-way DISPATCH predicate: a self-sovereign token (its genesis id
// carried in state) that transfers, splits, or merges, each move proving descent from
// an authenticated parent via a backtrace. Case order below is the on-chain dispatch
// order; compiles byte-identical to the deployed src/predicates/sovereign.js.
@contract('sovereign')
@dispatch
class Sovereign {
  // state layout: genesis id, current owner, balance — encoded by the compiler in order.
  genesis: bytes36
  owner: hash160
  balance: u64

  @case(2) @given('sibIblob, sibLt, sibOutsBlob, sibVout, sibling, raw1, iblob2, lt2, parentOutsBlob, newOwner, sig, pubkey')
  merge() {
    sovExtractState()
    sovRequireOwnerSig()
    sovNewOwnerCheck()
    sovMergeVector()
    sovMergeSiblingBacktrace()
    sovMergeConserve()
    sovDescent()
    finishBranch()
  }

  @case(1) @given('raw1, iblob2, lt2, parentOutsBlob, ownerA, ownerB, balA8, balB8, sig, pubkey')
  split() {
    sovExtractState()
    sovRequireOwnerSig()
    sovSplitConserve()
    sovSplitOutputs()
    sovDescent()
    finishBranch()
  }

  @case(0) @given('raw1, iblob2, lt2, parentOutsBlob, newOwner, sig, pubkey')
  transfer() {
    sovExtractState()
    sovRequireOwnerSig()
    sovTransferSuccessor()
    sovDescent()
    finishBranch()
  }
}
