// token — a conserved fungible token: its whole state is a balance, and it can be split
// into two coins or merged with an authenticated sibling, value preserved on both paths.
// A two-method @branch('asm') class — each side inherits its own @given unlocking stack and
// is @selfTerminating (it ends in its own finish step, so no clean-stack epilogue is added).
// Compiles byte-identical to the deployed src/predicates/token.js.
@contract('token')
@branch('asm')
class Token {
  balance: u64

  // merge: fold an authenticated sibling's balance into this coin, conserving the total.
  @given('lt4, iblob, outsBlob, sibBal8, sibling, preimage')
  @selfTerminating
  merge() {
    tokMergeReadSelf()
    tokMergeConserve()
    tokVerifySiblingVector()
    tokVerifySibSlice()
    tokVerifyFunding()
    tokBindMergeOutput()
    finishBranch()
  }

  // split: divide this coin's balance across two successor coins, conserving the total.
  @given('balA8, balB8, preimage')
  @selfTerminating
  split() {
    tokSplitReadSelf()
    tokSplitConserve()
    tokBindSplitOutputs()
    finishBranch()
  }
}
