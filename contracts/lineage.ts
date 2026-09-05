// lineage — an authenticity covenant: every coin carries its GENESIS outpoint in state, and
// each spend proves unbroken descent from that unique genesis (its funding tx either spent
// the genesis outpoint directly, or spent a parent of the same genesis). A single-path
// @body('asm') covenant behind an authenticate preamble, self-terminating. Byte-identical to
// the deployed src/predicates/lineage.js.
@contract('lineage')
@preamble('authenticate')
@body('asm')
class Lineage {
  genesis: bytes36

  @given('raw1, iblob2, lt2, preimage')
  @selfTerminating
  spend() {
    linReadSelf()
    linSuccessor()
    descentReadParent()
    linGenesisOrParent()
    finishBranch()
  }
}
