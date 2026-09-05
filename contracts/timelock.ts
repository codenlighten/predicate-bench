// Not spendable before a floor: nLockTime >= floor, and the input must be non-final.
@contract('timelock')
class Timelock {
  spend() {
    authenticate()
    requireSequenceNonFinal()
    requireLockTimeAtLeast(this.notBefore)
    finish()
  }
}
