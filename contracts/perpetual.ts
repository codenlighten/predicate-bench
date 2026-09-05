// A self-recreating covenant: every spend must recreate this exact script, minus a fee.
@contract('perpetual')
@terminates('fee-exhaustion')
class Perpetual {
  spend() {
    authenticate()
    assertSighashAll()
    recreateSelfMinusFee(this.fee)
  }
}
