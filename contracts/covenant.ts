// A covenant: the spend must create exactly this committed output set.
@contract('covenant')
class Covenant {
  spend() {
    authenticate()
    requireOutputs(this.expected)
    finish()
  }
}
