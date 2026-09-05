// lifecycle — a status STATE MACHINE with a constitution: an immutable core (genesis id,
// issuer) and a status that may move only along an allowed-transition set, each move
// issuer-signed; a terminal status has no outgoing move and is unspendable; retire is the
// exit. A two-method @branch('asm') class — each side inherits its own @given unlocking
// stack and is @selfTerminating (it ends in its own finish, so no clean-stack epilogue is
// added). Compiles byte-identical to the deployed src/predicates/lifecycle.js.
@contract('lifecycle')
@branch('asm')
class Lifecycle {
  // state layout: the immutable genesis id, the current status, the issuer — encoded in order.
  genesis: bytes32
  status: u8
  issuer: hash160

  // transition: move status old -> new along an allowed pair (the move's first byte must
  // equal the real current status), splice the immutable core into the successor, issuer signs.
  @given('pubkey, sig, move, preimage')
  @selfTerminating
  transition() {
    lifecycleTransition({ transitions: this.transitions, fee: this.fee })
  }

  // retire: the issuer sweeps the remainder and stops.
  @given('pubkey, sig, preimage')
  @selfTerminating
  retire() {
    lifecycleRetire({ fee: this.fee })
  }
}
