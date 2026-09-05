// turns — a two-player TURN-BASED GAME on chain: two players, whose turn it is, and a
// 32-byte game state. move: the player whose turn it is signs, sets the new game state, the
// turn flips, and the coin recreates itself; settle: both players sign and the pot goes to a
// named winner. A two-method @branch('asm') class — each side with its own @given unlocking
// stack and its own finish. Compiles byte-identical to the deployed src/predicates/turns.js.
@contract('turns')
@branch('asm')
class Turns {
  // state layout: the two players, whose turn it is (0 or 1), and the game state.
  a: hash160
  b: hash160
  turn: u8
  gstate: bytes32

  // move: only the player whose turn it is may act; the new game state is 32 bytes, the turn
  // flips, and everything immutable (both players) is spliced into the successor.
  @given('pubkey, sig, newState, preimage')
  @selfTerminating
  move() {
    turnsMove({ fee: this.fee })
  }

  // settle: both players sign, and the pot is paid to a named winner.
  @given('pubA, sigA, pubB, sigB, winner, preimage')
  @selfTerminating
  settle() {
    turnsSettle({ fee: this.fee })
  }
}
