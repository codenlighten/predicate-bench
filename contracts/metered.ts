// A hop counter that expires: while below the cap it advances (and recreates itself),
// once at the cap it settles to a fixed address. Two methods = a branch predicate.
@contract('metered')
@state('$state')
class Metered {
  advance() {
    readCounterKeep({ head: 4, counter: 4 })
    guardBelow(this.maxHops)
    incrementRecreate({ counter: 4, fee: this.hopFee })
  }
  expire() {
    readCounterDrop({ head: 4, counter: 4 })
    guardAtLeast(this.maxHops)
    payFixed(this.settle, this.hopFee)
  }
}
