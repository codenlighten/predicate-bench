'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const helpers = require('@smartledger/bsv/lib/covenant/helpers')
const C = require('../clauses')
const Script = bsv.Script
const Opcode = bsv.Opcode
const n = helpers.scriptNum

// An event ticket: capped resale, an enforced venue cut, and a one-way burn at
// the door.
//
//   resell   pay the seller at most maxPrice, pay the venue its share of that,
//            and hand the ticket on to a new owner
//   checkin  the owner destroys the ticket into OP_FALSE OP_RETURN
//
// Three things here are new to this bench, and one of them is a warning.
//
// **A spender-supplied number under a ceiling.** `royalty` derives its cut from
// the coin's own value, so there is nothing to cap. A resale price is a figure
// the seller picks, so the covenant has to take a number it cannot compute and
// bound it — `price <= maxPrice`, checked in script.
//
// **A free tail.** hashOutputs covers every output, so a covenant that fixes it
// exactly also forbids the buyer a change output (pitfall 17). The fix is to
// pin a PREFIX: the script builds outputs 0..2, concatenates a tail the spender
// supplies, and hashes the whole thing. The tail is unconstrained and safe —
// bytes that are not the transaction's real remaining outputs simply hash to
// something else and nothing spends.
//
// **And the warning.** The cap binds an on-chain output, not a price. A buyer
// can declare 10 satoshis, pay the venue its cut of 10 satoshis, and settle the
// other £400 by bank transfer. The covenant cannot see it, cannot price it, and
// signs off happily. There is a passing test below that does exactly that,
// named for what it is. This is the honest ceiling on "consensus-enforced
// market rules": Script binds what the transaction says, and a resale price is
// not something a transaction can be made to say.
const STATE_BYTES = 20                 // hash160 of the current holder
const VARINT_BYTES = 3                 // scripts of 253..65535
const HEAD_BYTES = VARINT_BYTES + 1    // varint + the 0x14 push opcode
const BPS_DENOMINATOR = 10000

// Shared covenant primitives — one implementation, in src/clauses.js.
const selfChunk = C.selfChunk
const hash160Of = C.hash160Of
const p2pkhChunk = C.p2pkhTxOutChunk
const requireOutputIs = C.requireOutputIs
const ownerFromChunk = (s) => C.fieldFromChunk(s, HEAD_BYTES, STATE_BYTES)

const P2PKH_PREFIX = Buffer.from('1976a914', 'hex')  // varint(25) OP_DUP OP_HASH160 push20
const P2PKH_SUFFIX = Buffer.from('88ac', 'hex')      // OP_EQUALVERIFY OP_CHECKSIG

function addressString (a) {
  if (typeof a === 'string') return a
  if (Buffer.isBuffer(a)) return bsv.Address.fromPublicKeyHash(a).toString()
  return a.toString()
}

/** What the covenant computes in script, so JS and script cannot disagree. */
function venueCutOn (price, bps) {
  return Math.floor(price * bps / BPS_DENOMINATOR)
}

/** An 8-byte little-endian satoshi amount — what a TxOut starts with. */
function amountLE (satoshis) {
  const b = Buffer.alloc(8)
  b.writeUIntLE(satoshis, 0, 6)
  return b
}

/**
 * The admission record: 32 bytes naming the event and the seat.
 *
 * It goes in the burn output, so the check-in is self-describing on chain — a
 * gate reading the transaction learns which seat was used without consulting
 * anything off-chain.
 */
function eventTag (event, seat) {
  return bsv.crypto.Hash.sha256(Buffer.from(`${event}|${seat}`, 'utf8'))
}

/** The whole burn TxOut, as a constant: zero satoshis, OP_FALSE OP_RETURN <tag>. */
function burnTxOut (event, seat) {
  const script = new Script()
    .add(Opcode.OP_FALSE).add(Opcode.OP_RETURN).add(eventTag(event, seat))
  return Buffer.concat([amountLE(0), C.txOutChunk(script)])
}

/** The recreated-ticket output's script, for a given holder. */
function ticketOutputScript (params, owner) {
  return buildScript({ ...params, owner })
}

function buildScript ({ owner, venue, event, seat, maxPrice, venueBps, ticketValue }) {
  const s = new Script()
  s.add(hash160Of(owner)).add(Opcode.OP_DROP)
  // One OP_PUSH_TX preamble above the split, not one per branch.
  C.authenticateThenBranch(s)

  // ---------------- resell ----------------
  // in: [tail, price, newOwner, sig, pubkey, preimage]
  //
  // The unlocking order is not arbitrary: items are pushed deepest-first in the
  // order they are LAST needed, so the branch never has to reach past two.

  selfChunk(s)                                   // [.., preimage, chunk]
  ownerFromChunk(s)                              // [.., preimage, chunk, owner]
  // The signer must be the holder named in our own bytes, not merely whoever
  // holds the UTXO. pubkey sits 3 deep with owner on top.
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_TOALTSTACK)                    // park chunk
  s.add(Opcode.OP_TOALTSTACK)                    // park preimage
  s.add(Opcode.OP_CHECKSIGVERIFY)                // consumes pubkey, sig
  s.add(Opcode.OP_FROMALTSTACK)                  // preimage
  s.add(Opcode.OP_FROMALTSTACK)                  // chunk

  // Splice the new holder into our own bytes, keeping the old one — the old
  // holder is the seller, and output 2 pays them.
  s.add(n(HEAD_BYTES)).add(Opcode.OP_SPLIT)      // [.., head, rest]
  s.add(n(STATE_BYTES)).add(Opcode.OP_SPLIT)     // [.., head, oldOwner, chunkTail]
  s.add(Opcode.OP_TOALTSTACK)                    // park chunkTail
  s.add(Opcode.OP_TOALTSTACK)                    // park oldOwner
  s.add(Opcode.OP_ROT)                           // [tail, price, preimage, head, newOwner]
  // A short or long holder field shifts every offset in the successor. The
  // malformed output would fail to match anyway; failing here says why.
  s.add(Opcode.OP_SIZE).add(n(STATE_BYTES)).add(Opcode.OP_EQUALVERIFY)
  s.add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK)                  // oldOwner, back onto the stack
  s.add(Opcode.OP_SWAP)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)  // [.., oldOwner, nextChunk]

  // Output 0: the ticket itself, always carrying the same fixed dust. Its value
  // is not a balance and must not drift, or a ticket could be drained by
  // reselling it to yourself.
  s.add(amountLE(ticketValue)).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  s.add(Opcode.OP_TOALTSTACK)                    // park out0
  s.add(Opcode.OP_TOALTSTACK)                    // park oldOwner  [pops: oldOwner, out0]
  s.add(Opcode.OP_SWAP)                          // [tail, preimage, price]

  // The ceiling. Everything this does and does not achieve is in the header.
  s.add(Opcode.OP_DUP).add(n(maxPrice))
    .add(Opcode.OP_LESSTHANOREQUAL).add(Opcode.OP_VERIFY)

  // The venue's share, truncating so the rounding favours the seller — and
  // refused if it rounds to nothing, because a ticket whose cut rounds away has
  // stopped being this instrument. It also puts a floor under the price.
  s.add(Opcode.OP_DUP).add(n(venueBps)).add(Opcode.OP_MUL)
    .add(n(BPS_DENOMINATOR)).add(Opcode.OP_DIV)
  s.add(Opcode.OP_DUP).add(n(1)).add(Opcode.OP_GREATERTHANOREQUAL).add(Opcode.OP_VERIFY)

  // Output 1: the venue's cut.
  s.add(n(8)).add(Opcode.OP_NUM2BIN)
  s.add(p2pkhChunk(venue)).add(Opcode.OP_CAT)    // [tail, preimage, price, out1]

  // Output 2: the seller's proceeds, to the holder named in the script we came
  // from — not to whoever the spender nominates.
  s.add(Opcode.OP_SWAP).add(n(8)).add(Opcode.OP_NUM2BIN)
  s.add(P2PKH_PREFIX).add(Opcode.OP_CAT)
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CAT)   // oldOwner
  s.add(P2PKH_SUFFIX).add(Opcode.OP_CAT)             // [tail, preimage, out1, out2]

  s.add(Opcode.OP_CAT)                               // out1 || out2
  s.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)  // out0 first
  s.add(Opcode.OP_ROT).add(Opcode.OP_CAT)            // append the spender's tail
  requireOutputIs(s)

  s.add(Opcode.OP_ELSE)

  // ---------------- checkin ----------------
  // in: [tail, sig, pubkey, preimage]
  //
  // The terminal branch, and the exit that keeps the covenant from stranding.
  // Output 0 must be the burn — a provably unspendable OP_FALSE OP_RETURN
  // naming the event and seat — so admission consumes the ticket in the same
  // act that records it. There is no second gate to double-enter.

  selfChunk(s)
  ownerFromChunk(s)
  s.add(n(3)).add(Opcode.OP_PICK).add(Opcode.OP_HASH160).add(Opcode.OP_EQUALVERIFY)

  s.add(Opcode.OP_DROP)                          // chunk
  s.add(Opcode.OP_TOALTSTACK)                    // park preimage
  s.add(Opcode.OP_CHECKSIGVERIFY)
  s.add(Opcode.OP_FROMALTSTACK)                  // [tail, preimage]

  s.add(Opcode.OP_SWAP)                          // [preimage, tail]
  s.add(burnTxOut(event, seat)).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  requireOutputIs(s)

  s.add(Opcode.OP_ENDIF)

  const size = s.toBuffer().length
  if (size < 253 || size > 65535) {
    throw new Error(`script is ${size} bytes; the 3-byte varint assumption holds only for 253..65535`)
  }
  return s
}

// Fixed values so a documented byte count is reproducible rather than dependent
// on whichever key happened to be generated.
const EXAMPLE_ADDRESS = '1PZBjMiVngoEhvffs7k5Rgysw4yAZVspcS'
const EXAMPLE_VENUE = '18fUDTpVhXjfbHBsdcj6diHnNDnafxP2if'

module.exports = {
  name: 'ticket',
  describe: 'an event ticket: capped resale, an enforced venue cut, burnt at the door',

  /** A canonical example, so docs and tooling can build this predicate. */
  example: () => ({
    owner: EXAMPLE_ADDRESS,
    venue: EXAMPLE_VENUE,
    event: 'Barbican 2026-11-04',
    seat: 'K12',
    maxPrice: 50000,
    venueBps: 1000,
    ticketValue: 600
  }),

  buildScript,
  venueCutOn,
  eventTag,
  burnTxOut,

  lock (p) {
    const { owner, venue, event, seat, maxPrice, venueBps, ticketValue } = p
    if (!owner || !venue) throw new Error('owner and venue are required')
    if (!event || !seat) throw new Error('event and seat are required')
    if (!Number.isInteger(maxPrice) || maxPrice <= 0) {
      throw new Error('maxPrice must be a positive integer')
    }
    if (!Number.isInteger(venueBps) || venueBps <= 0 || venueBps >= BPS_DENOMINATOR) {
      throw new Error('venueBps must be between 1 and 9999')
    }
    if (!Number.isInteger(ticketValue) || ticketValue <= 0) {
      throw new Error('ticketValue must be a positive integer')
    }
    // A price whose cut truncates to zero can never spend. Refusing at mint is
    // the difference between an error and a ticket nobody can resell.
    if (venueCutOn(maxPrice, venueBps) < 1) {
      throw new Error(`a ${venueBps}bps cut of maxPrice ${maxPrice} truncates to zero`)
    }
    return buildScript(p)
  },

  /**
   * The outputs, in the order hashOutputs commits to. Order is the mechanic:
   * the same three outputs in another sequence are a different hash.
   */
  outputs (t) {
    const { owner, newOwner, venue, satoshis, ticketValue, venueBps,
      branch = 'resell', price, event, seat,
      actualScript, actualTicketValue, actualNewOwner, actualPrice,
      actualCut, actualVenue, actualSeller, actualBurnScript,
      swapOutputs, dropVenueOutput, omitTail } = t

    const changeTo = t.changeTo || bsv.Address.fromPublicKeyHash(hash160Of(owner))

    if (branch === 'checkin') {
      const burn = actualBurnScript || new Script()
        .add(Opcode.OP_FALSE).add(Opcode.OP_RETURN).add(eventTag(event, seat))
      const outs = [new bsv.Transaction.Output({ script: burn, satoshis: 0 })]
      if (!omitTail) {
        outs.push(new bsv.Transaction.Output({
          script: bsv.Script.buildPublicKeyHashOut(changeTo),
          satoshis: satoshis - 200
        }))
      }
      return outs
    }

    const cut = actualCut ?? venueCutOn(price, venueBps)
    const carrier = actualScript ||
      ticketOutputScript(t, actualNewOwner ?? newOwner)

    const outs = [
      new bsv.Transaction.Output({
        script: carrier,
        satoshis: actualTicketValue ?? ticketValue
      }),
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(
          bsv.Address.fromPublicKeyHash(hash160Of(actualVenue ?? venue))),
        satoshis: cut
      }),
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(
          bsv.Address.fromPublicKeyHash(hash160Of(actualSeller ?? owner))),
        satoshis: actualPrice ?? price
      })
    ]
    if (dropVenueOutput) outs.splice(1, 1)
    if (swapOutputs) { const x = outs[1]; outs[1] = outs[2]; outs[2] = x }
    if (omitTail) return outs

    // The buyer's change: whatever the covenant does not pin. This is the free
    // tail, and it is what makes the covenant usable with a funding input.
    const spent = outs.reduce((sum, o) => sum + o.satoshis, 0)
    if (satoshis - spent - 200 > 0) {
      outs.push(new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(changeTo),
        satoshis: satoshis - spent - 200
      }))
    }
    return outs
  },

  /** After a resale the ticket still exists, under its new holder. */
  continuation (t) {
    if ((t.branch || 'resell') === 'checkin') return null
    return {
      script: ticketOutputScript(t, t.newOwner),
      params: {
        owner: addressString(t.newOwner), venue: addressString(t.venue),
        event: t.event, seat: t.seat, maxPrice: t.maxPrice,
        venueBps: t.venueBps, ticketValue: t.ticketValue
      }
    }
  },

  unlock (t) {
    const { tx, inputIndex, lockingScript, satoshis, sighashType,
      branch = 'resell', ownerKey, ownerWif, key, newOwner, price,
      pushNewOwner, pushPrice, signWith } = t
    const type = sighashType ??
      (bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID)

    const signer = signWith || ownerKey ||
      (ownerWif ? bsv.PrivateKey.fromWIF(ownerWif) : null) || key
    if (!signer) throw new Error('no signing key: pass ownerWif= for a ticket you do not hold')

    // The tail is exactly the outputs the covenant does not pin, serialised.
    // Building it from the real transaction is the point: if the spender's tail
    // and the transaction's outputs ever disagree, the hash does not match.
    const pinned = branch === 'checkin' ? 1 : 3
    const tail = Buffer.concat(
      tx.outputs.slice(pinned).map(o => o.toBufferWriter().toBuffer()))

    for (let i = 0; i < 50000; i++) {
      tx.nLockTime = i
      const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType)
      if (!PushTx.sFromPreimage(preimage)) continue

      const sig = bsv.Transaction.Sighash.sign(
        tx, signer, type, inputIndex, lockingScript, new bsv.crypto.BN(satoshis)
      ).toTxFormat()

      const s = new Script()
      s.add(tail.length ? tail : Opcode.OP_0)
      if (branch !== 'checkin') {
        // pushPrice and pushNewOwner exist so a test can DECLARE one thing while
        // the transaction pays another. The declaration is what the script
        // reasons about; hashOutputs is what it must match.
        s.add(n(pushPrice ?? price))
        s.add(hash160Of(pushNewOwner ?? newOwner))
      }
      s.add(sig).add(signer.publicKey.toBuffer())
      // The flag goes BELOW the preimage: the preimage must be on top for the
      // single hoisted OP_PUSH_TX, which then swaps the flag up for OP_IF.
      s.add(branch === 'checkin' ? Opcode.OP_0 : Opcode.OP_1)
      return s.add(preimage)
    }
    throw new Error('preimage grind failed after 50000 tries')
  }
}
