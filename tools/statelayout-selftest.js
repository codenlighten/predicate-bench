'use strict'

// The @state field layout is trustworthy only if the bytes it produces are exactly the
// bytes the predicates already carry on chain. This checks each type's width and encoding,
// and confirms the layouts of the deployed asset/sovereign predicates reconstruct their
// hand-written state byte-for-byte from field values — so a class can declare its state
// (owner: hash160, balance: u64) and the compiler owns every offset and push.

const L = require('../src/statelayout')
const asset = require('../src/predicates/asset')
const sovereign = require('../src/predicates/sovereign')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }
const ADDR = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'

console.log('each field type has the fixed width the covenant offsets depend on (pitfall 21):')
for (const [t, w] of [['u8', 1], ['u16', 2], ['u32', 4], ['u64', 8], ['hash160', 20], ['bytes32', 32], ['bytes36', 36]]) {
  ok(L.typeOf(t).width === w, `${t} is ${w} bytes`)
}
ok(L.typeOf('bytes7').width === 7, 'bytes<N> is N bytes')
try { L.typeOf('u128'); ok(false, 'an unknown type should throw') } catch (e) { ok(/unknown field type/.test(e.message), 'an unknown type is refused') }

console.log('\nlittle-endian integers encode exactly as the predicates do:')
ok(L.typeOf('u64').enc(500).equals(asset.balanceLE(500)), 'u64(500) == balanceLE(500) — 6-byte magnitude in 8 bytes')
ok(L.typeOf('u32').enc(1).toString('hex') === '01000000', 'u32(1) is little-endian')
try { L.encodeState([{ name: 'x', type: 'u32' }], { x: 2 ** 40 }); ok(false, 'overflow should throw') } catch (e) { ok(/out of range/.test(e.message), 'an out-of-range value is refused, not truncated') }

console.log('\nhash160 accepts an address, hex, or a 20-byte buffer — all the same bytes:')
const h = asset.hash160Of(ADDR)
ok(L.typeOf('hash160').enc(ADDR).equals(h), 'a base58 address encodes to its HASH160')
ok(L.typeOf('hash160').enc(h.toString('hex')).equals(h), 'the same as a 40-char hex string')
ok(L.typeOf('hash160').enc(h).equals(h), 'the same as a 20-byte buffer')

console.log('\nthe deployed layouts reconstruct the on-chain state byte-for-byte:')
{
  const layout = [{ name: 'owner', type: 'hash160' }, { name: 'balance', type: 'u64' }]
  ok(L.width(layout) === 28, 'asset layout is 28 bytes')
  ok(L.encodeState(layout, { owner: ADDR, balance: 500 }).equals(Buffer.concat([asset.hash160Of(ADDR), asset.balanceLE(500)])),
    'owner:hash160, balance:u64 == asset state(owner, balance)')
}
{
  const G = Buffer.alloc(36, 7)
  const layout = [{ name: 'genesis', type: 'bytes36' }, { name: 'owner', type: 'hash160' }, { name: 'balance', type: 'u64' }]
  ok(L.width(layout) === 64, 'sovereign layout is 64 bytes')
  ok(L.encodeState(layout, { genesis: G, owner: ADDR, balance: 500 }).equals(Buffer.concat([G, sovereign.hash160Of(ADDR), sovereign.balanceLE(500)])),
    'genesis:bytes36, owner:hash160, balance:u64 == sovereign state(genesis, owner, balance)')
}

console.log(failed
  ? `\n${failed} failing`
  : '\nthe state layout is faithful: a class declares its fields, the compiler emits the exact on-chain state bytes')
process.exit(failed ? 1 : 0)
