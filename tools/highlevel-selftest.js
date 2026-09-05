'use strict'

// The high-level API is the product bar: a person writes business rules, and out come
// coins byte-identical to the deployed predicate, a plain-English guarantee report, and
// — when a rule is wrong — a sentence in their own vocabulary, not a Script error.

const hl = require('../src/highlevel')
const onchain = require('../src/onchain')

let failed = 0
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok ' : 'FAIL'}  ${msg}`); if (!cond) failed++ }

// the deployed ledger: N=3 buckets 50/30/20, one owner — the accounting example, on chain
const lg = onchain.readLedger().filter((x) => x.predicate === 'ledger').slice(-1)[0]
const owner = lg.params.owner

const budget = hl.ledger('DepartmentBudget', {
  genesis: lg.params.genesis,
  total: 100,
  accounts: [
    { name: 'operations', balance: 50, owner },
    { name: 'research', balance: 30, owner },
    { name: 'marketing', balance: 20, owner }
  ]
})

console.log('an accountant’s ledger compiles to the deployed bytes:')
ok(budget.total === 100, 'the declared total (100) matches the accounts')
ok(budget.coins[0].script.toHex() === lg.lockHex,
  `the "operations" account is byte-identical to the deployed ledger ${lg.txid.slice(0, 12)}…:0 (${budget.coins[0].script.toBuffer().length} B)`)

console.log('\nand it states, in plain language, what Bitcoin will enforce:')
for (const g of budget.guarantees) console.log(`  ✓ ${g}`)
ok(budget.guarantees.length >= 4 && budget.guarantees.some((g) => /sum to 100/.test(g)),
  'the guarantee report is generated from the underlying predicate')

console.log('\na valid transfer is planned in business terms:')
const t = hl.transfer(budget, { from: 'operations', to: 'research', amount: 5 })
ok(t.next.join(',') === '45,35,20' && t.next.reduce((a, b) => a + b, 0) === 100,
  `move 5 ops→research: ${budget.accounts.map((a) => a.balance)} → ${t.next} (total still 100)`)

console.log('\nthe compiler teaches while it protects — wrong rules get plain sentences:')
try {
  hl.transfer(budget, { from: 'operations', to: 'research', amount: 999 })
  ok(false, 'an over-balance transfer should be refused')
} catch (e) { ok(/holds only 50/.test(e.message), `over-balance transfer → “${e.message}”`) }

try {
  hl.ledger('Bad', { genesis: lg.params.genesis, total: 100, accounts: [{ name: 'a', balance: 60, owner }, { name: 'b', balance: 30, owner }] })
  ok(false, 'a mismatched total should be refused')
} catch (e) { ok(/add up to 90.*total as 100/.test(e.message), `wrong total → “${e.message}”`) }

try {
  hl.ledger('Bad2', { genesis: lg.params.genesis, accounts: [{ name: 'a', balance: 100 }] })
  ok(false, 'a one-account ledger with no owner should be refused')
} catch (e) { ok(/at least two accounts/.test(e.message), `too few accounts → “${e.message}”`) }

// ── credential → lifecycle, byte-identical to the deployed certificate ──
const lc = onchain.readLedger().filter((x) => x.predicate === 'lifecycle')[0]
const cred = hl.credential('Certificate', { genesis: lc.params.genesis, issuer: lc.params.issuer, status: 'ISSUED' })
console.log('\na credential lowers to the deployed lifecycle certificate:')
ok(cred.coin.script.toHex() === lc.lockHex, `Certificate → byte-identical to ${lc.txid.slice(0, 12)}…:0 (status ${cred.status})`)
ok(hl.moveStatus('ISSUED', 'ACTIVE').to === 'ACTIVE', 'issued → active is planned')
try { hl.moveStatus('REVOKED', 'ACTIVE'); ok(false, 'revoked→active should refuse') }
catch (e) { ok(/terminal/.test(e.message), `revoked → active → “${e.message}”`) }
try { hl.moveStatus('ISSUED', 'SUSPENDED'); ok(false, 'issued→suspended should refuse') }
catch (e) { ok(/only ACTIVE or REVOKED/.test(e.message), `issued → suspended → “${e.message}”`) }

// ── capability → delegation, byte-identical to the deployed budget ──
const dg = onchain.readLedger().filter((x) => x.predicate === 'delegation')[0]
const cap = hl.capability('SpendAuthority', { root: dg.params.root, budget: dg.params.budget, owner: dg.params.owner })
console.log('\na capability lowers to the deployed delegation budget:')
ok(cap.coin.script.toHex() === dg.lockHex, `SpendAuthority → byte-identical to ${dg.txid.slice(0, 12)}…:0 (budget ${cap.budget})`)
const d = hl.delegate(cap, { amount: 40, to: 'a team lead' })
ok(d.childBudget === 40 && d.keep === cap.budget - 40, `delegate 40: child 40 + kept ${d.keep} = ${cap.budget}`)
try { hl.delegate(cap, { amount: 999 }); ok(false, 'over-delegation should refuse') }
catch (e) { ok(/budget of only/.test(e.message), `over-delegate → “${e.message}”`) }

// ── game → turns, byte-identical to the deployed game ──
const tn = onchain.readLedger().filter((x) => x.predicate === 'turns')[0]
const g = hl.game('TicTacToe', { players: [tn.params.a, tn.params.b], turn: 0, state: Buffer.alloc(32) })
console.log('\na game lowers to the deployed turn-based coin:')
ok(g.coin.script.toHex() === tn.lockHex, `TicTacToe → byte-identical to ${tn.txid.slice(0, 12)}…:0 (turn ${g.turn})`)
ok(hl.move(g, { player: 0, state: Buffer.alloc(32, 1) }).nextTurn === 1, 'player 1 moves on turn 0, turn passes to player 2')
try { hl.move(g, { player: 1, state: Buffer.alloc(32, 1) }); ok(false, 'wrong-player move should refuse') }
catch (e) { ok(/player 1's turn/.test(e.message), `wrong player → “${e.message}”`) }

// ── escrow → htlc, byte-identical to the deployed escrow ──
const ht = onchain.readLedger().filter((x) => x.predicate === 'htlc')[0]
const esc = hl.escrow('DeliveryEscrow', { recipient: ht.params.recipient, sender: ht.params.sender, secret: ht.params.secret, notBefore: ht.params.notBefore })
console.log('\nan escrow lowers to the deployed htlc:')
ok(esc.coin.script.toHex() === ht.lockHex, `DeliveryEscrow → byte-identical to ${ht.txid.slice(0, 12)}…:0`)
try { hl.escrow('Bad', { recipient: ht.params.recipient, sender: ht.params.sender, secret: 'x' }); ok(false, 'missing notBefore should refuse') }
catch (e) { ok(/needs notBefore/.test(e.message), `missing field → “${e.message}”`) }

// ── stream → journal, byte-identical to the deployed log ──
const jr = onchain.readLedger().filter((x) => x.predicate === 'journal')[0]
const str = hl.stream('AuditLog', { publisher: jr.params.publisher })
console.log('\na stream lowers to the deployed journal:')
ok(str.coin.script.toHex() === jr.lockHex, `AuditLog → byte-identical to ${jr.txid.slice(0, 12)}…:0`)
const ap = hl.append(str, { seq: 0, head: undefined, recordHash: Buffer.alloc(32, 0xaa) })
ok(ap.nextSeq === 1 && Buffer.isBuffer(ap.nextHead), `append: seq 0 → 1, head folds in the record`)

// ── predictionMarket → market, byte-identical to the predicate (not yet deployed) ──
const marketPred = require('../src/predicates/market')
const bsv = require('@smartledger/bsv')
const yesAddr = bsv.PrivateKey.fromRandom().toAddress().toString()
const noAddr = bsv.PrivateKey.fromRandom().toAddress().toString()
const pm = hl.predictionMarket('RainTomorrow', { question: 'Will it rain in Austin tomorrow?', yesOwner: yesAddr, noOwner: noAddr, m: 2, deadline: 900000 })
const qid = bsv.crypto.Hash.sha256(Buffer.from('Will it rain in Austin tomorrow?', 'utf8'))
const wantMarket = marketPred.buildScript({ question: qid, yesPKH: marketPred.pkhOf(yesAddr), noPKH: marketPred.pkhOf(noAddr), m: 2, deadline: 900000 })
console.log('\na prediction market lowers to the market predicate (a question of text becomes a stable id):')
ok(pm.coin.script.toHex() === wantMarket.toHex(), `RainTomorrow → byte-identical to the market predicate (${pm.coin.script.toBuffer().length} B, id ${pm.questionId.slice(0, 12)}…)`)
ok(hl.settleMarket(pm, { outcome: 'yes' }).winner === 'the YES owner' && hl.settleMarket(pm, { outcome: 'no' }).winner === 'the NO owner', 'settle names the winning side for each outcome')
ok(hl.refundMarket(pm).note.includes('50/50'), 'refund explains the 50/50 reclaim after the deadline')
try { hl.predictionMarket('Bad', { yesOwner: yesAddr, noOwner: noAddr }); ok(false, 'missing question should refuse') } catch (e) { ok(/needs a question/.test(e.message), `a market without a question is refused — “${e.message}”`) }
try { hl.predictionMarket('Bad', { question: 'x', yesOwner: yesAddr, noOwner: noAddr, m: 9 }); ok(false, 'm out of range should refuse') } catch (e) { ok(/between 1 and 3/.test(e.message), `a threshold above the panel size is refused — “${e.message}”`) }
try { hl.settleMarket(pm, { outcome: 'maybe' }); ok(false, 'a non-binary outcome should refuse') } catch (e) { ok(/unknown outcome/.test(e.message), `a non-binary outcome is refused — “${e.message}”`) }

// the same builder, given 3+ named outcomes, lowers to the categorical marketN
const marketNPred = require('../src/predicates/marketN')
const a3 = [bsv.PrivateKey.fromRandom().toAddress().toString(), bsv.PrivateKey.fromRandom().toAddress().toString(), bsv.PrivateKey.fromRandom().toAddress().toString()]
const cm = hl.predictionMarket('Election', { question: 'Who wins the election?', outcomes: [{ label: 'Alice', owner: a3[0] }, { label: 'Bob', owner: a3[1] }, { label: 'Carol', owner: a3[2] }], m: 2, deadline: 900000 })
const eid = bsv.crypto.Hash.sha256(Buffer.from('Who wins the election?', 'utf8'))
const wantN = marketNPred.buildScript({ question: eid, owners: a3.map((x) => marketNPred.pkhOf(x)), m: 2, deadline: 900000 })
ok(cm.predicate === 'marketN' && cm.coin.script.toHex() === wantN.toHex(), `Election (3 outcomes) → byte-identical to the marketN predicate (${cm.coin.script.toBuffer().length} B, outcomes: ${cm.outcomes.join(', ')})`)
ok(hl.settleMarket(cm, { outcome: 'Bob' }).index === 1, 'settle resolves a named outcome to its index')
ok(hl.refundMarket(cm).note.includes('3 equal shares'), 'refund explains the K-way equal split')

// the same builder, given a numeric range with LONG/SHORT, lowers to the scalar marketScalar
const marketScalarPred = require('../src/predicates/marketScalar')
const longA = bsv.PrivateKey.fromRandom().toAddress().toString()
const shortA = bsv.PrivateKey.fromRandom().toAddress().toString()
const sm = hl.predictionMarket('BSVUSD', { question: 'BSV/USD price at close?', low: 6000, high: 7000, longOwner: longA, shortOwner: shortA, m: 2 })
const sid = bsv.crypto.Hash.sha256(Buffer.from('BSV/USD price at close?', 'utf8'))
const wantS = marketScalarPred.buildScript({ question: sid, low: 6000, high: 7000, pkhL: marketScalarPred.pkhOf(longA), pkhS: marketScalarPred.pkhOf(shortA), m: 2, deadline: 900000 })
ok(sm.predicate === 'marketScalar' && sm.coin.script.toHex() === wantS.toHex(), `BSVUSD (scalar range 6000–7000) → byte-identical to the marketScalar predicate (${sm.coin.script.toBuffer().length} B)`)
ok(hl.settleMarket(sm, { value: 6500 }).longPct === 50, 'settle on a mid-range value splits the pot piecewise (50/50 at the midpoint)')
try { hl.predictionMarket('Bad', { question: 'x', low: 6000 }); ok(false, 'a scalar market missing high should refuse') } catch (e) { ok(/needs high/.test(e.message), `an incomplete scalar market is refused — “${e.message}”`) }

// a MANY-POSITION market: one descentmarket coin + positions written against its identity, before resolution
const descentmarketPred = require('../src/predicates/descentmarket')
const positionv2Pred = require('../src/predicates/positionv2')
const G = descentmarketPred.genesisOutpoint('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', 0)
const pmkt = hl.positionMarket('ElectionMarket', { genesis: G, question: 'Will candidate A win?', m: 2 })
console.log('\na market of many positions lowers to one descentmarket coin, with positions written against its identity:')
ok(pmkt.predicate === 'descentmarket' && pmkt.coin.script.toHex() === descentmarketPred.buildScript({ genesis: G, status: descentmarketPred.OPEN, outcome: 0, m: 2 }).toHex(),
  `ElectionMarket → byte-identical to the OPEN descentmarket (${pmkt.coin.script.toBuffer().length} B, id ${pmkt.marketId.slice(0, 12)}…)`)
const pOwner = bsv.PrivateKey.fromRandom().toAddress().toString(); const pCp = bsv.PrivateKey.fromRandom().toAddress().toString()
const pos = hl.writePosition(pmkt, { side: 'yes', owner: pOwner, counterparty: pCp })
ok(pos.predicate === 'positionv2' && pos.coin.script.toHex() === positionv2Pred.buildScript({ market: positionv2Pred.marketId(G), side: 1, owner: positionv2Pred.pkhOf(pOwner), counterparty: positionv2Pred.pkhOf(pCp) }).toHex(),
  `a YES position written against the market’s identity → byte-identical to positionv2 (${pos.coin.script.toBuffer().length} B)`)
ok(hl.settlePosition(pos, { outcome: 'yes' }).winner === 'the owner' && hl.settlePosition(pos, { outcome: 'no' }).winner === 'the counterparty', 'settle pays the owner when the market matches the side, else the counterparty')
try { hl.positionMarket('Bad', {}); ok(false, 'a market without a genesis should refuse') } catch (e) { ok(/needs a genesis/.test(e.message), `a market without a genesis is refused — “${e.message}”`) }
try { hl.writePosition(pmkt, { side: 'yes', owner: pOwner }); ok(false, 'a position without a counterparty should refuse') } catch (e) { ok(/needs counterparty/.test(e.message), `a position missing a party is refused — “${e.message}”`) }

console.log(failed
  ? `\n${failed} failing`
  : '\nthe high-level API holds: eight domain builders — business rules in, deployed bytes out')
process.exit(failed ? 1 : 0)
