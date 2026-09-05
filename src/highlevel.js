'use strict'

const ledgerPred = require('./predicates/ledger')
const lifecyclePred = require('./predicates/lifecycle')
const delegationPred = require('./predicates/delegation')
const turnsPred = require('./predicates/turns')
const htlcPred = require('./predicates/htlc')
const journalPred = require('./predicates/journal')
const marketPred = require('./predicates/market')
const marketNPred = require('./predicates/marketN')
const marketScalarPred = require('./predicates/marketScalar')
const descentmarketPred = require('./predicates/descentmarket')
const positionv2Pred = require('./predicates/positionv2')
const bsv = require('@smartledger/bsv')

// THE HIGH-LEVEL API — the top of the stack, for people who think in their problem
// domain, not in Script. An accountant declares accounts and a total; this returns the
// coins (byte-identical to the deployed predicate), a plain-English statement of what
// Bitcoin will enforce, and diagnostics that speak business, not stack depth.
//
//   ledger('DepartmentBudget', {
//     genesis, accounts: [
//       { name: 'operations', balance: 50, owner },
//       { name: 'research',   balance: 30, owner },
//       { name: 'marketing',  balance: 20, owner }
//     ]
//   })
//
// The user never sees OP_PICK. They see: three accounts that always sum to 100, each
// movable only by its owner, every move appended to a tamper-evident audit chain — and,
// if they get a rule wrong, a sentence that explains it in their own vocabulary.

// what each underlying predicate GUARANTEES, in plain language (the "this contract
// guarantees ✓…" report the product shows before deployment).
function ledgerGuarantees (spec) {
  const total = spec.accounts.reduce((s, a) => s + a.balance, 0)
  return [
    `the ${spec.accounts.length} accounts always sum to ${total} — no transfer can inflate or destroy value`,
    'an account can be moved only by its own owner (a signature is required)',
    'every transfer is appended to each account’s tamper-evident audit chain (sequence + rolling hash)',
    'no counterfeit account can enter circulation — each descends from the genesis',
    'the whole group must move together — a transfer that leaves an account behind is rejected'
  ]
}

// friendly, business-level validation — the "teaches while it protects" layer.
function checkLedger (name, spec) {
  const p = []
  if (!spec || !Array.isArray(spec.accounts) || spec.accounts.length < 2) {
    p.push(`a ledger needs at least two accounts (got ${spec && spec.accounts ? spec.accounts.length : 0})`)
    return p
  }
  if (spec.accounts.length > 16) p.push(`a ledger supports up to 16 accounts (got ${spec.accounts.length})`)
  if (!spec.genesis) p.push('the ledger needs a genesis outpoint (the unique origin every account descends from)')
  spec.accounts.forEach((a, i) => {
    if (!a.name) p.push(`account #${i} has no name`)
    if (!Number.isInteger(a.balance) || a.balance < 0) p.push(`account '${a.name || i}' needs a whole, non-negative balance`)
    if (!a.owner) p.push(`account '${a.name || i}' has no owner — who is allowed to move its funds?`)
  })
  const names = spec.accounts.map((a) => a.name)
  if (new Set(names).size !== names.length) p.push('two accounts share a name — each account needs a distinct name')
  if (spec.total !== undefined) {
    const t = spec.accounts.reduce((s, a) => s + (a.balance || 0), 0)
    if (t !== spec.total) p.push(`the accounts add up to ${t}, but you declared the total as ${spec.total} — these must match`)
  }
  return p
}

/**
 * Compile an accounting ledger to Bitcoin. Returns { name, predicate, total, accounts,
 * coins:[{account,index,balance,owner,script}], guarantees:[…] }.
 * Throws a plain-English Error (with .problems) if the rules don't add up.
 */
function ledger (name, spec) {
  const problems = checkLedger(name, spec)
  if (problems.length) { const e = new Error(`${name}: ${problems[0]}`); e.problems = problems; throw e }
  const N = spec.accounts.length
  const coins = spec.accounts.map((a, i) => ({
    account: a.name, index: i, balance: a.balance, owner: a.owner,
    script: ledgerPred.buildScript({ genesis: spec.genesis, index: i, balance: a.balance, owner: a.owner, seq: 0, head: ledgerPred.GENESIS_HEAD, N })
  }))
  return { name, predicate: 'ledger', total: spec.accounts.reduce((s, a) => s + a.balance, 0), accounts: spec.accounts, coins, guarantees: ledgerGuarantees(spec) }
}

/**
 * Plan a transfer between two accounts, in business terms — the checks Bitcoin will
 * enforce, surfaced as readable sentences before the transaction is ever built.
 * Returns { next:[balances], record, note }. Throws a plain-English Error otherwise.
 */
function transfer (spec, { from, to, amount, record }) {
  const bal = {}
  for (const a of spec.accounts) bal[a.name] = a.balance
  if (!(from in bal)) throw new Error(`there is no account named '${from}'`)
  if (!(to in bal)) throw new Error(`there is no account named '${to}'`)
  if (from === to) throw new Error('the source and destination accounts are the same')
  if (!Number.isInteger(amount) || amount <= 0) throw new Error('the transfer amount must be a positive whole number')
  if (amount > bal[from]) throw new Error(`'${from}' holds only ${bal[from]}, so it cannot transfer ${amount}`)
  const total = spec.accounts.reduce((s, a) => s + a.balance, 0)
  const next = spec.accounts.map((a) => a.name === from ? a.balance - amount : a.name === to ? a.balance + amount : a.balance)
  // conservation holds by construction; state it as the guarantee the chain will enforce.
  return { next, record: record || `transfer ${amount} from ${from} to ${to}`, note: `${amount} moves ${from} → ${to}; the total stays ${total}, and the move is added to the audit chain` }
}

// ── credential: a status lifecycle (issued → active → suspended → revoked) ──────────
// lowers to the `lifecycle` predicate. The vocabulary is status names; the compiler owns
// the transition set, the terminal state, and the immutable core.
const STATUS = { ISSUED: lifecyclePred.ISSUED, ACTIVE: lifecyclePred.ACTIVE, SUSPENDED: lifecyclePred.SUSPENDED, REVOKED: lifecyclePred.REVOKED }
const STATUS_NAME = Object.fromEntries(Object.entries(STATUS).map(([k, v]) => [v, k]))
function statusNum (s) {
  if (typeof s === 'number') return s
  const n = STATUS[String(s).toUpperCase()]
  if (n === undefined) throw new Error(`unknown status '${s}' — use one of ${Object.keys(STATUS).join(', ')}`)
  return n
}
function credentialGuarantees () {
  return [
    'only the issuer can change the certificate’s status (a signature is required)',
    'the status may move only along the allowed path: issued → active or revoked; active ⇄ suspended; any state → revoked',
    'REVOKED is terminal — once revoked, no status can ever follow, and the fact cannot be rewritten',
    'the certificate’s identity (its genesis) and its issuer are immutable — even the issuer cannot change them'
  ]
}
/**
 * A status credential/lifecycle. spec: { genesis, issuer, status? }.
 * Returns { name, predicate:'lifecycle', status, coin:{script}, guarantees }.
 */
function credential (name, spec) {
  if (!spec || !spec.genesis) throw new Error(`${name}: a credential needs a genesis (its unique identity)`)
  if (!spec.issuer) throw new Error(`${name}: a credential needs an issuer (who may change its status)`)
  const status = statusNum(spec.status ?? 'ISSUED')
  const script = lifecyclePred.buildScript({ genesis: spec.genesis, issuer: spec.issuer, status, fee: spec.fee ?? lifecyclePred.DEFAULT_FEE })
  return { name, predicate: 'lifecycle', status: STATUS_NAME[status], coin: { script }, guarantees: credentialGuarantees() }
}
/** Plan a status change in plain terms; refuse an illegal or terminal move with a sentence. */
function moveStatus (fromStatus, to) {
  const a = statusNum(fromStatus); const b = statusNum(to)
  const allowed = lifecyclePred.CERT_TRANSITIONS.some(([x, y]) => x === a && y === b)
  if (!allowed) {
    const outs = lifecyclePred.CERT_TRANSITIONS.filter(([x]) => x === a).map(([, y]) => STATUS_NAME[y])
    if (!outs.length) throw new Error(`${STATUS_NAME[a]} is a terminal state — nothing can follow it`)
    throw new Error(`a ${STATUS_NAME[a]} certificate cannot go to ${STATUS_NAME[b]} — only ${outs.join(' or ')}`)
  }
  return { from: STATUS_NAME[a], to: STATUS_NAME[b], note: `status ${STATUS_NAME[a]} → ${STATUS_NAME[b]}, issuer-signed` }
}

// ── capability: a divisible authority budget (delegate / exercise / revoke) ──────────
// lowers to the `delegation` predicate. The vocabulary is a budget and an owner.
function capabilityGuarantees (spec) {
  return [
    `the owner holds a budget of ${spec.budget} and may delegate part of it, spend it, or revoke it`,
    'delegated sub-budgets can never sum to more than the owner’s — authority is conserved, not created',
    'only the owner can delegate, exercise, or revoke (a signature is required)',
    'every capability descends from the root grant — no counterfeit authority can enter'
  ]
}
/**
 * A capability with a spendable authority budget. spec: { root, budget, owner }.
 * Returns { name, predicate:'delegation', budget, coin:{script}, guarantees }.
 */
function capability (name, spec) {
  if (!spec || !spec.root) throw new Error(`${name}: a capability needs a root (the origin of the authority)`)
  if (!spec.owner) throw new Error(`${name}: a capability needs an owner`)
  if (!Number.isInteger(spec.budget) || spec.budget < 1) throw new Error(`${name}: the budget must be a whole number of at least 1`)
  const script = delegationPred.buildScript({ root: spec.root, budget: spec.budget, owner: spec.owner, fee: spec.fee ?? delegationPred.DEFAULT_FEE })
  return { name, predicate: 'delegation', budget: spec.budget, coin: { script }, guarantees: capabilityGuarantees(spec) }
}
/** Plan a delegation in plain terms; refuse over-delegation with a sentence. */
function delegate (cap, { amount, to }) {
  if (!Number.isInteger(amount) || amount < 1) throw new Error('the delegated amount must be a whole number of at least 1')
  if (amount > cap.budget) throw new Error(`cannot delegate ${amount}: the capability holds a budget of only ${cap.budget}`)
  return { childBudget: amount, keep: cap.budget - amount, note: `delegate ${amount} to ${to || 'a child'}; the owner keeps ${cap.budget - amount} — the two sum to the original ${cap.budget}` }
}

// ── game: a two-player turn-based game ──────────────────────────────────────────────
// lowers to the `turns` predicate. The vocabulary is players, turns and moves; the
// compiler owns the turn-bound authority and the alternation. (The Kaboom.js visual
// layer, and per-game move legality, sit above this — see docs/roadmap.md.)
function gameGuarantees () {
  return [
    'only the player whose turn it is can move (a signature is required)',
    'the turn always alternates — no player can move twice in a row',
    'the game state is carried forward honestly; every other rule of the game stays fixed',
    'the pot is paid out only when BOTH players sign to settle on a winner'
  ]
}
/**
 * A two-player turn-based game. spec: { players: [a, b], turn?, state? }.
 * Returns { name, predicate:'turns', turn, coin:{script}, guarantees }.
 */
function game (name, spec) {
  const players = spec && spec.players
  if (!Array.isArray(players) || players.length !== 2) throw new Error(`${name}: a game needs exactly two players`)
  const turn = spec.turn ?? 0
  if (turn !== 0 && turn !== 1) throw new Error(`${name}: turn must be 0 (player 1) or 1 (player 2)`)
  const script = turnsPred.buildScript({ a: players[0], b: players[1], turn, gstate: spec.state, fee: spec.fee ?? turnsPred.DEFAULT_FEE })
  return { name, predicate: 'turns', turn, coin: { script }, guarantees: gameGuarantees() }
}
/** Plan a move in plain terms; refuse the wrong player with a sentence. */
function move (gameObj, { player, state }) {
  const who = gameObj.turn === 0 ? 'player 1' : 'player 2'
  if (player !== undefined && player !== gameObj.turn) {
    throw new Error(`it is ${who}'s turn — ${player === 0 ? 'player 1' : 'player 2'} cannot move now`)
  }
  return { by: who, nextTurn: 1 - gameObj.turn, state, note: `${who} moves; the turn passes to ${gameObj.turn === 0 ? 'player 2' : 'player 1'}` }
}

// ── escrow: pay on a revealed secret, or refund after a deadline ─────────────────────
// lowers to the `htlc` predicate. The vocabulary is a recipient, a sender, a secret and
// a deadline; the compiler owns the hashlock and the timelock.
function escrowGuarantees (spec) {
  return [
    'the recipient can claim the funds by revealing the agreed secret',
    `the sender can reclaim the funds after block ${spec.notBefore} if it was never claimed`,
    'no one else can move the funds, and the sender cannot reclaim early'
  ]
}
/**
 * A hash-timelock escrow. spec: { recipient, sender, secret, notBefore }.
 * Returns { name, predicate:'htlc', coin:{script}, guarantees }.
 */
function escrow (name, spec) {
  for (const k of ['recipient', 'sender', 'secret', 'notBefore']) {
    if (spec == null || spec[k] === undefined) throw new Error(`${name}: an escrow needs ${k} (recipient, sender, secret, notBefore)`)
  }
  const script = htlcPred.lock({ secret: spec.secret, recipient: spec.recipient, sender: spec.sender, notBefore: spec.notBefore })
  return { name, predicate: 'htlc', coin: { script }, guarantees: escrowGuarantees(spec) }
}

// ── stream: an append-only, authenticated log ────────────────────────────────────────
// lowers to the `journal` predicate. The vocabulary is a publisher; the compiler owns the
// sequence and the rolling hash-chained head.
function streamGuarantees () {
  return [
    'only the publisher can append to the stream (a signature is required)',
    'each entry advances the sequence by exactly one — no skips, repeats, or reordering',
    'the head commits to the whole history, so deleting or altering a past entry is detectable',
    'only each record’s hash goes on chain; the entries themselves stay private'
  ]
}
/**
 * An append-only authenticated stream. spec: { publisher }.
 * Returns { name, predicate:'journal', coin:{script}, guarantees }.
 */
function stream (name, spec) {
  if (spec == null || !spec.publisher) throw new Error(`${name}: a stream needs a publisher (who may append)`)
  const script = journalPred.buildScript({ seq: spec.seq ?? 0, head: spec.head ?? journalPred.GENESIS_HEAD, publisher: spec.publisher, fee: spec.fee ?? journalPred.DEFAULT_FEE })
  return { name, predicate: 'journal', coin: { script }, guarantees: streamGuarantees() }
}
/** Plan an append in plain terms: the next sequence and head, from a record's hash. */
function append (streamObj, { seq, head, recordHash }) {
  if (!recordHash) throw new Error('an append needs the record’s hash (the record itself stays off chain)')
  const nextHead = journalPred.chain(head ?? journalPred.GENESIS_HEAD, recordHash)
  return { nextSeq: (seq ?? 0) + 1, nextHead, note: `append record #${(seq ?? 0) + 1}; the head folds it into the chain — reorder or drop a past entry and every later head changes` }
}

// ── predictionMarket: two parties bet on a yes/no question, oracles decide ────────────
// lowers to the `market` predicate. The vocabulary is a question, a YES owner, a NO owner,
// and how many oracles must agree; the compiler owns the quorum, the payout binding, and
// the timelocked refund. This is the flagship application — a whole prediction market that
// a non-expert describes in four fields.
function predictionMarketGuarantees (m, N, deadline) {
  return [
    `the pot pays out only when at least ${m} of ${N} independent oracles attest the same outcome — no single oracle can decide it`,
    'the winning side is the oracles’ to call, not either party’s: a forged outcome, or one signed for a different question, is rejected',
    'the whole pot goes to the winner — the YES owner if the outcome is yes, the NO owner if no; no one can pay the loser or skim the pot',
    `if the oracles never agree, either party can reclaim their half after block ${deadline} (and a past-timestamp shortcut around that deadline is rejected)`
  ]
}
/** A stable 32-byte id for a market question: a hex id as-is, or the SHA-256 of the text. */
function questionId (q) {
  if (Buffer.isBuffer(q)) {
    if (q.length !== 32) throw new Error('a question given as bytes must be exactly 32 bytes')
    return q
  }
  if (typeof q === 'string' && /^[0-9a-fA-F]{64}$/.test(q)) return Buffer.from(q, 'hex')
  return bsv.crypto.Hash.sha256(Buffer.from(String(q), 'utf8'))
}
function outcomeNum (o) {
  if (o === 1 || o === true || /^(yes|y|true)$/i.test(String(o))) return marketPred.YES
  if (o === 0 || o === false || /^(no|n|false)$/i.test(String(o))) return marketPred.NO
  throw new Error(`unknown outcome '${o}' — use 'yes' or 'no'`)
}
/**
 * A fully-collateralised prediction market. Binary: spec { question, yesOwner, noOwner, … }
 * lowers to [`market`]. Categorical: spec { question, outcomes: [{ label?, owner }, …] } (3+)
 * lowers to [`marketN`]. `question` may be text (hashed to an id) or a 32-byte/64-hex id.
 * Also: m?, deadline?, oraclePanel?, fee?. Returns { name, predicate, question, questionId,
 * outcomes?, m, deadline, coin:{script}, guarantees }.
 */
function predictionMarket (name, spec) {
  if (spec == null || spec.question === undefined) throw new Error(`${name}: a prediction market needs a question`)
  const m = spec.m ?? 2
  const deadline = spec.deadline ?? marketPred.DEFAULT_DEADLINE
  const N = (spec.oraclePanel || marketPred.PANEL_N).length
  if (!Number.isInteger(m) || m < 1 || m > N) throw new Error(`${name}: the oracle threshold must be a whole number between 1 and ${N}`)
  const id = questionId(spec.question)
  const questionText = typeof spec.question === 'string' && !/^[0-9a-fA-F]{64}$/.test(spec.question) ? spec.question : id.toString('hex')

  // scalar: a numeric range with a LONG and a SHORT → marketScalar
  if (spec.low !== undefined || spec.high !== undefined || spec.longOwner !== undefined) {
    for (const k of ['low', 'high', 'longOwner', 'shortOwner']) {
      if (spec[k] === undefined) throw new Error(`${name}: a scalar market needs ${k} (low, high, longOwner, shortOwner)`)
    }
    if (!(spec.high > spec.low && spec.low >= 0)) throw new Error(`${name}: need high > low >= 0`)
    const script = marketScalarPred.buildScript({ question: id, low: spec.low, high: spec.high, pkhL: marketScalarPred.pkhOf(spec.longOwner), pkhS: marketScalarPred.pkhOf(spec.shortOwner), m, deadline, panelN: spec.oraclePanel, fee: spec.fee })
    return {
      name,
      predicate: 'marketScalar',
      question: questionText,
      questionId: id.toString('hex'),
      low: spec.low,
      high: spec.high,
      m,
      deadline,
      coin: { script },
      guarantees: [
        `the pot pays out only when at least ${m} of ${N} independent oracles attest the same value`,
        `the pot is split between LONG and SHORT by where the attested value falls in [${spec.low}, ${spec.high}]: at or below ${spec.low} the SHORT takes it all, at or above ${spec.high} the LONG does, and in between it is shared piecewise-linearly`,
        'the split is the oracles’ value to set, bound to this question — a forged value, or one signed for a different question, is rejected, and neither party can skew the payout',
        `if the oracles never agree, both parties reclaim their half after block ${deadline}`
      ]
    }
  }

  // categorical: 3+ named outcomes → marketN
  if (Array.isArray(spec.outcomes)) {
    if (spec.outcomes.length < 2) throw new Error(`${name}: a categorical market needs at least two outcomes`)
    spec.outcomes.forEach((o, i) => { if (o == null || o.owner === undefined) throw new Error(`${name}: outcome ${i} needs an owner`) })
    const labels = spec.outcomes.map((o, i) => o.label || `outcome ${i}`)
    const script = marketNPred.buildScript({ question: id, owners: spec.outcomes.map((o) => marketNPred.pkhOf(o.owner)), m, deadline, panelN: spec.oraclePanel, fee: spec.fee })
    return {
      name,
      predicate: 'marketN',
      question: questionText,
      questionId: id.toString('hex'),
      outcomes: labels,
      m,
      deadline,
      coin: { script },
      guarantees: [
        `the pot pays out only when at least ${m} of ${N} independent oracles attest the same outcome`,
        `the winner is one of ${labels.length} named outcomes (${labels.join(', ')}); the whole pot goes to that outcome's owner`,
        'the outcome is the oracles’ to call, bound to this question — a forged, out-of-range, or wrong-question index is rejected',
        `if the oracles never agree, the pot splits equally among all ${labels.length} owners after block ${deadline}`
      ]
    }
  }

  // binary: yes/no → market
  for (const k of ['yesOwner', 'noOwner']) {
    if (spec[k] === undefined) throw new Error(`${name}: a binary prediction market needs ${k} (or give an 'outcomes' array for a categorical one)`)
  }
  const script = marketPred.buildScript({
    question: id,
    yesPKH: marketPred.pkhOf(spec.yesOwner),
    noPKH: marketPred.pkhOf(spec.noOwner),
    m,
    deadline,
    panelN: spec.oraclePanel,
    fee: spec.fee
  })
  return {
    name,
    predicate: 'market',
    question: questionText,
    questionId: id.toString('hex'),
    m,
    deadline,
    coin: { script },
    guarantees: predictionMarketGuarantees(m, N, deadline)
  }
}
/** Plan a settlement in plain terms: which side/outcome wins and what the oracles must attest. */
function settleMarket (marketObj, { outcome, value } = {}) {
  if (marketObj.predicate === 'marketScalar') {
    if (value === undefined) throw new Error('a scalar market settles on a value — pass { value }')
    const { payL, payS } = marketScalarPred.payout(1000000, value, marketObj.low, marketObj.high)
    const pct = Math.round((payL / 1000000) * 100)
    return { value, longPct: pct, shortPct: 100 - pct, note: `settle on value ${value}: at least ${marketObj.m} oracle${marketObj.m === 1 ? '' : 's'} must attest it, then the LONG takes ${pct}% of the pot and the SHORT ${100 - pct}%` }
  }
  if (marketObj.predicate === 'marketN') {
    const K = marketObj.outcomes.length
    const i = typeof outcome === 'number' ? outcome : marketObj.outcomes.indexOf(outcome)
    if (!Number.isInteger(i) || i < 0 || i >= K) throw new Error(`unknown outcome '${outcome}' — use an index 0..${K - 1} or one of: ${marketObj.outcomes.join(', ')}`)
    return { outcome: marketObj.outcomes[i], index: i, note: `settle to '${marketObj.outcomes[i]}' (index ${i}): at least ${marketObj.m} oracle${marketObj.m === 1 ? '' : 's'} must attest it, then the whole pot goes to that outcome's owner` }
  }
  const o = outcomeNum(outcome)
  const side = o === marketPred.YES ? 'YES' : 'NO'
  const winner = o === marketPred.YES ? 'the YES owner' : 'the NO owner'
  return { outcome: side, winner, note: `settle to ${side}: at least ${marketObj.m} oracle${marketObj.m === 1 ? '' : 's'} must attest ${side} for this question, and then the whole pot goes to ${winner}` }
}
/** Plan the refund in plain terms: the equal reclaim after the deadline. */
function refundMarket (marketObj) {
  if (marketObj.predicate === 'marketScalar') {
    return { note: `after block ${marketObj.deadline}, the pot splits 50/50 back to the LONG and SHORT owners, no oracle needed` }
  }
  if (marketObj.predicate === 'marketN') {
    const K = marketObj.outcomes.length
    return { note: `after block ${marketObj.deadline}, the pot splits into ${K} equal shares — one back to each of the ${K} outcome owners, no oracle needed` }
  }
  return { note: `after block ${marketObj.deadline}, either party may reclaim their half — the pot splits 50/50 back to the YES and NO owners, no oracle needed` }
}

// ── positionMarket: a market of MANY positions, written before the outcome is known ────────────
// lowers to `descentmarket` (the one counterfeit-proof, quorum-resolved coin) plus `positionv2`
// coins that each commit to the market's IDENTITY. The vocabulary is a genesis (the market's
// unique on-chain id) and, per position, a side and its two parties; the compiler owns the
// descent proof, the quorum, and the identity check.
function positionMarketGuarantees (m, N) {
  return [
    `the outcome is set exactly once, by at least ${m} of ${N} independent oracles — no single oracle, and no one else, can decide it`,
    'the outcome is counterfeit-proof: any coin claiming this market’s outcome must descend from this exact genesis, or it cannot be spent',
    'any number of positions can settle against the market without consuming it — one resolution settles them all',
    'a position can be written before the outcome is known, and only its winner can ever claim its collateral'
  ]
}
/**
 * A market of many positions. spec: { genesis, m?, oraclePanel?, question? }. `genesis` is the
 * market's unique outpoint (the UTXO minting it will spend). Returns the market coin (an OPEN
 * descentmarket), its identity, a plain-English guarantee report, and `writePosition`/`settle`.
 */
function positionMarket (name, spec) {
  if (spec == null || spec.genesis === undefined) throw new Error(`${name}: a position market needs a genesis (its unique on-chain outpoint)`)
  const genesis = Buffer.isBuffer(spec.genesis) ? spec.genesis : Buffer.from(spec.genesis, 'hex')
  if (genesis.length !== 36) throw new Error(`${name}: the genesis must be a 36-byte outpoint`)
  const m = spec.m ?? 2
  const N = (spec.oraclePanel || descentmarketPred.PANEL_N).length
  if (!Number.isInteger(m) || m < 1 || m > N) throw new Error(`${name}: the oracle threshold must be a whole number between 1 and ${N}`)
  const marketId = positionv2Pred.marketId(genesis)
  const script = descentmarketPred.buildScript({ genesis, status: descentmarketPred.OPEN, outcome: 0, m, panelN: spec.oraclePanel })
  return {
    name,
    predicate: 'descentmarket',
    question: spec.question,
    genesis: genesis.toString('hex'),
    marketId: marketId.toString('hex'),
    m,
    coin: { script },
    guarantees: positionMarketGuarantees(m, N)
  }
}
/** Write a position against a market's identity, before the outcome is known. */
function writePosition (marketObj, spec) {
  for (const k of ['side', 'owner', 'counterparty']) {
    if (spec == null || spec[k] === undefined) throw new Error(`a position needs ${k} (side, owner, counterparty)`)
  }
  const side = outcomeNum(spec.side)
  const script = positionv2Pred.buildScript({ market: Buffer.from(marketObj.marketId, 'hex'), side, owner: spec.owner, counterparty: spec.counterparty })
  return {
    predicate: 'positionv2',
    side: side === 1 ? 'YES' : 'NO',
    coin: { script },
    guarantees: [
      `if the market resolves ${side === 1 ? 'YES' : 'NO'}, the owner may take the collateral; otherwise the counterparty may`,
      'it settles only against the genuine market (checked by the market’s identity, committing to its genesis), and only the winner can claim',
      'it does not consume the market, so it settles alongside every other position'
    ]
  }
}
/** Plan a position's settlement in plain terms, given the market's resolved outcome. */
function settlePosition (positionObj, { outcome }) {
  const o = outcomeNum(outcome)
  const won = (o === 1 ? 'YES' : 'NO') === positionObj.side
  return { outcome: o === 1 ? 'YES' : 'NO', winner: won ? 'the owner' : 'the counterparty', note: `the market resolved ${o === 1 ? 'YES' : 'NO'}; this ${positionObj.side} position pays ${won ? 'the owner (they called it right)' : 'the counterparty'}` }
}

module.exports = {
  ledger, transfer, checkLedger, ledgerGuarantees,
  credential, moveStatus, credentialGuarantees, STATUS,
  capability, delegate, capabilityGuarantees,
  game, move, gameGuarantees,
  escrow, escrowGuarantees,
  stream, append, streamGuarantees,
  predictionMarket, settleMarket, refundMarket, predictionMarketGuarantees,
  positionMarket, writePosition, settlePosition, positionMarketGuarantees
}
