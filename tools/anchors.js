#!/usr/bin/env node
'use strict'

const fs = require('fs')
const path = require('path')

// Cross-references into a numbered document break every time the numbering
// changes, and they break silently — a dead anchor scrolls to the top of the
// page rather than erroring. This has now happened three times while reordering
// pitfalls.md by cost.
//
// The number is not the identity of a section; the title is. So repair by
// matching on the title and rewriting whatever number currently precedes it.
// `--fix` rewrites, otherwise it reports and exits non-zero.

const root = path.join(__dirname, '..')

// Auto-discover rather than maintain a list by hand: every Markdown file in the
// repo root and docs/ is checked. A new doc is validated the moment it exists,
// which is how docs/clauses.md and docs/index.md joined without a code change.
const DOCS = [
  ...fs.readdirSync(root).filter(f => f.endsWith('.md')),
  ...fs.readdirSync(path.join(root, 'docs')).filter(f => f.endsWith('.md')).map(f => 'docs/' + f)
]

// GitHub's rule: lowercase, drop anything that is not alphanumeric, space,
// hyphen or UNDERSCORE, then turn EACH space into a hyphen. Two details this
// got wrong in turn, both silently:
//   - runs are not collapsed, so a removed em-dash between two words leaves `--`
//   - underscores are KEPT, so `OP_CODESEPARATOR` slugs as `op_codeseparator`
const slug = (text) =>
  text.toLowerCase().replace(/[^a-z0-9 _\-]/g, '').trim().replace(/ /g, '-')

/** Every heading in a file: its full anchor, and its anchor with any leading number stripped. */
function headings (file) {
  const out = []
  const src = fs.readFileSync(path.join(root, file), 'utf8')
  for (const line of src.split('\n')) {
    const m = line.match(/^#{1,6} (.*)$/)
    if (!m) continue
    const full = slug(m[1])
    out.push({ title: m[1], anchor: '#' + full, bare: '#' + full.replace(/^\d+-/, '') })
  }
  return out
}

function main () {
  const fix = process.argv.includes('--fix')
  const index = Object.fromEntries(DOCS.map(f => [f, headings(f)]))
  let broken = 0
  let repaired = 0
  let mislabelled = 0

  for (const file of DOCS) {
    const p = path.join(root, file)
    let src = fs.readFileSync(p, 'utf8')
    const before = src

    src = src.replace(/([A-Za-z0-9_\-]+\.md)(#[a-z0-9_\-]+)/g, (whole, target, anchor) => {
      const key = DOCS.find(d => path.basename(d) === target)
      if (!key || !index[key]) return whole
      if (index[key].some(h => h.anchor === anchor)) return whole   // already good

      // Same section, different number?
      const bare = anchor.replace(/^#\d+-/, '#')
      const hit = index[key].find(h => h.bare === bare)
      if (hit) {
        repaired++
        return target + hit.anchor
      }
      broken++
      console.log(`  BROKEN  ${file} -> ${target}${anchor}`)
      return whole
    })

    // A second, quieter kind of rot: the anchor resolves but the visible link
    // TEXT still names the old number. `[pitfall 2](…#9-…)` scrolls to the right
    // place and reads as a lie. The number after `#` is the truth; rewrite the
    // label to match it. This class survived every anchor repair until it was
    // checked for directly — four labels were stale across the docs.
    src = src.replace(/\[(pitfall|clause|predicate) (\d+)\]\(([^)]*)#(\d+)-/gi,
      (whole, kind, label, target, num) => {
        if (label === num) return whole
        mislabelled++
        console.log(`  MISLABELLED  ${file}: "${kind} ${label}" -> #${num}`)
        return `[${kind} ${num}](${target}#${num}-`
      })

    if (fix && src !== before) fs.writeFileSync(p, src)
  }

  if (repaired) console.log(`${fix ? 'repaired' : 'repairable'}: ${repaired} anchor(s)`)
  if (broken) console.log(`unresolvable: ${broken} anchor(s)`)
  if (mislabelled) console.log(`${fix ? 'relabelled' : 'mislabelled'}: ${mislabelled} link(s)`)
  if (!repaired && !broken && !mislabelled) console.log('all cross-references resolve')
  if (broken || ((repaired || mislabelled) && !fix)) process.exit(1)
}

main()
