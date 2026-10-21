// Confirm the live bundle wires exactly the entry points we intend.
//
// Two notes on the assertions:
//
//   1. The settings entry goes through a shared helper that writes
//      `{ name: slot, ...options }`, so the literal `name: 'settings.section'`
//      never appears in the bundle. Asserting on the slot name as a string is
//      the correct check — the first version of this file looked for the literal
//      and produced a false failure.
//
//   2. `plugins.item` is deliberately NOT registered any more. That slot is for
//      plugins with a small config form: the Plugins page renders the entry
//      inline, so a full panel there blows the page up. The tunnel is reached
//      from the sidebar (or Settings), so this script now asserts its absence —
//      a regression that re-adds it should fail loudly.
import fs from 'node:fs'

// Needs a running `dsh web` and the cookie a local browser would hold:
//
//   DSH_URL=http://127.0.0.1:PORT
//   DSH_COOKIE_FILE=/path/to/harness-cookie.json     (or DSH_COOKIE inline)
//
// Skips itself when those are absent, so `npm run test:all` on a fresh clone
// does not fail over a missing local file.
const up = (process.env.DSH_URL || '').replace(/\/$/, '')
const cookie = process.env.DSH_COOKIE
  ? process.env.DSH_COOKIE
  : process.env.DSH_COOKIE_FILE && fs.existsSync(process.env.DSH_COOKIE_FILE)
    ? JSON.parse(fs.readFileSync(process.env.DSH_COOKIE_FILE, 'utf8')).cookie
    : ''

if (!up || !cookie) {
  console.log('DSH_URL / DSH_COOKIE not set; skipping the live entry-point check')
  process.exit(0)
}

const html = await (await fetch(up + '/', { headers: { cookie } })).text()
const urls = [...html.matchAll(/plugins\/\?\?[^"'<>]+/g)].map((m) => m[0].replace(/&amp;/g, '&'))
const hit = urls.find((u) => u.includes('dsh-tunnel'))
const bundle = await (await fetch(up + '/' + hit, { headers: { cookie } })).text()

/**
 * Registration calls only — comments mention the slot names too, and a comment
 * saying "we do not register plugins.item" must not read as a registration.
 */
const registrations = [
  ...bundle.matchAll(/(?:safe\(\s*|slots\.inject\()'([^']+)'/g),
].map((m) => m[1])

const registered = (slot) => registrations.includes(slot)

const checks = [
  ['sidebar row: main panel registered', registered('main')],
  ['sidebar glyph: panellist registered', registered('sidebar.panellist')],
  ['settings section registered', registered('settings.section')],
  ['plugins page entry NOT registered', !registered('plugins.item')],
  ['shared safe() helper present', /const safe = \(slot, options, component\)/.test(bundle)],
  ['label is 隧道', /label: \(\) => '隧道'/.test(bundle)],
  ['Chinese copy present', (bundle.match(/[\u4e00-\u9fa5]/g) || []).length > 500],
]

let ok = true
for (const [label, pass] of checks) {
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}`)
  if (!pass) ok = false
}

console.log('\nregistrations found: ' + JSON.stringify(registrations))
console.log(ok ? '\nENTRY POINTS ARE AS INTENDED' : '\nSOMETHING IS MISSING')
process.exit(ok ? 0 : 1)
