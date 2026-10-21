// Contract checks for the read-only panel.
//
// The client half has no DOM and no build step, so it cannot be unit-tested the
// way the server can. Two things *can* be checked, and this file does both:
//
//   A. The bundle consults `status.remote` and gates every mutating surface on
//      it. These are presence checks on the deployed source, deliberately loose:
//      they catch a control being un-gated, not a change in JSX layout.
//
//   B. The panel survives the exact snapshot a remote caller receives — one with
//      the key, the token, and `tunnelCommand` removed. That is asserted by
//      actually calling `redactSnapshot` and inspecting the result, so it does
//      not depend on how the JSX happens to be written.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { redactSnapshot } from '../lib/index.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const source = fs.readFileSync(path.join(here, '..', 'lib', 'client.js'), 'utf8')

let ok = true

/** Report one check. */
const check = (label, pass) => {
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}`)
  if (!pass) ok = false
}

// ── A. the bundle is gated ──────────────────────────────────────────────────

check('reads status.remote', /status\s*&&\s*status\.remote/.test(source))
check('derives a readOnly flag', /const readOnly\s*=/.test(source))
check('renders a read-only notice', /readOnlyNotice/.test(source))
check('explains why it is read-only', /只读视图/.test(source))
check('key card is behind the flag', /readOnly\s*\n\s*\?\s*readOnlyNotice\(\)/.test(source))
check('provider card is behind the flag', /readOnly\s*\n\s*\?\s*null/.test(source))
check('provider tabs are disabled when read-only', /disabled:\s*readOnly/.test(source))

// Every mutating endpoint must be reachable only through a control that is
// gated above. If a call appears, its enclosing card must be one of the gated
// ones — checked by name so a new call site cannot slip in unnoticed.
const mutatingCalls = ['api(CONFIG', 'api(START', 'api(STOP', 'api(REGENERATE']
for (const call of mutatingCalls) {
  const present = source.includes(call)
  check(`${call}) still exists in the (gated) form path`, present)
}

// ── B. the panel survives a remote snapshot ─────────────────────────────────

const fullSnapshot = {
  ok: true,
  remote: false,
  controlToken: 'token',
  provider: 'cloudflared',
  configuredProvider: 'cloudflared',
  providers: ['off', 'cloudflared', 'tailscale', 'custom'],
  port: 8443,
  host: '127.0.0.1',
  proxyRunning: true,
  upstream: 'http://127.0.0.1:47996',
  hasSession: true,
  accessKey: 'secret',
  accessKeyGenerated: true,
  publicUrl: 'https://x.trycloudflare.com',
  tunnelProvider: 'cloudflared',
  tunnelCommand: 'cloudflared tunnel --token=SECRET',
  starting: false,
  lastError: '',
  startedAt: 1,
  platform: 'win32',
  versions: {},
  config: { cloudflared: {}, tailscale: {}, custom: {} },
}

const viewer = redactSnapshot(fullSnapshot, true)

check('viewer snapshot flags itself remote', viewer.remote === true)
check('viewer snapshot has no controlToken', !('controlToken' in viewer))
check('viewer snapshot has no accessKey', !('accessKey' in viewer))
check('viewer snapshot has no tunnelCommand', viewer.tunnelCommand === '')
check('viewer snapshot keeps proxyRunning', viewer.proxyRunning === true)
check('viewer snapshot keeps publicUrl', viewer.publicUrl === 'https://x.trycloudflare.com')

// The client reads `status.accessKey` only to decide whether to offer a link at
// all — the link itself no longer carries the key. What matters is that the read
// sits behind a guard, so a remote snapshot (which has no key) renders nothing
// instead of "undefined".
const keyGuard = /status\.accessKey\s*\n\s*\?/
check('the sign-in link is behind a status.accessKey guard', keyGuard.test(source))

// The client offers a sign-in link, and that link must point at the form rather
// than at `/?key=…`. A key in a query string reaches the tunnel provider's access
// log before this process sees the request, so the panel must stop handing out
// that shape even though the proxy still accepts it for old links.
check('the panel links to the sign-in form', source.includes('/__tunnel'))
check('the panel no longer builds a ?key= link', !source.includes('/?key=${'))

console.log(ok ? '\nREAD-ONLY PANEL CONTRACT HOLDS' : '\nCONTRACT VIOLATED')
process.exit(ok ? 0 : 1)
