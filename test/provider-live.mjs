// provider-live.mjs — prove a real tunnel can be started, discovered and
// stopped through the provider layer, using the actual cloudflared binary.
//
// This runs lib/providers.js directly (not through dsh), so it does not need a
// restart of the live web app.
//
// A quick-tunnel start is *not* guaranteed to succeed: Cloudflare's control
// plane (api.trycloudflare.com) is unreachable from some networks, and when it
// is, cloudflared exits with code 1. That is a legitimate outcome for this test
// as long as the failure is reported as a failure — which is exactly the bug
// this file exists to catch (a failed start used to be reported as
// `https://api.trycloudflare.com`).
//
// Usage: node test/provider-live.mjs

import { startTunnel, stopTunnel, resolveBinary } from '../lib/providers.js'

const log = (line) => console.log('   ' + line)
let ok = true
const expect = (label, condition) => {
  console.log(`  ${condition ? 'ok  ' : 'FAIL'} ${label}`)
  if (!condition) ok = false
}

const binary = resolveBinary('cloudflared', '')
console.log('cloudflared resolved to:', binary || '(not found)')
if (!binary) {
  console.log('SKIP: cloudflared is not installed, nothing to verify')
  process.exit(0)
}

const config = {
  provider: 'cloudflared',
  cloudflared: { path: '', extraArgs: [] },
  tailscale: { path: '', port: 8443, hostname: '' },
  custom: { command: '', args: [] },
}

console.log('\nstarting a quick tunnel against a throwaway port…')

let started = null
let failure = null
try {
  started = await startTunnel({
    id: 'cloudflared',
    config,
    port: 45123, // nothing listens there; we only care that cloudflared comes up
    upstream: 'http://127.0.0.1:45123',
    log,
    timeoutMs: 90_000,
  })
} catch (error) {
  failure = error
}

if (started) {
  console.log('\nSUCCESS PATH')
  console.log('  url     :', started.url)
  console.log('  command :', started.command)
  console.log('  args    :', started.args.join(' '))

  expect('the discovered URL is a real quick-tunnel hostname', /^https:\/\/[a-z0-9]+(?:-[a-z0-9]+){2,}\.trycloudflare\.com$/.test(started.url))
  expect('the control-plane host was not mistaken for a tunnel', started.url !== 'https://api.trycloudflare.com')
  expect('the command is the resolved binary', started.command === binary)
  expect('--no-autoupdate is passed', started.args.includes('--no-autoupdate'))
  expect('the tunnel points at the requested port', started.args.some((a) => a.includes('45123')))

  console.log('\nstopping…')
  await stopTunnel({ id: 'cloudflared', child: started.child, config, log })
  await new Promise((r) => setTimeout(r, 1500))
  expect('the tunnel process is gone', started.child.exitCode !== null || started.child.killed)
} else {
  console.log('\nFAILURE PATH (Cloudflare control plane unreachable from this network)')
  console.log('  reason  :', String(failure && failure.message).slice(0, 200))

  // The important property: a failure must *be* a failure, and must say why.
  expect('the failure surfaced as an error, not a bogus URL', failure instanceof Error)
  expect('the message names the provider', /cloudflared/i.test(String(failure.message)))
  expect('the message includes the tool output so the user can act', /api\.trycloudflare\.com|deadline|timed out/i.test(String(failure.message)))
  expect('no URL was invented', !/^https:\/\//.test(String(failure.message)))
}

console.log(ok ? '\nPROVIDER CHECKS PASSED' : '\nPROVIDER CHECKS FAILED')
process.exit(ok ? 0 : 1)
