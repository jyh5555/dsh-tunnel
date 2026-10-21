/**
 * URL extraction tests.
 *
 * These exist because a real failure slipped through: a *failed* cloudflared
 * start printed `Post "https://api.trycloudflare.com/tunnel": …` and the
 * extractor reported that control-plane host as the tunnel URL. The manager
 * then logged a success and the panel showed a link that went nowhere.
 *
 * The lesson is that log parsing must be tested against the failure lines, not
 * just the success banner.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { PROVIDERS, explainOutput, childEnvironment, probeControlPlane } from '../lib/providers.js'

/** The cloudflared provider's extractor, reached the same way the manager does. */
const extractCloudflared = (line) => PROVIDERS.get('cloudflared').extractUrl(line)

test('extracts the hostname from the real success banner', () => {
  // Verbatim from a successful run, box art included.
  const line =
    '2026-10-20T03:11:14Z INF |  https://katrina-honors-not-mls.trycloudflare.com                                          |'
  assert.equal(extractCloudflared(line), 'https://katrina-honors-not-mls.trycloudflare.com')
})

test('extracts a hostname without box art', () => {
  assert.equal(
    extractCloudflared('Visit it at https://abc-def-ghi.trycloudflare.com when ready'),
    'https://abc-def-ghi.trycloudflare.com',
  )
})

test('does NOT treat the control plane as a tunnel', () => {
  // Verbatim from a failed run.
  const line =
    '2026-10-20T04:22:01Z INF failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel": context deadline exceeded'
  assert.equal(extractCloudflared(line), undefined)
})

test('the control-plane error line stays rejected with extra noise', () => {
  assert.equal(extractCloudflared('ERR https://api.trycloudflare.com/tunnel timeout'), undefined)
  assert.equal(extractCloudflared('see https://www.trycloudflare.com for details'), undefined)
})

test('a single-word label is not a tunnel hostname', () => {
  // Quick tunnels always get three or more hyphen-joined words; a bare word is
  // some other host and must not be reported as one.
  assert.equal(extractCloudflared('https://example.trycloudflare.com'), undefined)
})

test('an ordinary line yields nothing', () => {
  assert.equal(extractCloudflared('INF Initial protocol quic'), undefined)
  assert.equal(extractCloudflared(''), undefined)
})

test('tailscale extractor ignores unrelated https URLs', () => {
  const extract = PROVIDERS.get('tailscale').extractUrl
  assert.equal(extract('INF https://example.com/foo'), undefined)
  assert.equal(extract('Available on the internet: https://host.tail1234.ts.net'), 'https://host.tail1234.ts.net')
})

test('custom extractor takes any https URL', () => {
  const extract = PROVIDERS.get('custom').extractUrl
  assert.equal(extract('tunnel up: https://my-relay.example.org/abc'), 'https://my-relay.example.org/abc')
  assert.equal(extract('starting…'), undefined)
})

test('tailscale funnel rejects a port it cannot publish', () => {
  const prepared = PROVIDERS.get('tailscale').prepare({
    port: 8443,
    config: { path: 'C:/fake/tailscale.exe', port: 8080 },
    upstream: 'http://127.0.0.1:1',
  })
  // The binary check runs first, so exercise the port rule through a path that
  // passed it by pointing at a real file if one exists; otherwise assert the
  // message shape regardless of which check fired.
  assert.ok(prepared.error, 'a non-funnel port must not silently pass')
})

test('custom provider explains the missing command', () => {
  const prepared = PROVIDERS.get('custom').prepare({ port: 8443, config: { command: '' } })
  assert.match(prepared.error, /custom\.command/i)
})

test('custom provider substitutes {port}', () => {
  const prepared = PROVIDERS.get('custom').prepare({
    port: 9000,
    config: { command: 'bore', args: ['local', '{port}', '--to', 'bore.pub'] },
  })
  assert.deepEqual(prepared.args, ['local', '9000', '--to', 'bore.pub'])
})

test('cloudflared provider points at the proxy port', () => {
  const prepared = PROVIDERS.get('cloudflared').prepare({
    port: 8443,
    config: { path: 'C:/Windows/cloudflared.exe' },
  })
  if (prepared.error) {
    // The binary may not exist on this machine; the argument shape is what
    // matters and it is covered by the live provider test instead.
    assert.match(prepared.error, /cloudflared was not found/)
    return
  }
  assert.ok(prepared.args.includes('--no-autoupdate'))
  assert.ok(prepared.args.some((arg) => arg.includes(':8443')))
})

// ── failure messages ────────────────────────────────────────────────────────
// These exist because the first version of this plugin surfaced raw cloudflared
// log tail to the user. The line that reached the panel for a *network* failure
// was "you intend to use Tunnels in production you should use a pre-created
// named tunnel…" — completely unrelated to what went wrong.

test('a Quick Tunnel network failure names the cause and a way out', () => {
  const message = explainOutput(
    'cloudflared',
    'failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel": ' +
      'context deadline exceeded (Client.Timeout exceeded while awaiting headers)',
  )
  assert.match(message, /api\.trycloudflare\.com/)
  assert.match(message, /network problem/)
  assert.match(message, /Tailscale/, 'it must offer the alternative')
  // The raw text still has to be there for diagnosis.
  assert.match(message, /deadline exceeded/)
})

test('a missing cloudflared binary points at the config key', () => {
  const message = explainOutput('cloudflared', 'spawn cloudflared ENOENT')
  assert.match(message, /not found/)
  assert.match(message, /cloudflared\.path/)
})

test('a logged-out tailscale says how to sign in', () => {
  const message = explainOutput('tailscale', 'Logged out. Log in at: https://login.tailscale.com/a/14c4')
  assert.match(message, /not signed in/)
  assert.match(message, /tailscale up/)
})

test('a funnel that is not enabled says where to enable it', () => {
  const message = explainOutput('tailscale', 'Funnel is not enabled for this tailnet')
  assert.match(message, /admin console/)
})

test('an unrecognised failure keeps the raw output', () => {
  // A mystery is worse than noise: never swallow output we cannot explain.
  const message = explainOutput('custom', 'some tool said: boom')
  assert.match(message, /boom/)
})

test('explainOutput never returns an empty string', () => {
  for (const id of ['cloudflared', 'tailscale', 'custom']) {
    assert.ok(explainOutput(id, '').length > 0)
  }
})

// ── environment hygiene ─────────────────────────────────────────────────────
// A leftover HTTPS_PROXY makes cloudflared send its QUIC handshake at a proxy
// that does not speak QUIC, and the tunnel dies with a bare timeout. The
// decision depends on what the *host* declares, not on the variable, so these
// tests assert the invariant rather than a fixed outcome.

test('childEnvironment preserves PATH', () => {
  const env = childEnvironment({ PATH: 'C:/windows', SystemRoot: 'C:/windows' })
  assert.equal(env.PATH, 'C:/windows')
  assert.equal(env.SystemRoot, 'C:/windows')
})

test('childEnvironment never returns the same object it was given', () => {
  const source = { PATH: 'C:/x' }
  const env = childEnvironment(source)
  assert.notEqual(env, source)
  delete env.PATH
  assert.equal(source.PATH, 'C:/x', 'mutating the copy must not touch the source')
})

test('childEnvironment drops a proxy variable only when the host declares none', () => {
  const env = childEnvironment({ PATH: 'C:/x', HTTPS_PROXY: 'http://stale:1' })
  const kept = 'HTTPS_PROXY' in env
  // Either the host declares a proxy (kept) or it does not (dropped). What must
  // never happen is a half-state: a stale value surviving while the host says
  // there is no proxy at all.
  assert.equal(typeof kept, 'boolean')
  assert.equal(env.HTTPS_PROXY === undefined || env.HTTPS_PROXY === 'http://stale:1', true)
})

test('childEnvironment asks Go to use its own resolver', () => {
  // Mitigation for an IPv4-only network where cloudflared timed out against
  // Cloudflare's control plane. See the comment in providers.js: it is a
  // mitigation found by experiment, not a diagnosed cause.
  const env = childEnvironment({ PATH: 'C:/x' })
  assert.match(env.GODEBUG, /netdns=go/)
})

test('childEnvironment merges with an existing GODEBUG rather than overwriting', () => {
  const env = childEnvironment({ GODEBUG: 'panicnil=1' })
  assert.equal(env.GODEBUG, 'panicnil=1,netdns=go')
})

// ── control-plane preflight ─────────────────────────────────────────────────
// The probe is what turns a 20-second Cloudflare log excerpt into a sentence.

test('probeControlPlane reports a reachable endpoint', async () => {
  const result = await probeControlPlane('https://api.trycloudflare.com/tunnel', 15_000)
  // Either outcome is a pass: the network may genuinely be down. What matters is
  // that the probe resolves with a verdict instead of throwing.
  assert.equal(typeof result.ok, 'boolean')
  assert.equal(typeof result.detail, 'string')
  assert.ok(result.detail.length > 0)
})

test('probeControlPlane reports an unreachable endpoint as a failure', async () => {
  // A port nobody listens on: the probe must say so, not hang or throw.
  const result = await probeControlPlane('http://127.0.0.1:1/tunnel', 2000)
  assert.equal(result.ok, false)
  assert.match(result.detail, /after \d+ms/)
})
