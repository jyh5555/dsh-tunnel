// integration.mjs — boot the plugin's host half against a mock ctx and a fake
// upstream, then exercise the control routes end to end.
//
// This is the only way to verify the plugin without restarting the live dsh web
// (which would drop the session that is running the test). Everything exercised
// here is real plugin code: lib/index.js, lib/proxy.js, lib/providers.js.
//
// Usage: node test/integration.mjs

import http from 'node:http'
import { EventEmitter } from 'node:events'
import assert from 'node:assert/strict'

// ── fake upstream: stands in for dsh web ──────────────────────────────────
let sawHost = ''
const upstream = http.createServer((req, res) => {
  sawHost = String(req.headers.host || '')
  res.writeHead(200, { 'content-type': 'text/plain' })
  res.end('upstream')
})
await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
const upstreamOrigin = `http://127.0.0.1:${upstream.address().port}`

// ── mock ctx ──────────────────────────────────────────────────────────────
const registered = []
const disposers = []

const mockCtx = {
  logger: { info: (line) => console.log('   plugin:', line) },
  effect(factory) {
    const dispose = factory()
    if (typeof dispose === 'function') disposers.push(dispose)
    return () => {}
  },
  get(name) {
    if (name === 'webServer') {
      return {
        register(route) {
          registered.push(route)
          return () => {
            const index = registered.indexOf(route)
            if (index >= 0) registered.splice(index, 1)
          }
        },
        getOrigin: () => upstreamOrigin,
      }
    }
    if (name === 'connection') {
      return {
        // The fence passes: this test is about the plugin, not about dsh web.
        requestRejection: () => undefined,
        authenticatedUrl: (base) => `${base}?token=stub`,
      }
    }
    return undefined
  },
}

// The cookie exchange goes through fetch; the fake upstream does not mint
// cookies, so answer that one URL locally to exercise the acquisition path.
const realFetch = globalThis.fetch
globalThis.fetch = async (input, init) => {
  if (String(input).includes('token=stub')) {
    return new Response('', {
      status: 303,
      headers: { 'set-cookie': 'dsh-auth-test=abc123; Path=/; HttpOnly' },
    })
  }
  return realFetch(input, init)
}

// ── load the plugin from this repo ────────────────────────────────────────
// Deliberately the source next door, not an installed copy: a repo test should
// exercise the code being committed. (An earlier version pointed at the author's
// `node_modules`, which of course only worked on that one machine.)
const plugin = await import(new URL('../lib/index.js', import.meta.url).href)

console.log('plugin exports:', ['Config', 'apply', 'inject', 'name'].filter((k) => plugin[k] !== undefined).join(', '))
console.log('inject:', JSON.stringify(plugin.inject))
assert.ok(plugin.apply, 'plugin must export apply')
assert.ok(plugin.Config, 'plugin must export Config for the loader to validate the patch layer')
assert.ok(plugin.inject.includes('webServer'), 'plugin must inject webServer')

const config = {
  provider: 'off',
  port: 0, // 0 = OS picks, so the test never collides with a real tunnel
  host: '127.0.0.1',
  accessKey: 'test-key',
  cloudflared: { path: '', extraArgs: [] },
  tailscale: { path: '', port: 8443, hostname: '' },
  custom: { command: '', args: [] },
}

plugin.apply(mockCtx, config)

const route = (path) => registered.find((r) => r.path === path)
for (const path of [
  '/dsh-tunnel/status',
  '/dsh-tunnel/start',
  '/dsh-tunnel/stop',
  '/dsh-tunnel/config',
  '/dsh-tunnel/key',
]) {
  assert.ok(route(path), `route ${path} was not registered`)
}
console.log('routes:', registered.map((r) => r.path).join(' '))

/** Invoke a route handler with minimal IncomingMessage/ServerResponse stand-ins. */
function call(path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const message = Object.assign(new EventEmitter(), { method, url: path, headers })
    const res = Object.assign(new EventEmitter(), { statusCode: 200, headers: {} })
    const out = []
    res.writeHead = (status, hdrs) => {
      res.statusCode = status
      if (hdrs) Object.assign(res.headers, hdrs)
      return res
    }
    res.write = (chunk) => {
      out.push(Buffer.from(chunk))
      return true
    }
    res.end = (chunk) => {
      if (chunk) out.push(Buffer.from(chunk))
      resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(out).toString('utf8') })
    }
    const chunks = body ? [Buffer.from(JSON.stringify(body))] : []
    process.nextTick(() => {
      for (const chunk of chunks) message.emit('data', chunk)
      message.emit('end')
    })
    try {
      route(path).handler(message, res)
    } catch (error) {
      reject(error)
    }
  })
}

const failures = []
const check = (label, condition, detail) => {
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    console.log(`  FAIL ${label}${detail ? ' — ' + detail : ''}`)
    failures.push(label)
  }
}

// ── 1. status is readable before a control token exists ──────────────────
const first = await call('/dsh-tunnel/status')
check('GET /status without token returns 200', first.status === 200, `got ${first.status}`)
let snapshot = {}
try {
  snapshot = JSON.parse(first.body)
} catch {
  /* reported by the check below */
}
check('status body is JSON with a control token', Boolean(snapshot.controlToken))
check('status reports the configured provider', snapshot.provider === 'off', String(snapshot.provider))
check('status reports the configured access key', snapshot.accessKey === 'test-key', String(snapshot.accessKey))
check('status exposes provider config for the form', Boolean(snapshot.config && snapshot.config.cloudflared))

// ── 2. mutations are refused without the token ───────────────────────────
const denied = await call('/dsh-tunnel/key', { method: 'POST' })
check('POST /key without token is 403', denied.status === 403, `got ${denied.status}`)

// ── 3. mutations are accepted with the token ─────────────────────────────
const rotated = await call('/dsh-tunnel/key', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': snapshot.controlToken },
})
check('POST /key with token is 200', rotated.status === 200, `got ${rotated.status}`)
let afterRotate = {}
try {
  afterRotate = JSON.parse(rotated.body)
} catch {
  /* checked below */
}
check('key actually rotates', afterRotate.accessKey && afterRotate.accessKey !== 'test-key')

// ── 4. starting an unconfigured provider explains what is missing ────────
const customNoCommand = await call('/dsh-tunnel/start', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': snapshot.controlToken },
  body: { provider: 'custom' },
})
let startBody = {}
try {
  startBody = JSON.parse(customNoCommand.body)
} catch {
  /* checked below */
}
check('start custom without a command fails with 500', customNoCommand.status === 500, `got ${customNoCommand.status}`)
check('the error names the missing setting', /custom\.command/i.test(startBody.lastError || ''), startBody.lastError)

// ── 5. unknown provider is rejected ──────────────────────────────────────
const unknown = await call('/dsh-tunnel/start', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': snapshot.controlToken },
  body: { provider: 'nope' },
})
check('unknown provider is 400', unknown.status === 400, `got ${unknown.status}`)

// ── 6. stop is safe when nothing is running ──────────────────────────────
const stopped = await call('/dsh-tunnel/stop', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': snapshot.controlToken },
})
check('POST /stop when idle is 200', stopped.status === 200, `got ${stopped.status}`)

// ── 7. config accepts provider settings ──────────────────────────────────
const saved = await call('/dsh-tunnel/config', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': snapshot.controlToken },
  body: { custom: { command: 'bore', args: ['local', '{port}'] } },
})
check('POST /config is 200', saved.status === 200, `got ${saved.status}`)
let savedBody = {}
try {
  savedBody = JSON.parse(saved.body)
} catch {
  /* checked below */
}
check(
  'config change is reflected in the snapshot',
  savedBody.config && savedBody.config.custom && savedBody.config.custom.command === 'bore',
  JSON.stringify(savedBody.config && savedBody.config.custom),
)

// ── 8. the viewer/operator split, through the real handlers ───────────────
// The hop marker is what `proxy.js` stamps on forwarded requests. Sending it
// here simulates a visitor who reached the plugin through the tunnel.

const asViewer = { 'x-dsh-tunnel-hop': '1' }

const viewerStatus = await call('/dsh-tunnel/status', { headers: asViewer })
let viewerSnapshot = {}
try {
  viewerSnapshot = JSON.parse(viewerStatus.body)
} catch {
  /* checked below */
}
check('viewer can read status', viewerStatus.status === 200, `got ${viewerStatus.status}`)
check('viewer snapshot says remote', viewerSnapshot.remote === true, String(viewerSnapshot.remote))
check('viewer gets NO control token', viewerSnapshot.controlToken === undefined, String(viewerSnapshot.controlToken))
check('viewer gets NO access key', viewerSnapshot.accessKey === undefined, String(viewerSnapshot.accessKey))
check(
  'viewer still sees the read-only status',
  viewerSnapshot.proxyRunning === false && viewerSnapshot.providers.length === 4,
)

// Every mutation must be refused even though the viewer replays the real token.
const realToken = snapshot.controlToken
for (const [label, path, body] of [
  ['/key', '/dsh-tunnel/key', undefined],
  ['/stop', '/dsh-tunnel/stop', undefined],
  ['/start', '/dsh-tunnel/start', { provider: 'off' }],
  ['/config', '/dsh-tunnel/config', { custom: { command: 'bore', args: [] } }],
]) {
  const deniedRemote = await call(path, {
    method: 'POST',
    headers: { ...asViewer, 'x-dsh-tunnel-token': realToken },
    body,
  })
  check(`viewer cannot POST ${label} even with the token`, deniedRemote.status === 403, `got ${deniedRemote.status}`)
}

// The custom provider refuses shells and metacharacters when a local operator
// tries, so a compromised token on the host is still not a shell.
const shellRefused = await call('/dsh-tunnel/config', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': realToken },
  body: { custom: { command: 'cmd', args: ['/c', 'echo hi'] } },
})
check('a shell command is refused even locally', shellRefused.status === 400, `got ${shellRefused.status}`)

const metaRefused = await call('/dsh-tunnel/config', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': realToken },
  body: { custom: { args: ['a; rm -rf /'] } },
})
check('shell metacharacters are refused even locally', metaRefused.status === 400, `got ${metaRefused.status}`)

// And the legitimate case still works, or the feature would be gone.
const plainOk = await call('/dsh-tunnel/config', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': realToken },
  body: { custom: { command: 'bore', args: ['local', '{port}'] } },
})
check('an ordinary custom command is still accepted', plainOk.status === 200, `got ${plainOk.status}`)

// ── teardown ─────────────────────────────────────────────────────────────
for (const dispose of disposers) {
  try {
    await dispose()
  } catch {
    /* best effort */
  }
}
globalThis.fetch = realFetch
await new Promise((resolve) => upstream.close(resolve))

if (failures.length) {
  console.log(`\n${failures.length} CHECK(S) FAILED`)
  process.exit(1)
}
console.log('\nALL INTEGRATION CHECKS PASSED')
process.exit(0)
