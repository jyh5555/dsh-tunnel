// Security regression tests for the viewer/operator split.
//
// Every case here corresponds to a vulnerability that was demonstrated against a
// live tunnel before it was fixed. They are written as attacks, not as unit
// tests of helpers, so a regression fails loudly instead of quietly.
//
// Background: dsh web cannot tell a tunnel visitor from someone at the keyboard,
// because the proxy always dials upstream from `127.0.0.1`. `proxy.js` therefore
// stamps `x-dsh-tunnel-hop` on everything it forwards, and `index.js` treats a
// marked request as remote: no control token, no access key, no mutations.
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import { createProxy, TUNNEL_HOP_HEADER, ACCESS_COOKIE } from '../lib/proxy.js'
import { sanitizeCustomSettings, redactSnapshot, rememberProxy, reclaimProxy, forgetProxy } from '../lib/index.js'

/**
 * Upstream that records what it received and answers with that record.
 * Lets a test see exactly which headers reached dsh web.
 */
async function recordingUpstream() {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: { ...req.headers } })
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{"ok":true}')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, seen, port: server.address().port }
}

async function startProxy(upstreamPort, accessKey = 'k') {
  const proxy = createProxy({
    upstream: `http://127.0.0.1:${upstreamPort}`,
    accessKey: () => accessKey,
    cookie: () => 'dsh-auth-x=y',
  })
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  return { proxy, port: proxy.address().port }
}

/**
 * One request, GET by default.
 * @param {number} port
 * @param {string} path
 * @param {object} [options] - `headers`, or `{ method, headers, body }`.
 */
function request(port, path, options = {}) {
  const opts = options && (options.method || options.body) ? options : { headers: options }
  const { method = 'GET', headers = {}, body } = opts
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
      )
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

/** Get past the key gate and return the cookie a real visitor would hold. */
async function authorisedCookie(port, key = 'k') {
  const res = await request(port, '/?key=' + key)
  assert.equal(res.status, 303, 'the key gate should have accepted the key')
  return res.headers['set-cookie'][0].split(';')[0]
}

// ── P0-1: the hop marker is what separates viewer from operator ──────────────

test('every proxied request carries the hop marker', async () => {
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    const cookie = await authorisedCookie(port)
    await request(port, '/api/session/list', { cookie })
    const forwarded = up.seen.at(-1)
    assert.equal(forwarded.headers[TUNNEL_HOP_HEADER], '1')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('the hop marker cannot be forged by a client', async () => {
  // The whole permission model rests on this: if a visitor could send the
  // header themselves, they would be indistinguishable from the operator.
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    const cookie = await authorisedCookie(port)
    await request(port, '/api/session/list', {
      cookie,
      [TUNNEL_HOP_HEADER]: 'forged-value',
    })
    // Exactly one marker, and it is the proxy's own — never the client's.
    assert.equal(up.seen.at(-1).headers[TUNNEL_HOP_HEADER], '1')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('the marker reaches the upstream on a WebSocket upgrade too', async () => {
  // The upgrade path builds its own header block, so it can drift from the
  // normal one. A viewer whose WebSocket is unmarked would look local.
  const seen = []
  const net = await import('node:net')
  const upstream = net.createServer((socket) => {
    let buffer = ''
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      if (buffer.includes('\r\n\r\n')) {
        seen.push(buffer)
        socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      }
    })
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const { proxy, port } = await startProxy(upstream.address().port)
  try {
    const cookie = await authorisedCookie(port)
    await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1', () => {
        socket.write(
          'GET /api/remote.mux HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
            `Cookie: ${cookie}\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n` +
            'Sec-WebSocket-Version: 13\r\n\r\n',
        )
      })
      socket.on('close', resolve)
      socket.on('error', resolve)
      setTimeout(() => {
        socket.destroy()
        resolve()
      }, 500)
    })
    assert.equal(seen.length, 1, 'the upgrade should have reached the upstream')
    assert.match(seen[0], new RegExp(`${TUNNEL_HOP_HEADER}: 1`, 'i'))
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => upstream.close(r))
  }
})

// ── P0-3: the custom provider is not a remote shell ─────────────────────────

test('sanitizeCustomSettings refuses to install a shell', () => {
  for (const shell of ['cmd', 'cmd.exe', 'powershell', 'pwsh', 'bash', 'sh', '/bin/sh', 'C:\\Windows\\System32\\cmd.exe']) {
    const result = sanitizeCustomSettings({ command: shell }, {})
    assert.equal(result.ok, false, `${shell} should be refused`)
  }
})

test('sanitizeCustomSettings refuses shell metacharacters in arguments', () => {
  for (const arg of ['a; rm -rf /', 'x && y', '$(whoami)', 'a | b', 'a > out', 'a`id`', 'a\nb']) {
    const result = sanitizeCustomSettings({ args: [arg] }, { command: 'bore' })
    assert.equal(result.ok, false, `${JSON.stringify(arg)} should be refused`)
  }
})

test('sanitizeCustomSettings accepts an ordinary tunnel command', () => {
  const result = sanitizeCustomSettings(
    { args: ['local', '{port}', '--to', 'bore.pub'] },
    { command: 'bore', args: [] },
  )
  assert.equal(result.ok, true)
  assert.deepEqual(result.value.args, ['local', '{port}', '--to', 'bore.pub'])
  assert.equal(result.value.command, 'bore', 'the command is kept when not replaced')
})

test('sanitizeCustomSettings ignores a blank command instead of clearing it', () => {
  // Clearing the command over HTTP would be one request away from silently
  // disabling the operator's tunnel.
  const result = sanitizeCustomSettings({ command: '   ' }, { command: 'bore', args: ['x'] })
  assert.equal(result.ok, true)
  assert.equal(result.value.command, 'bore')
})

// ── the access key itself ───────────────────────────────────────────────────

test('the access key cookie is an HMAC, never the key', async () => {
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port, 'super-secret-key')
  try {
    const res = await request(port, '/?key=super-secret-key')
    const cookieValue = res.headers['set-cookie'][0].split(';')[0].split('=')[1]
    assert.notEqual(cookieValue, 'super-secret-key')
    assert.ok(!cookieValue.includes('super-secret-key'))
    assert.equal(decodeURIComponent(res.headers['set-cookie'][0]).includes('super-secret-key'), false)
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('the key is stripped from the URL before the redirect', async () => {
  // Otherwise the browser keeps it in history, and the proxy leaks it onward.
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port, 'k')
  try {
    const res = await request(port, '/some/path?key=k&other=1')
    assert.equal(res.status, 303)
    assert.equal(res.headers.location, '/some/path?other=1')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

// ── P0-1: what a viewer may read ────────────────────────────────────────────

/** A complete snapshot, shaped like the one `apply()` builds. */
function completeSnapshot() {
  return {
    ok: true,
    controlToken: 'control-token-value',
    provider: 'cloudflared',
    configuredProvider: 'cloudflared',
    providers: ['off', 'cloudflared', 'tailscale', 'custom'],
    port: 8443,
    host: '127.0.0.1',
    proxyRunning: true,
    upstream: 'http://127.0.0.1:47996',
    hasSession: true,
    accessKey: 'the-shared-secret',
    accessKeyGenerated: true,
    publicUrl: 'https://example.trycloudflare.com',
    tunnelProvider: 'cloudflared',
    tunnelCommand: 'cloudflared tunnel --url http://127.0.0.1:8443 --token=SECRET-TOKEN',
    starting: false,
    lastError: '',
    startedAt: 1,
    platform: 'win32',
    versions: { node: '24.0.0' },
    config: {
      cloudflared: { path: '', args: ['--token=SECRET-TOKEN'] },
      tailscale: { path: '', port: 8443, hostname: 'my-host' },
      custom: { command: 'bore', args: ['local', '8443', '--secret=SECRET-TOKEN'] },
    },
  }
}

test('a viewer snapshot carries no control token, key, or command line', () => {
  const viewer = redactSnapshot(completeSnapshot(), true)

  // The three fields that turned "holding the link" into code execution.
  assert.equal('controlToken' in viewer, false, 'controlToken must be absent, not blank')
  assert.equal('accessKey' in viewer, false)
  assert.equal('accessKeyGenerated' in viewer, false)
  assert.equal(viewer.tunnelCommand, '')

  // Nothing anywhere in the payload may contain the secret.
  const serialised = JSON.stringify(viewer)
  assert.equal(serialised.includes('SECRET-TOKEN'), false, 'command secrets must not leak')
  assert.equal(serialised.includes('the-shared-secret'), false)
  assert.equal(serialised.includes('control-token-value'), false)
})

test('a viewer snapshot keeps the read-only status the panel needs', () => {
  const viewer = redactSnapshot(completeSnapshot(), true)
  assert.equal(viewer.ok, true)
  assert.equal(viewer.remote, true)
  assert.equal(viewer.provider, 'cloudflared')
  assert.equal(viewer.proxyRunning, true)
  assert.equal(viewer.hasSession, true)
  assert.equal(viewer.publicUrl, 'https://example.trycloudflare.com')
  // Provider paths and ports are harmless and let the panel render honestly.
  assert.equal(viewer.config.tailscale.port, 8443)
  assert.equal(viewer.config.tailscale.hostname, 'my-host')
})

test('a local snapshot is returned untouched', () => {
  // The operator sitting at the machine must keep full control, or the plugin
  // cannot be configured at all.
  const full = completeSnapshot()
  const local = redactSnapshot(full, false)
  assert.equal(local.controlToken, 'control-token-value')
  assert.equal(local.accessKey, 'the-shared-secret')
  // `remote` is explicit on both paths, so the client tests one field rather
  // than inferring "is absent" from "no token".
  assert.equal(local.remote, false)
  assert.notEqual(local, full, 'a copy, so a caller cannot mutate the source')
})

test('redactSnapshot does not mutate its input', () => {
  const full = completeSnapshot()
  redactSnapshot(full, true)
  assert.equal(full.controlToken, 'control-token-value')
  assert.deepEqual(full.config.custom.args, ['local', '8443', '--secret=SECRET-TOKEN'])
})

// ── the Secure cookie attribute ─────────────────────────────────────────────
// A browser silently drops a `Secure` cookie delivered over plain HTTP, so a
// deployment on `http://<vps-ip>:<port>` would sign in, lose the cookie, and
// bounce back to the form — indistinguishable from a wrong password. The
// attribute therefore follows the browser's origin, which a reverse proxy states
// in `X-Forwarded-Proto`.

/** POST the key to the sign-in form and return the response. */
function signIn(port, extraHeaders = {}) {
  const body = 'key=k'
  return request(port, '/__tunnel', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': String(Buffer.byteLength(body)),
      ...extraHeaders,
    },
    body,
  })
}

test('the session cookie is Secure by default', async () => {
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    const res = await signIn(port)
    assert.equal(res.status, 303)
    const cookie = res.headers['set-cookie'][0]
    assert.match(cookie, /; Secure;/)
    assert.match(cookie, /HttpOnly/)
    assert.match(cookie, /SameSite=Lax/)
    assert.match(cookie, /Max-Age=43200/)
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('the session cookie drops Secure when the origin is http', async () => {
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    const res = await signIn(port, { 'x-forwarded-proto': 'http' })
    assert.equal(res.status, 303)
    const cookie = res.headers['set-cookie'][0]
    assert.equal(/; Secure;/.test(cookie), false, 'Secure must be omitted over plain http')
    // The other protections are unaffected.
    assert.match(cookie, /HttpOnly/)
    assert.match(cookie, /SameSite=Lax/)
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('a chained X-Forwarded-Proto is read from its first element', async () => {
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    // "https, http" means the browser spoke https to the nearest hop.
    const res = await signIn(port, { 'x-forwarded-proto': 'https, http' })
    assert.match(res.headers['set-cookie'][0], /; Secure;/, 'the nearest hop decides')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('the legacy ?key= path sets the same cookie as the form', async () => {
  // Two ways in must not produce two different session shapes.
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    const viaQuery = await request(port, '/?key=k')
    const viaForm = await signIn(port)
    const strip = (c) => c.split(';').map((s) => s.trim()).filter((s) => s !== 'Path=/')
    assert.deepEqual(strip(viaQuery.headers['set-cookie'][0]), strip(viaForm.headers['set-cookie'][0]))
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

// ── P1: failed-attempt throttle ─────────────────────────────────────────────

test('repeated wrong keys are throttled with 429 and Retry-After', async () => {
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port)
  try {
    // The limit is 10 failures per minute; 11 requests guarantees a trip.
    let sawThrottle = false
    for (let i = 0; i < 12; i++) {
      const res = await request(port, '/?key=wrong-' + i)
      if (res.status === 429) {
        sawThrottle = true
        assert.equal(res.headers['retry-after'], '60')
        break
      }
      assert.equal(res.status, 401, `attempt ${i} should have been a plain 401`)
    }
    assert.equal(sawThrottle, true, 'the throttle should have engaged within 12 attempts')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('a successful key clears the failure count', async () => {
  // Otherwise one fat-fingered afternoon would lock the owner out for the rest
  // of the minute even after they got it right.
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port, 'right-key')
  try {
    for (let i = 0; i < 9; i++) await request(port, '/?key=wrong-' + i)
    const good = await request(port, '/?key=right-key')
    assert.equal(good.status, 303, 'the correct key must be accepted before the limit')
    // The counter is now clear, so another 9 failures must not trip it.
    let throttledEarly = false
    for (let i = 0; i < 9; i++) {
      const res = await request(port, '/?key=again-' + i)
      if (res.status === 429) throttledEarly = true
    }
    assert.equal(throttledEarly, false, 'the count should have been reset by the success')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

test('a throttled client is refused before the key is even compared', async () => {
  // The point of the throttle is to cost an attacker something. If a correct
  // key still worked while throttled, guessing would remain free.
  const up = await recordingUpstream()
  const { proxy, port } = await startProxy(up.port, 'right-key')
  try {
    for (let i = 0; i < 11; i++) await request(port, '/?key=wrong-' + i)
    const res = await request(port, '/?key=right-key')
    assert.equal(res.status, 429, 'even the correct key waits out the window')
  } finally {
    await new Promise((r) => proxy.close(r))
    await new Promise((r) => up.server.close(r))
  }
})

// ── the port a reloaded plugin must be able to reclaim ──────────────────────
// Observed on a live install: reloading the plugin left the previous instance's
// listener bound, the new instance failed with EADDRINUSE against its own port,
// and the *old* proxy kept answering with the *old* access key. From the outside
// that reads as "the key is wrong", which is the worst possible symptom.

test('a leftover listener can be reclaimed by the next instance', async () => {
  const up = await recordingUpstream()

  // The previous instance's listener, still bound and still holding connections.
  const stale = createProxy({ upstream: `http://127.0.0.1:${up.port}`, accessKey: () => 'old' })
  await new Promise((resolve) => stale.listen(0, '127.0.0.1', resolve))
  const port = stale.address().port
  rememberProxy(port, stale)

  // A long-lived connection, exactly like the WebSocket this proxy relays.
  const keepAlive = await authorisedCookie(port, 'old')
  const held = http.request({ host: '127.0.0.1', port, path: '/api/remote.mux', headers: { cookie: keepAlive } })
  held.on('error', () => {})
  held.end()

  try {
    assert.equal(reclaimProxy(port), true, 'the registry should have had it')

    // The port must now be bindable — this is the whole point.
    const fresh = createProxy({ upstream: `http://127.0.0.1:${up.port}`, accessKey: () => 'new' })
    await new Promise((resolve, reject) => {
      fresh.once('error', reject)
      fresh.listen(port, '127.0.0.1', resolve)
    })

    // And it answers with the new key, not the leaked old one.
    const res = await request(port, '/?key=new')
    assert.equal(res.status, 303, 'the new instance must serve the new key')
    assert.equal((await request(port, '/?key=old')).status, 401, 'the old key must be gone')

    await new Promise((r) => fresh.close(r))
    forgetProxy(port, fresh)
  } finally {
    await new Promise((r) => up.server.close(r))
  }
})

test('reclaiming a port this plugin never held is a no-op', () => {
  // Closing a socket we did not open would mean killing an unrelated service.
  // "Port busy" is a far better outcome than that.
  assert.equal(reclaimProxy(1), false)
  assert.equal(reclaimProxy(65535), false)
})

test('forgetting only drops the server it was told about', async () => {
  const up = await recordingUpstream()
  const server = createProxy({ upstream: `http://127.0.0.1:${up.port}`, accessKey: () => 'k' })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  try {
    rememberProxy(port, server)
    // A different server object must not evict the recorded one.
    forgetProxy(port, { close() {} })
    assert.equal(reclaimProxy(port), true, 'the real one was still registered')
    assert.equal(reclaimProxy(port), false, 'and is gone now')
  } finally {
    await new Promise((r) => up.server.close(r))
  }
})
