/**
 * Unit tests for the pure parts: path handling, cookie parsing, the access key
 * gate, header rewriting, and the WebSocket upgrade relay.
 *
 * Run with `node --test`. No framework, because the package has no runtime
 * dependencies and adding one just for tests would contradict that.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'

import { createProxy, upstreamPath, parseCookies, ACCESS_COOKIE } from '../lib/proxy.js'

test('upstreamPath keeps the doubled question mark that plugin bundles use', () => {
  // This is the bug that made the whole front end fail to boot: WHATWG URL
  // splits at the first `?`, so `/plugins/??a,b` silently became `/plugins/`.
  assert.equal(
    upstreamPath('/plugins/??dsh-x/client.js,@deepseek-ai/dsh-y/client.js&rev=abc'),
    '/plugins/??dsh-x/client.js,@deepseek-ai/dsh-y/client.js&rev=abc',
  )
})

test('upstreamPath passes normal paths and queries through unchanged', () => {
  assert.equal(upstreamPath('/'), '/')
  assert.equal(upstreamPath('/api/session?x=1&y=2'), '/api/session?x=1&y=2')
  assert.equal(upstreamPath(''), '/')
  assert.equal(upstreamPath('relative'), '/relative')
})

test('upstreamPath handles absolute-form request lines', () => {
  assert.equal(upstreamPath('http://example.test/a/b?c=1'), '/a/b?c=1')
})

test('parseCookies ignores malformed pairs', () => {
  assert.deepEqual(parseCookies('a=1; b=2'), { a: '1', b: '2' })
  assert.deepEqual(parseCookies('novalue; c=3'), { c: '3' })
  assert.deepEqual(parseCookies(''), {})
  assert.deepEqual(parseCookies(undefined), {})
})

/** Start a proxy in front of a fake upstream; return both plus a closer. */
async function harness({ accessKey = 'k', upstreamHandler, cookie = 'dsh-auth-x=y' } = {}) {
  const upstream = http.createServer(upstreamHandler || ((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('upstream-ok')
  }))
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upstreamPort = upstream.address().port

  const proxy = createProxy({
    upstream: `http://127.0.0.1:${upstreamPort}`,
    accessKey,
    cookie: () => cookie,
  })
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  const proxyPort = proxy.address().port

  return {
    proxyPort,
    upstreamPort,
    close: async () => {
      await new Promise((resolve) => proxy.close(resolve))
      await new Promise((resolve) => upstream.close(resolve))
    },
  }
}

/** Minimal GET returning status and body. */
function get(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, headers }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
      )
    })
    req.on('error', reject)
    req.end()
  })
}

test('requests without a key are refused before reaching upstream', async () => {
  let reached = false
  const h = await harness({
    upstreamHandler: (req, res) => {
      reached = true
      res.end('should not happen')
    },
  })
  try {
    const res = await get(h.proxyPort, '/')
    assert.equal(res.status, 401)
    assert.equal(reached, false)
  } finally {
    await h.close()
  }
})

test('a correct key redirects and sets an HttpOnly cookie', async () => {
  const h = await harness({ accessKey: 'secret' })
  try {
    const res = await get(h.proxyPort, '/?key=secret')
    assert.equal(res.status, 303)
    const setCookie = String(res.headers['set-cookie'])
    assert.match(setCookie, /HttpOnly/)
    assert.match(setCookie, /SameSite=Lax/)
    assert.ok(!setCookie.includes('secret'), 'the raw key must not be stored in the cookie')
  } finally {
    await h.close()
  }
})

test('a wrong key is rejected with 401', async () => {
  const h = await harness({ accessKey: 'secret' })
  try {
    const res = await get(h.proxyPort, '/?key=nope')
    assert.equal(res.status, 401)
  } finally {
    await h.close()
  }
})

test('authorised requests rewrite Host and inject the session cookie', async () => {
  let seen = null
  const h = await harness({
    accessKey: 'secret',
    cookie: 'dsh-auth-abc=def',
    upstreamHandler: (req, res) => {
      seen = { headers: req.headers, url: req.url }
      res.end('ok')
    },
  })
  try {
    const login = await get(h.proxyPort, '/?key=secret')
    const cookie = String(login.headers['set-cookie']).split(';')[0]
    const res = await get(h.proxyPort, '/api/thing?q=1', {
      cookie,
      host: 'tunnel.example.com',
      origin: 'https://tunnel.example.com',
      'sec-fetch-site': 'cross-site',
    })
    assert.equal(res.status, 200)
    assert.equal(seen.url, '/api/thing?q=1')
    // The fence only accepts loopback; the tunnel hostname must not survive.
    assert.match(seen.headers.host, /^127\.0\.0\.1:/)
    // Cross-site markers and the caller's cookie must not cross the hop.
    assert.equal(seen.headers.origin, undefined)
    assert.equal(seen.headers['sec-fetch-site'], undefined)
    // And ours must be there instead.
    assert.equal(seen.headers.cookie, 'dsh-auth-abc=def')
  } finally {
    await h.close()
  }
})

test('no upstream session cookie yields an explanatory 503', async () => {
  const h = await harness({ accessKey: 'secret', cookie: '' })
  try {
    const login = await get(h.proxyPort, '/?key=secret')
    const cookie = String(login.headers['set-cookie']).split(';')[0]
    const res = await get(h.proxyPort, '/', { cookie })
    assert.equal(res.status, 503)
    assert.match(res.body, /session/i)
  } finally {
    await h.close()
  }
})

test('manifest and favicon are answered without a key', async () => {
  const h = await harness()
  try {
    const manifest = await get(h.proxyPort, '/manifest.webmanifest')
    assert.equal(manifest.status, 200)
    assert.match(String(manifest.headers['content-type']), /manifest\+json/)

    const icon = await get(h.proxyPort, '/favicon.ico')
    assert.equal(icon.status, 204)
  } finally {
    await h.close()
  }
})

test('WebSocket upgrade relays a 101 and preserves extensions', async () => {
  let upgradeHeaders = null
  let upgradeSocket = null
  const upstream = http.createServer((req, res) => res.end('http'))
  upstream.on('upgrade', (req, socket) => {
    upgradeHeaders = req.headers
    upgradeSocket = socket
    // Accept the handshake by hand: enough to prove the relay, no ws library.
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${req.headers['sec-websocket-key']}\r\n` +
        `Sec-WebSocket-Extensions: ${req.headers['sec-websocket-extensions'] || 'none'}\r\n\r\n`,
    )
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upstreamPort = upstream.address().port

  const proxy = createProxy({
    upstream: `http://127.0.0.1:${upstreamPort}`,
    accessKey: 'secret',
    cookie: () => 'dsh-auth-abc=def',
  })
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  const proxyPort = proxy.address().port

  try {
    const login = await get(proxyPort, '/?key=secret')
    const cookie = String(login.headers['set-cookie']).split(';')[0]

    const response = await new Promise((resolve, reject) => {
      const socket = net.connect(proxyPort, '127.0.0.1', () => {
        socket.write(
          'GET /api/remote.mux HTTP/1.1\r\n' +
            `Host: tunnel.example.com\r\n` +
            'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
            'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
            'Sec-WebSocket-Version: 13\r\n' +
            'Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n' +
            `Cookie: ${cookie}\r\n\r\n`,
        )
      })
      let buffer = ''
      socket.on('data', (chunk) => {
        buffer += chunk.toString('latin1')
        if (buffer.includes('\r\n\r\n')) {
          socket.destroy()
          resolve(buffer)
        }
      })
      socket.on('error', reject)
    })

    assert.match(response, /^HTTP\/1\.1 101/)
    assert.ok(upgradeHeaders, 'upstream never saw the upgrade')
    // Losing the extension makes the browser misread frames.
    assert.match(String(upgradeHeaders['sec-websocket-extensions']), /permessage-deflate/)
    assert.equal(upgradeHeaders.cookie, 'dsh-auth-abc=def')
  } finally {
    // A socket handed to an `upgrade` listener is no longer tracked by the
    // server, so http.Server#close waits forever unless it is dropped by hand.
    try {
      upgradeSocket?.destroy()
    } catch {
      /* already gone */
    }
    await new Promise((resolve) => proxy.close(resolve))
    await new Promise((resolve) => upstream.close(resolve))
  }
})

test('WebSocket upgrade without a key is refused', async () => {
  const h = await harness()
  try {
    const response = await new Promise((resolve, reject) => {
      const socket = net.connect(h.proxyPort, '127.0.0.1', () => {
        socket.write(
          'GET /api/remote.mux HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n' +
            'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
            'Sec-WebSocket-Version: 13\r\n\r\n',
        )
      })
      let buffer = ''
      socket.on('data', (chunk) => {
        buffer += chunk.toString('latin1')
      })
      socket.on('close', () => resolve(buffer))
      socket.on('error', () => resolve(buffer))
    })
    assert.match(response, /401/)
  } finally {
    await h.close()
  }
})

test('ACCESS_COOKIE name is stable', () => {
  // The panel and the proxy must agree; a rename would silently break the gate.
  assert.equal(ACCESS_COOKIE, 'dshtunnel')
})

// ── key rotation ────────────────────────────────────────────────────────────
// Regression: `createProxy` used to capture `tokenFor(options.accessKey)` once
// at construction. `POST /dsh-tunnel/key` then updated the panel while the
// running proxy kept accepting the OLD key and rejected the new one — verified
// against a live tunnel, so this is not hypothetical. Rotation has to be
// observable on every request, which is why the key is read through a getter.

/** Spin up a proxy whose key can be changed while it runs. */
async function rotatableProxy(initialKey) {
  const upstream = http.createServer((_req, res) => res.end('upstream-ok'))
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const state = { key: initialKey }
  const proxy = createProxy({
    upstream: `http://127.0.0.1:${upstream.address().port}`,
    accessKey: () => state.key,
    cookie: () => 'dsh-auth-x=y',
  })
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  return {
    port: proxy.address().port,
    state,
    close: async () => {
      await new Promise((resolve) => proxy.close(resolve))
      await new Promise((resolve) => upstream.close(resolve))
    },
  }
}

test('a rotated key takes effect on the running proxy', async () => {
  const h = await rotatableProxy('old-key')
  try {
    assert.equal((await get(h.port, '/?key=old-key')).status, 303)

    h.state.key = 'new-key'

    // The old key must be dead...
    assert.equal((await get(h.port, '/?key=old-key')).status, 401)
    // ...and the new one must work.
    const rotated = await get(h.port, '/?key=new-key')
    assert.equal(rotated.status, 303)
    assert.match(rotated.headers['set-cookie'][0], /^dshtunnel=/)
  } finally {
    await h.close()
  }
})

test('a cookie minted before rotation stops working after it', async () => {
  const h = await rotatableProxy('old-key')
  try {
    const authorised = await get(h.port, '/?key=old-key')
    const cookie = authorised.headers['set-cookie'][0].split(';')[0]
    assert.equal((await get(h.port, '/', { cookie })).status, 200)

    h.state.key = 'new-key'

    // The cookie is an HMAC of the key, so rotation revokes every issued device.
    assert.equal((await get(h.port, '/', { cookie })).status, 401)
  } finally {
    await h.close()
  }
})
