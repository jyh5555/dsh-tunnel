// End-to-end proof that the P0 viewer/operator split holds in a real process.
//
// Unlike the unit tests, this spins up the *actual* proxy and a fake upstream
// that behaves like dsh web (it reads the hop marker and answers accordingly),
// then runs the attack chain that used to work:
//
//   1. visitor uses the key            -> may read the panel
//   2. visitor reads /status           -> must get no control token, no key
//   3. visitor tries to stop the tunnel-> must be refused
//   4. visitor tries to write custom   -> must be refused
//
// Run: node test/e2e-viewer.mjs
import http from 'node:http'
import assert from 'node:assert/strict'

import { createProxy, TUNNEL_HOP_HEADER } from '../lib/proxy.js'

const KEY = 'e2e-access-key'

/** Upstream that implements the same rule `index.js` does. */
function fakeDshWeb() {
  const log = []
  const server = http.createServer((req, res) => {
    const remote = String(req.headers[TUNNEL_HOP_HEADER] || '') !== ''
    const full = {
      ok: true,
      controlToken: 'THE-CONTROL-TOKEN',
      accessKey: KEY,
      publicUrl: 'https://example.trycloudflare.com',
      proxyRunning: true,
      tunnelCommand: 'cloudflared tunnel --token=SECRET',
      config: { custom: { command: 'bore', args: ['--secret=SECRET'] } },
    }
    const body = remote
      ? { ...full, remote: true, controlToken: undefined, accessKey: undefined, tunnelCommand: '', config: {} }
      : { ...full, remote: false }

    log.push({ url: req.url, remote, method: req.method })

    if (req.url.startsWith('/dsh-tunnel/status')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(body))
    }
    // Mutations: refused for anything that came through the tunnel.
    if (remote) {
      res.writeHead(403, { 'content-type': 'application/json' })
      return res.end(JSON.stringify({ error: 'read-only over the tunnel' }))
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true }))
  })
  return { server, log }
}

/** POST/GET through the proxy with a cookie. */
function call(port, path, { cookie = '', method = 'GET', body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {}
    if (cookie) headers.cookie = cookie
    if (body) {
      headers['content-type'] = 'application/json'
      headers['content-length'] = Buffer.byteLength(body)
    }
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString('utf8'),
        }),
      )
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

const up = fakeDshWeb()
await new Promise((resolve) => up.server.listen(0, '127.0.0.1', resolve))
const proxy = createProxy({
  upstream: `http://127.0.0.1:${up.server.address().port}`,
  accessKey: () => KEY,
  cookie: () => 'dsh-auth-x=y',
})
await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
const port = proxy.address().port

let ok = true
const check = (label, pass, detail = '') => {
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`)
  if (!pass) ok = false
}

try {
  // ── the visitor becomes authorised ────────────────────────────────────────
  const auth = await call(port, '/?key=' + KEY)
  check('visitor is authorised by the key', auth.status === 303)
  const cookie = auth.headers['set-cookie'][0].split(';')[0]

  // ── 1. reading status ─────────────────────────────────────────────────────
  const status = JSON.parse((await call(port, '/dsh-tunnel/status', { cookie })).text)
  check('viewer gets a status payload', status.ok === true)
  check('viewer is told it is remote', status.remote === true)
  check('NO control token', status.controlToken === undefined, status.controlToken ? 'LEAKED' : '')
  check('NO access key', status.accessKey === undefined, status.accessKey ? 'LEAKED' : '')
  check('NO tunnel command', !status.tunnelCommand)
  check(
    'no secret anywhere in the payload',
    !JSON.stringify(status).includes('SECRET') && !JSON.stringify(status).includes(KEY),
  )
  check('read-only status still present', status.proxyRunning === true && Boolean(status.publicUrl))

  // ── 2. mutating as a viewer ───────────────────────────────────────────────
  const stop = await call(port, '/dsh-tunnel/stop', { cookie, method: 'POST' })
  check('viewer cannot stop the tunnel', stop.status === 403, `got ${stop.status}`)

  const config = await call(port, '/dsh-tunnel/config', {
    cookie,
    method: 'POST',
    body: JSON.stringify({ custom: { command: 'cmd', args: ['/c', 'echo pwned>', 'C:\\pwned.txt'] } }),
  })
  check('viewer cannot write provider config', config.status === 403, `got ${config.status}`)

  const start = await call(port, '/dsh-tunnel/start', {
    cookie,
    method: 'POST',
    body: JSON.stringify({ provider: 'custom' }),
  })
  check('viewer cannot start a provider', start.status === 403, `got ${start.status}`)

  const rotate = await call(port, '/dsh-tunnel/key', { cookie, method: 'POST' })
  check('viewer cannot rotate the key', rotate.status === 403, `got ${rotate.status}`)

  // ── 3. the upstream really saw the hop marker ─────────────────────────────
  check('every upstream request was marked remote', up.log.every((entry) => entry.remote))
} finally {
  await new Promise((resolve) => proxy.close(resolve))
  await new Promise((resolve) => up.server.close(resolve))
}

console.log(ok ? '\nP0 VIEWER/OPERATOR SPLIT HOLDS END TO END' : '\nP0 SPLIT IS BROKEN')
process.exit(ok ? 0 : 1)
