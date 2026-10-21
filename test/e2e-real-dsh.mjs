// End-to-end proof against the *real* dsh web, without restarting it.
//
// Every other test in this directory uses a fake upstream, because a fake is
// easy to reason about. That leaves one gap: does the viewer/operator split still
// hold when the thing behind the proxy is the actual dsh web, with its real
// origin fence, real session cookie, and real routes?
//
// This closes that gap. It loads the deployed plugin, points its proxy at the
// live dsh web, and then talks to that proxy exactly as a tunnel visitor would.
// Nothing about the running dsh web is modified: the proxy is a separate
// listener in this process, and it is closed on exit.
//
// Usage: node test/e2e-real-dsh.mjs
import http from 'node:http'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'

import { createProxy } from '../lib/proxy.js'
import { redactSnapshot } from '../lib/index.js'

// This one needs a live `dsh web` and a valid session cookie, so it is driven by
// environment variables and skips itself when they are absent:
//
//   DSH_URL=http://127.0.0.1:PORT
//   DSH_COOKIE_FILE=/path/to/harness-cookie.json     (a file containing {cookie})
//   DSH_COOKIE='dsh-auth-…=…'                        (or the value inline)
//
// It is the only test here that talks to a real host rather than a fake one, and
// it is skipped by `npm run test:all` for that reason.
const UPSTREAM = (process.env.DSH_URL || 'http://127.0.0.1:47996').replace(/\/$/, '')
const KEY = 'e2e-real-key-' + Math.random().toString(36).slice(2, 10)

let ok = true
const check = (label, pass, detail = '') => {
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`)
  if (!pass) ok = false
}

/** The session cookie, from either an inline value or a json file. */
function readCookie() {
  if (process.env.DSH_COOKIE) return process.env.DSH_COOKIE
  if (process.env.DSH_COOKIE_FILE && fs.existsSync(process.env.DSH_COOKIE_FILE)) {
    return JSON.parse(fs.readFileSync(process.env.DSH_COOKIE_FILE, 'utf8')).cookie
  }
  return ''
}

const cookieValue = readCookie()
if (!cookieValue) {
  console.log('DSH_COOKIE or DSH_COOKIE_FILE not set; skipping the real-host test')
  console.log('(see the header of this file for what it needs)')
  process.exit(0)
}

// ── is dsh web actually up? ─────────────────────────────────────────────────
const alive = await fetch(UPSTREAM + '/', { headers: { cookie: cookieValue }, signal: AbortSignal.timeout(5000) })
  .then((r) => r.status)
  .catch(() => 0)
if (!alive) {
  console.log(`dsh web at ${UPSTREAM} is not answering; skipping`)
  process.exit(0)
}

// ── a real proxy in front of the real host ──────────────────────────────────
const proxy = createProxy({
  upstream: UPSTREAM,
  accessKey: () => KEY,
  cookie: () => cookieValue,
  log: () => {},
})
await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
const port = proxy.address().port

/** Talk to the proxy the way a browser on the tunnel would. */
function call(path, { cookie = '', method = 'GET', body } = {}) {
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
        resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }),
      )
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

try {
  console.log('== against the REAL dsh web ==')

  // 1. the key gate
  const noKey = await call('/')
  check('a stranger without the key gets 401', noKey.status === 401, `got ${noKey.status}`)

  const authRes = await call('/?key=' + KEY)
  check('the key is accepted', authRes.status === 303, `got ${authRes.status}`)
  const cookie = authRes.headers['set-cookie'][0].split(';')[0]

  // 2. the real app really loads through the proxy
  const page = await call('/', { cookie })
  const title = (page.text.match(/<title>(.*?)<\/title>/i) || [])[1]
  check('the real app loads through the proxy', page.status === 200 && /Harness/i.test(title || ''), `${page.status} ${title}`)

  // 3. the real /api fence is satisfied — this is the whole reason the proxy exists
  const api = await call('/api/session/list', { cookie, method: 'POST', body: '{}' })
  check('the real /api fence accepts the proxy', api.status === 200, `got ${api.status}`)
  check('and answers real JSON, not a fence error', /server-response|gateway\/bad-request/.test(api.text))

  // 4. what a viewer may see, against the live host
  //
  //    This request goes through the proxy, so the plugin sees the hop marker and
  //    answers as remote. That is the whole point: `live` here is already the
  //    viewer's view, not the operator's. (An earlier version of this test
  //    asserted the opposite and passed only because the bug existed.)
  const live = JSON.parse((await call('/dsh-tunnel/status', { cookie })).text)
  check('a proxied status call is marked remote', live.remote === true, String(live.remote))
  check('and carries no control token', live.controlToken === undefined, String(live.controlToken))
  check('and carries no access key', live.accessKey === undefined, String(live.accessKey))
  check('and no secret anywhere in it', !JSON.stringify(live).includes(KEY))

  // The operator view is what you get straight from dsh web, no proxy involved.
  const direct = await fetch(UPSTREAM + '/dsh-tunnel/status', {
    headers: { cookie: cookieValue },
    signal: AbortSignal.timeout(10000),
  }).then((r) => r.json())
  check('the operator, unseen by the proxy, still gets a token', typeof direct.controlToken === 'string' && direct.controlToken.length > 0)
  check('and is not marked remote', direct.remote === false, String(direct.remote))
  check('redactSnapshot then strips it for the viewer', !('controlToken' in redactSnapshot(direct, true)))

  // 5. WebSocket through the proxy to the real host
  const wsStatus = await new Promise((resolve) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: '/api/remote.mux',
      headers: {
        cookie,
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
        'sec-websocket-version': '13',
      },
    })
    req.on('upgrade', (res, socket) => {
      socket.destroy()
      resolve(res.statusCode)
    })
    req.on('response', (res) => {
      res.resume()
      resolve(res.statusCode)
    })
    req.on('error', () => resolve(0))
    req.setTimeout(8000, () => {
      req.destroy()
      resolve(0)
    })
    req.end()
  })
  check('the real WebSocket endpoint upgrades through the proxy', wsStatus === 101, `got ${wsStatus}`)
} finally {
  await new Promise((resolve) => proxy.close(resolve))
}

console.log(ok ? '\nREAL-HOST END-TO-END HOLDS' : '\nREAL-HOST END-TO-END FAILED')
process.exit(ok ? 0 : 1)
