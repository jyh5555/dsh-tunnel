// Post-restart smoke test.
//
// The P0 fix lives in `lib/index.js`, which only reloads when `dsh web`
// restarts. This script boots the plugin's real `apply()` against a mock ctx in
// its own process, so the code path that will run after the restart is the exact
// code being tested — without dropping the session that this conversation is
// running over.
//
// It answers one question: after a restart, does the panel still work for the
// operator, and is the tunnel really closed to visitors?
//
// Usage: node test/smoke-after-restart.mjs
import http from 'node:http'
import { EventEmitter } from 'node:events'

const results = []
const check = (label, pass, detail = '') => {
  results.push({ label, pass })
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`)
}

// ── fake dsh web ────────────────────────────────────────────────────────────
const upstream = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' })
  res.end('upstream')
})
await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
const upstreamOrigin = `http://127.0.0.1:${upstream.address().port}`

// ── mock ctx, shaped like the real one ──────────────────────────────────────
const routes = []
const disposers = []
const ctx = {
  logger: { info: () => {} },
  effect(factory) {
    const dispose = factory()
    if (typeof dispose === 'function') disposers.push(dispose)
    return () => {}
  },
  get(name) {
    if (name === 'webServer') {
      return {
        register(route) {
          routes.push(route)
          return () => {
            const i = routes.indexOf(route)
            if (i >= 0) routes.splice(i, 1)
          }
        },
        getOrigin: () => upstreamOrigin,
      }
    }
    if (name === 'connection') {
      return {
        requestRejection: () => undefined,
        authenticatedUrl: (base) => `${base}?token=stub`,
      }
    }
    return undefined
  },
}

const realFetch = globalThis.fetch
globalThis.fetch = async (input, init) => {
  if (String(input).includes('token=stub')) {
    return new Response('', { status: 303, headers: { 'set-cookie': 'dsh-auth-t=a; Path=/' } })
  }
  return realFetch(input, init)
}

// ── load the plugin from this repo ─────────────────────────────────────────
// Set DSH_TUNNEL_DEPLOYED to smoke-test an *installed* copy instead, which is
// how this file was originally used: point it at
// `<profile>/node_modules/dsh-tunnel/lib/index.js` to check what a restart will
// actually load.
const pluginPath = process.env.DSH_TUNNEL_DEPLOYED
  ? new URL('file://' + process.env.DSH_TUNNEL_DEPLOYED.replace(/\\/g, '/')).href
  : new URL('../lib/index.js', import.meta.url).href
const plugin = await import(pluginPath)

const config = {
  provider: 'off',
  port: 0,
  host: '127.0.0.1',
  accessKey: '',
  cloudflared: { path: '', extraArgs: [] },
  tailscale: { path: '', port: 8443, hostname: '' },
  custom: { command: '', args: [] },
}

plugin.apply(ctx, config)

/** Invoke a registered route the way the host would. */
function call(path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = Object.assign(new EventEmitter(), { method, url: path, headers })
    const res = Object.assign(new EventEmitter(), { statusCode: 200, headers: {} })
    const chunks = []
    res.writeHead = (status, hdrs) => {
      res.statusCode = status
      if (hdrs) Object.assign(res.headers, hdrs)
      return res
    }
    res.write = (chunk) => {
      chunks.push(Buffer.from(chunk))
      return true
    }
    res.end = (chunk) => {
      if (chunk) chunks.push(Buffer.from(chunk))
      resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') })
    }
    const payload = body ? [Buffer.from(JSON.stringify(body))] : []
    process.nextTick(() => {
      for (const c of payload) req.emit('data', c)
      req.emit('end')
    })
    try {
      routes.find((r) => r.path === path).handler(req, res)
    } catch (error) {
      reject(error)
    }
  })
}

console.log('\n== the operator, at the machine ==')
const local = await call('/dsh-tunnel/status')
const operator = JSON.parse(local.body)
check('status is 200', local.status === 200)
check('operator gets a control token', typeof operator.controlToken === 'string' && operator.controlToken.length > 0)
check('operator gets the access key', typeof operator.accessKey === 'string' && operator.accessKey.length >= 20)
check('operator is not marked remote', operator.remote === false)
check('the key is 144+ bits of base64url', /^[A-Za-z0-9_-]{24,}$/.test(operator.accessKey))

console.log('\n== a visitor, through the tunnel ==')
const remote = await call('/dsh-tunnel/status', { headers: { 'x-dsh-tunnel-hop': '1' } })
const viewer = JSON.parse(remote.body)
check('visitor can read status', remote.status === 200)
check('visitor is marked remote', viewer.remote === true)
check('visitor gets NO control token', !('controlToken' in viewer))
check('visitor gets NO access key', !('accessKey' in viewer))
check('visitor gets NO command line', !viewer.tunnelCommand)
check('nothing secret in the payload', !JSON.stringify(viewer).includes(operator.accessKey))

console.log('\n== a visitor trying to mutate, replaying the real token ==')
for (const [label, path, body] of [
  ['/key', '/dsh-tunnel/key', undefined],
  ['/stop', '/dsh-tunnel/stop', undefined],
  ['/start', '/dsh-tunnel/start', { provider: 'off' }],
  ['/config', '/dsh-tunnel/config', { custom: { command: 'bore' } }],
]) {
  const res = await call(path, {
    method: 'POST',
    headers: { 'x-dsh-tunnel-hop': '1', 'x-dsh-tunnel-token': operator.controlToken },
    body,
  })
  check(`visitor POST ${label} is refused`, res.status === 403, `got ${res.status}`)
}

console.log('\n== the operator can still configure things ==')
const saved = await call('/dsh-tunnel/config', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': operator.controlToken },
  body: { custom: { command: 'bore', args: ['local', '{port}'] } },
})
check('operator config write is 200', saved.status === 200, `got ${saved.status}`)
const after = JSON.parse(saved.body)
check('the write took effect', after.config.custom.command === 'bore')

const shell = await call('/dsh-tunnel/config', {
  method: 'POST',
  headers: { 'x-dsh-tunnel-token': operator.controlToken },
  body: { custom: { command: 'cmd' } },
})
check('a shell is still refused locally', shell.status === 400, `got ${shell.status}`)

// ── teardown ────────────────────────────────────────────────────────────────
for (const dispose of disposers) {
  try {
    await dispose()
  } catch {
    /* best effort */
  }
}
globalThis.fetch = realFetch
await new Promise((resolve) => upstream.close(resolve))

const failed = results.filter((r) => !r.pass)
console.log(
  failed.length === 0
    ? '\nREADY FOR A RESTART — the operator keeps control, visitors get read-only'
    : `\n${failed.length} CHECK(S) FAILED — do not restart yet`,
)
process.exit(failed.length === 0 ? 0 : 1)
