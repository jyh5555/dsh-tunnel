// Does the plugin notice that its tunnel died?
//
// This test exists because of a real failure. `ssh -N -R` was started at boot,
// ran for a while, and then exited. Nothing watched it: the only `exit` listener
// lived inside `startTunnel`'s promise and stopped mattering the moment that
// promise resolved, so `state.tunnel` kept pointing at a dead child. The panel
// showed 「已对外开放」 and the public URL answered 502 for hours.
//
// Everything here uses a fake child (`node -e 'setTimeout(exit)'`) instead of a
// real provider, so the assertions are about this plugin's behaviour, not about
// ssh, cloudflared, or the network. Nothing leaves 127.0.0.1.
//
// Usage: node test/supervision.mjs
import http from 'node:http'
import { EventEmitter } from 'node:events'

const results = []
const check = (label, pass, detail = '') => {
  results.push({ label, pass })
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`)
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Poll until `test` is true, or give up. Returns the last value seen. */
async function waitFor(test, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs
  let last
  while (Date.now() < deadline) {
    last = await test()
    if (last) return last
    await sleep(100)
  }
  console.log(`  ..   timed out waiting for ${label}`)
  return last
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
      // No `authenticatedUrl`: that keeps the session-cookie refresh from making
      // any request at all, which matters for a test that must stay offline.
      return { requestRejection: () => undefined }
    }
    return undefined
  },
}

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

const statusOf = async () => JSON.parse((await call('/dsh-tunnel/status')).body)

// ── the plugin, configured to run a child that will die on purpose ──────────
// Set DSH_TUNNEL_DEPLOYED to test an *installed* copy instead — that is what a
// restart of `dsh web` will actually load.
const plugin = await import(
  process.env.DSH_TUNNEL_DEPLOYED
    ? new URL('file://' + process.env.DSH_TUNNEL_DEPLOYED.replace(/\\/g, '/')).href
    : new URL('../lib/index.js', import.meta.url).href
)

// Long enough to clear `startTunnel`'s 1.5s liveness grace for a declared URL —
// otherwise the start itself fails and there is no live tunnel to lose.
const CHILD_LIFETIME_MS = 2500
const DEATH_CODE = 3

plugin.apply(ctx, {
  provider: 'custom',
  port: 0,
  host: '127.0.0.1',
  accessKey: '',
  cloudflared: { path: '', extraArgs: [] },
  tailscale: { path: '', port: 8443, hostname: '' },
  custom: {
    command: process.execPath,
    args: ['-e', `setTimeout(() => process.exit(${DEATH_CODE}), ${CHILD_LIFETIME_MS})`],
    url: 'https://example.test',
  },
})

console.log('\n== it comes up on its own ==')
const up = await waitFor(async () => {
  const s = await statusOf()
  return s.tunnelUp ? s : null
}, 8000, 'the tunnel to start')
check('autostart brings the tunnel up', Boolean(up))
check('a live tunnel names its provider', up && up.provider === 'custom', up && `got ${up.provider}`)
check('a live tunnel reports whether it is up', up && up.tunnelUp === true)
check('the declared url is reported', up && up.publicUrl === 'https://example.test', up && up.publicUrl)

console.log(`\n== the child dies after ${CHILD_LIFETIME_MS}ms ==`)
const down = await waitFor(async () => {
  const s = await statusOf()
  return s.tunnelUp === false ? s : null
}, 6000, 'the death to be noticed')
check('the plugin notices the exit', Boolean(down))
check('a dead tunnel is not called exposed', down && down.publicUrl === '')
check('a dead tunnel does not name a running provider', down && down.provider === 'off', down && `got ${down.provider}`)
check(
  'the reason is kept for the panel',
  down && new RegExp(`exited \\(code ${DEATH_CODE}\\)`).test(down.lastError || ''),
  down && down.lastError,
)
check(
  'the panel is told when it will retry',
  down && /reconnecting in 5s/.test(down.lastError || ''),
  down && down.lastError,
)

console.log('\n== it reconnects by itself ==')
const again = await waitFor(async () => {
  const s = await statusOf()
  return s.tunnelUp ? s : null
}, 12000, 'the automatic reconnect')
check('a new child is spawned after the backoff', Boolean(again))
check('the error clears once it is back', again && again.lastError === '', again && again.lastError)

console.log('\n== a deliberate stop wins over the ladder ==')
const token = (await statusOf()).controlToken
const stopped = JSON.parse(
  (await call('/dsh-tunnel/stop', { method: 'POST', headers: { 'x-dsh-tunnel-token': token } })).body,
)
check('stop is accepted', stopped.ok === true)
check('nothing is exposed after stop', stopped.tunnelUp === false && stopped.publicUrl === '')

// Longer than the 5s first rung: a stop that still let the ladder fire would
// bring the tunnel back up here, which is the bug this line is watching for.
await sleep(7000)
const later = await statusOf()
check('no reconnect fires after a stop', later.tunnelUp === false, `tunnelUp=${later.tunnelUp}`)

// ── teardown ────────────────────────────────────────────────────────────────
for (const dispose of disposers) {
  try {
    await dispose()
  } catch {
    /* best effort */
  }
}
await new Promise((resolve) => upstream.close(resolve))

const failed = results.filter((r) => !r.pass)
console.log(
  failed.length === 0
    ? '\nOK — a lost tunnel is noticed, reported, and reconnected'
    : `\n${failed.length} CHECK(S) FAILED`,
)
process.exit(failed.length === 0 ? 0 : 1)
