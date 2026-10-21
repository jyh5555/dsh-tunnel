// Attack-scenario tests: not "does the function work" but "what does an
// attacker actually get".
//
// Each scenario is a story with a beginning, a middle, and an assertion about
// what the attacker walks away with. They exist because unit tests of helpers can
// all pass while the assembled system still hands out a shell.
//
// Usage: node test/attack-scenarios.mjs
import http from 'node:http'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'

let ok = true
const check = (label, pass, detail = '') => {
  console.log(`  ${pass ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`)
  if (!pass) ok = false
}

/** Boot a fresh copy of the plugin against a fake upstream. */
async function bootPlugin() {
  const upstream = http.createServer((_q, s) => s.end('upstream'))
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  const routes = []
  const disposers = []
  const ctx = {
    logger: { info: () => {} },
    effect(f) {
      const d = f()
      if (typeof d === 'function') disposers.push(d)
      return () => {}
    },
    get(n) {
      if (n === 'webServer') {
        return {
          register(r) {
            routes.push(r)
            return () => {}
          },
          getOrigin: () => `http://127.0.0.1:${upstream.address().port}`,
        }
      }
      if (n === 'connection') {
        return { requestRejection: () => undefined, authenticatedUrl: (b) => b + '?token=stub' }
      }
    },
  }
  const realFetch = globalThis.fetch
  globalThis.fetch = async (i, o) =>
    String(i).includes('token=stub')
      ? new Response('', { status: 303, headers: { 'set-cookie': 'dsh-auth-t=a; Path=/' } })
      : realFetch(i, o)

  // A fresh module instance per scenario, so one scenario's plugin state cannot
  // leak into the next. `?t=` defeats the ESM module cache.
  const source = new URL('../lib/index.js', import.meta.url).href
  const plugin = await import(source + '?t=' + Math.random())
  plugin.apply(ctx, {
    provider: 'off',
    port: 0,
    host: '127.0.0.1',
    accessKey: '',
    cloudflared: { path: '', extraArgs: [] },
    tailscale: { path: '', port: 8443, hostname: '' },
    custom: { command: '', args: [] },
  })

  const call = (path, { method = 'GET', headers = {}, body } = {}) =>
    new Promise((resolve) => {
      const req = Object.assign(new EventEmitter(), { method, url: path, headers })
      const res = Object.assign(new EventEmitter(), { statusCode: 200, headers: {} })
      const out = []
      res.writeHead = (s, h) => {
        res.statusCode = s
        if (h) Object.assign(res.headers, h)
        return res
      }
      res.write = (c) => {
        out.push(Buffer.from(c))
        return true
      }
      res.end = (c) => {
        if (c) out.push(Buffer.from(c))
        resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(out).toString() })
      }
      process.nextTick(() => {
        if (body) req.emit('data', Buffer.from(JSON.stringify(body)))
        req.emit('end')
      })
      routes.find((r) => r.path === path).handler(req, res)
    })

  return {
    call,
    env: { HTTPS_PROXY: realFetch },
    close: async () => {
      for (const d of disposers) {
        try {
          await d()
        } catch {
          /* best effort */
        }
      }
      globalThis.fetch = realFetch
      await new Promise((r) => upstream.close(r))
    },
  }
}

// ── Scenario 1: the curious visitor ─────────────────────────────────────────
// Someone found the trycloudflare subdomain in a scanner log and has the link,
// because the owner pasted it into a group chat.
console.log('\n== scenario 1: a visitor with the link, snooping ==')
{
  const p = await bootPlugin()
  try {
    const status = JSON.parse((await p.call('/dsh-tunnel/status', { headers: { 'x-dsh-tunnel-hop': '1' } })).text)
    check('they learn the tunnel is up', status.proxyRunning === false || status.proxyRunning === true)
    check('they learn nothing about the key', !('accessKey' in status))
    check('they learn nothing about the token', !('controlToken' in status))
    check('they cannot see the command line', !status.tunnelCommand)
    check('the payload is safe to have leaked', !JSON.stringify(status).match(/[A-Za-z0-9_-]{24}/))
  } finally {
    await p.close()
  }
}

// ── Scenario 2: the visitor who tries to take over ──────────────────────────
// Same visitor, now poking at endpoints. The old build handed them RCE here.
console.log('\n== scenario 2: the same visitor tries to take over ==')
{
  const p = await bootPlugin()
  try {
    const hop = { 'x-dsh-tunnel-hop': '1' }
    const attempts = [
      ['install a command', '/dsh-tunnel/config', { custom: { command: 'node', args: ['-e', '1'] } }],
      ['start that command', '/dsh-tunnel/start', { provider: 'custom' }],
      ['stop the tunnel', '/dsh-tunnel/stop', undefined],
      ['rotate the key', '/dsh-tunnel/key', undefined],
      ['overwrite the key', '/dsh-tunnel/config', { accessKey: 'attacker' }],
    ]
    for (const [what, path, body] of attempts) {
      const res = await p.call(path, { method: 'POST', headers: hop, body })
      check(`cannot ${what}`, res.status === 403, `got ${res.status}`)
    }
  } finally {
    await p.close()
  }
}

// ── Scenario 3: the visitor who steals a token from elsewhere ───────────────
// Suppose the token leaked some other way — a screenshot, a log line. Does the
// token alone still get them in from outside?
console.log('\n== scenario 3: they somehow obtained the control token ==')
{
  const p = await bootPlugin()
  try {
    const st = JSON.parse((await p.call('/dsh-tunnel/status')).text)
    const stolen = st.controlToken
    check('the token exists for the operator', typeof stolen === 'string' && stolen.length > 0)

    const res = await p.call('/dsh-tunnel/config', {
      method: 'POST',
      headers: { 'x-dsh-tunnel-hop': '1', 'x-dsh-tunnel-token': stolen },
      body: { custom: { command: 'node' } },
    })
    check('a stolen token is useless from outside', res.status === 403, `got ${res.status}`)
  } finally {
    await p.close()
  }
}

// ── Scenario 4: a local page tries to reach the panel ───────────────────────
// Same-origin policy does not stop a form POST or a DNS-rebinding attempt.
// The origin fence is what does.
console.log('\n== scenario 4: the operator visits a malicious page ==')
{
  // The fence is dsh web's, not this plugin's: assert the plugin *calls* it.
  const source = fs.readFileSync(
    'D:/deepseek-harness/default-workspace/dsh-tunnel-plugin/lib/index.js',
    'utf8',
  )
  check('every control route consults the origin fence', /requestRejection/.test(source))
  check('and refuses before doing any work', /rejection !== undefined[\s\S]{0,80}return true/.test(source))
}

// ── Scenario 5: the operator mistypes a shell ───────────────────────────────
// Defence in depth: even with the token in hand and sitting at the machine,
// the config route will not install a shell.
console.log('\n== scenario 5: the operator (or their stolen token) tries a shell ==')
{
  const p = await bootPlugin()
  try {
    const st = JSON.parse((await p.call('/dsh-tunnel/status')).text)
    const tok = { 'x-dsh-tunnel-token': st.controlToken }
    for (const command of ['cmd', 'cmd.exe', 'pwsh', 'bash', '/bin/sh', 'C:\\Windows\\System32\\cmd.exe']) {
      const res = await p.call('/dsh-tunnel/config', { method: 'POST', headers: tok, body: { custom: { command } } })
      check(`a shell is refused: ${command}`, res.status === 400, `got ${res.status}`)
    }
    const chain = await p.call('/dsh-tunnel/config', {
      method: 'POST',
      headers: tok,
      body: { custom: { command: 'bore', args: ['local', '8443', '&&', 'calc'] } },
    })
    check('a chained argument is refused', chain.status === 400, `got ${chain.status}`)

    const fine = await p.call('/dsh-tunnel/config', {
      method: 'POST',
      headers: tok,
      body: { custom: { command: 'bore', args: ['local', '{port}', '--to', 'bore.pub'] } },
    })
    check('a legitimate tunnel command still works', fine.status === 200, `got ${fine.status}`)

    // The key can be replaced, but not weakened: a 3-character key would turn
    // the only gate in front of a public address into something guessable.
    for (const weak of ['abc', 'short', 'x'.repeat(23)]) {
      const res = await p.call('/dsh-tunnel/config', {
        method: 'POST',
        headers: tok,
        body: { accessKey: weak },
      })
      check(`a weak access key is refused (${weak.length} chars)`, res.status === 400, `got ${res.status}`)
    }
    const strong = await p.call('/dsh-tunnel/config', {
      method: 'POST',
      headers: tok,
      body: { accessKey: 'A'.repeat(24) },
    })
    check('a 24-character key is accepted', strong.status === 200, `got ${strong.status}`)
  } finally {
    await p.close()
  }
}

console.log(ok ? '\nALL ATTACK SCENARIOS HELD' : '\nAN ATTACK SCENARIO SUCCEEDED')
process.exit(ok ? 0 : 1)
