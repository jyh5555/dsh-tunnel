/**
 * dsh-tunnel — expose this machine's dsh web through a tunnel the user picks.
 *
 * ## Why this plugin exists
 *
 * `dsh web` binds to loopback and its `/api` fence only trusts loopback, its own
 * bind address, or a `--trusted-host` declaration. Putting a tunnel in front is
 * therefore not enough: the fence rejects the public hostname before any route
 * runs. This plugin starts a small reverse proxy on loopback, does the four
 * rewrites that make dsh web accept traffic from it (see `proxy.js`), and lets a
 * tunnel point at that proxy.
 *
 * ## Why the user chooses the tunnel
 *
 * "Free" and "stable hostname" cannot both come from one provider:
 *
 *   Cloudflare Quick Tunnel — free, no account, new hostname each restart, no SSE.
 *   Tailscale Funnel        — free, permanent `*.ts.net`, SSE works, needs an account.
 *   Custom command          — whatever the user already runs.
 *   Off                     — LAN only, nothing public.
 *
 * Hard-coding one would be picking a favourite; this ships all of them.
 *
 * ## What it deliberately does not do
 *
 * No account system, no relay server, no end-to-end encryption. A tunnel is TLS
 * between the visitor and the tunnel edge, so the provider can see plaintext.
 * The panel says so instead of implying otherwise.
 *
 * @module dsh-tunnel
 */

import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { stat } from 'node:fs/promises'

import { TUNNEL_HOP_HEADER } from './proxy.js'
import { PROVIDER_IDS, startTunnel, stopTunnel, probeControlPlane } from './providers.js'
import { Config } from './config.js'

export const name = 'dsh-tunnel'

/**
 * `webServer` carries the routes, `connection` mints this process's launch
 * token so the proxy can hold a valid `dsh-auth-*` session cookie. Both are
 * optional in other surfaces, so every use below is guarded.
 */
export const inject = ['webServer', 'connection']

/**
 * Re-exported so the loader finds it, and so anyone reading the package can see
 * the whole surface shape without opening a second file. The schema itself is
 * hand-written in `config.js` — no schema library, no transitive dependencies.
 */
export { Config }

/** Routes live under one prefix so nothing can collide with a core route. */
const STATUS_PATH = '/dsh-tunnel/status'
const START_PATH = '/dsh-tunnel/start'
const STOP_PATH = '/dsh-tunnel/stop'
const CONFIG_PATH = '/dsh-tunnel/config'
const REGENERATE_PATH = '/dsh-tunnel/key'

/** Longest request body accepted on the control routes. They carry small JSON. */
const MAX_BODY = 16 * 1024

/**
 * Listening proxies, shared across module instances of this plugin.
 *
 * A plugin reload replaces the module but not the sockets it opened: the old
 * instance's `http.Server` keeps the port bound unless something closes it, and
 * the new instance then fails with `EADDRINUSE` against its own port. That is
 * not hypothetical — it is what happened the first time this plugin was reloaded
 * while a tunnel was running, and the symptom looked like "the access key is
 * wrong" because an *old* proxy was answering on the port with an old key.
 *
 * `globalThis` is the only place two module instances can share state, so the
 * registry lives there keyed by a `Symbol.for` that survives reloads.
 */
const PROXY_REGISTRY = Symbol.for('dsh-tunnel.proxies')

/** @returns {Map<number, import('node:http').Server>} */
function proxyRegistry() {
  if (!globalThis[PROXY_REGISTRY]) globalThis[PROXY_REGISTRY] = new Map()
  return globalThis[PROXY_REGISTRY]
}

/** Remember a listening server so a future instance can reclaim the port. */
export function rememberProxy(port, server) {
  proxyRegistry().set(port, server)
}

/** Drop a server from the registry, if it is still the one recorded. */
export function forgetProxy(port, server) {
  const registry = proxyRegistry()
  if (registry.get(port) === server) registry.delete(port)
}

/**
 * Close a listener a previous instance of this plugin left behind.
 *
 * Deliberately only touches ports this plugin previously claimed: closing a
 * socket we never opened would mean stomping on whatever else owns the port, and
 * a plain "port busy" error is far better than killing an unrelated service.
 *
 * @param {number} port
 * @returns {boolean} true when a leftover listener was closed.
 */
export function reclaimProxy(port) {
  const registry = proxyRegistry()
  const stale = registry.get(port)
  if (!stale) return false
  try {
    stale.close()
    stale.closeAllConnections?.()
  } catch {
    /* already closed */
  }
  registry.delete(port)
  return true
}

/** How often to re-mint the session cookie. dsh web rotates it only on restart. */
const COOKIE_REFRESH_MS = 15_000

/**
 * Shortest access key the config route will accept.
 *
 * Generated keys are 18 random bytes → 24 base64url characters → 144 bits. A
 * caller replacing the key through `/config` is allowed to, but not to make it
 * weaker than that: a short string would silently turn the only gate in front of
 * a public address into something guessable, and no other check would notice.
 */
const MIN_ACCESS_KEY_LENGTH = 24

/**
 * Read a JSON body, bounded.
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<any>}
 */
function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    req.on('data', (chunk) => {
      total += chunk.length
      if (total > MAX_BODY) {
        reject(new Error('request body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim()
      if (!text) return resolve({})
      try {
        resolve(JSON.parse(text))
      } catch {
        reject(new Error('request body is not valid JSON'))
      }
    })
    req.on('error', reject)
  })
}

/** Send JSON without a framework. */
function sendJson(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8')
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(payload.length),
    'cache-control': 'no-store',
  })
  res.end(payload)
}

/**
 * Is this request arriving through the public tunnel?
 *
 * dsh web cannot distinguish a tunnel visitor from someone at the keyboard: the
 * proxy always dials upstream from `127.0.0.1`, so `remoteAddress` is loopback
 * for both. `proxy.js` therefore stamps `x-dsh-tunnel-hop` on every forwarded
 * request, after stripping any client-supplied value under that name.
 *
 * Everything a viewer must not have — the control token, the plaintext access
 * key, the ability to stop the tunnel — hangs off this one bit, so the check
 * lives in one place and is asserted by tests in both directions.
 *
 * @param {import('node:http').IncomingMessage} req
 * @returns {boolean}
 */
function cameThroughTunnel(req) {
  return String(req.headers[TUNNEL_HOP_HEADER] || '') !== ''
}

/**
 * Guard a route.
 *
 * Three layers, and they stop different things:
 *
 *   - The **origin fence** (`connection.requestRejection`) rejects any request
 *     whose Host is not this listener and whose Origin is not same-origin. That
 *     is what stops a web page the user happens to visit from reaching these
 *     routes, and what stops DNS rebinding.
 *   - The **tunnel hop marker** refuses every mutation to a request that arrived
 *     through the public listener. Holding the access key makes you a *viewer*
 *     — you may use dsh web — but never an *operator*. Without this, anyone with
 *     the link could open the panel and spawn a command on the host.
 *   - The **control token** additionally proves the caller loaded this panel,
 *     and only ever reaches a local one.
 *
 * @param {any} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{token: string, mutate: boolean}} options
 * @returns {boolean} true when the request was rejected and the response is done.
 */
function rejectControlRequest(ctx, req, res, options) {
  const connection = ctx.get?.('connection')
  const rejection = connection?.requestRejection?.(req)
  if (rejection !== undefined) {
    res.writeHead(rejection).end()
    return true
  }
  if (options.mutate && cameThroughTunnel(req)) {
    // Deliberately a plain 403 carrying no hint about the token: a viewer learns
    // nothing about how control is granted.
    sendJson(res, 403, {
      error: 'this panel is read-only over the tunnel; control it from the host machine',
    })
    return true
  }
  if (options.mutate && String(req.headers['x-dsh-tunnel-token'] || '') !== options.token) {
    sendJson(res, 403, { error: 'missing or stale control token; reload the panel' })
    return true
  }
  return false
}

/**
 * Commands the panel may never install.
 *
 * `custom` is a `spawn(command, args)`, which is the feature — and also the
 * loudest thing this plugin can do. Two rules keep it from being a remote shell:
 *
 *   1. A blank `command` is ignored rather than applied. Clearing it over HTTP
 *      would be one request away from silently disabling the operator's tunnel.
 *   2. Shells are refused outright, and arguments may not carry shell
 *      metacharacters. `spawn` without a shell does not interpret them, but
 *      `cmd /c` and `sh -c` do, and those are exactly what someone reaching for
 *      this field would type.
 *
 * This is defence in depth, not the primary control — the primary control is
 * that only the operator can reach the config route at all.
 */
const SHELL_COMMANDS = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
])

/** Characters that mean "run this through a shell" to a human reader. */
const SHELL_METACHARACTERS = /[;&|`$><\n\r]/

/**
 * Validate a proposed `custom` group before it reaches `config`.
 *
 * @param {object} proposed - the `custom` object from the request body.
 * @param {object} current - the `custom` group currently in effect.
 * @returns {{ok: true, value: object} | {ok: false, error: string}}
 */
export function sanitizeCustomSettings(proposed, current) {
  const next = { ...(current || {}) }

  if (Object.prototype.hasOwnProperty.call(proposed, 'command')) {
    const command = String(proposed.command ?? '').trim()
    if (command !== '') {
      const base = command.split(/[\\/]/).pop().toLowerCase()
      if (SHELL_COMMANDS.has(base)) {
        return {
          ok: false,
          error: `refusing to run a shell as the tunnel command (${base}); set it in the profile patch if you really mean it`,
        }
      }
      next.command = command
    }
  }

  if (Object.prototype.hasOwnProperty.call(proposed, 'args')) {
    if (!Array.isArray(proposed.args)) {
      return { ok: false, error: 'custom.args must be an array of strings' }
    }
    const args = proposed.args.map((value) => String(value))
    const offending = args.find((value) => SHELL_METACHARACTERS.test(value))
    if (offending !== undefined) {
      return {
        ok: false,
        error: `refusing an argument containing shell metacharacters: ${JSON.stringify(offending)}`,
      }
    }
    next.args = args
  }

  if (Object.prototype.hasOwnProperty.call(proposed, 'url')) {
    const url = String(proposed.url ?? '').trim()
    if (url === '') {
      // Blank clears it, unlike `command`: falling back to "parse the output" is
      // a safe default, whereas falling back to "no command" is not.
      next.url = ''
    } else {
      let parsed
      try {
        parsed = new URL(url)
      } catch {
        return { ok: false, error: `custom.url is not a valid URL: ${url}` }
      }
      if (parsed.protocol !== 'https:') {
        // The access key travels in the sign-in form, so a plain-http address
        // would put it on the wire in clear. Refuse rather than warn.
        return { ok: false, error: 'custom.url must be https://; a plain http address would expose the access key' }
      }
      next.url = url
    }
  }

  return { ok: true, value: next }
}

/**
 * Validate one provider's settings group from a request body.
 *
 * Only `custom` carries an execution surface; the other two are paths and ports
 * and are passed through as typed.
 *
 * @param {string} key - `cloudflared` | `tailscale` | `custom`.
 * @param {object} proposed - the group from the request body.
 * @param {object} current - the group currently in effect, used as the base.
 * @returns {object} the settings to merge
 * @throws {Error} when the group is refused
 */
function sanitizeProviderSettings(key, proposed, current) {
  if (key !== 'custom') return proposed
  const result = sanitizeCustomSettings(proposed, current)
  if (!result.ok) throw new Error(result.error)
  return result.value
}

/**
 * Strip operator-only fields from a panel snapshot.
 *
 * Kept out of `apply()` so it can be tested directly: this function is the
 * boundary between "can use dsh web" and "can control this machine", and a
 * mistake in it is a security bug, not a UI one.
 *
 * Removed for remote callers, and why:
 *
 *   - `controlToken` — proof of being local. Handing it to a viewer is what
 *     turned "holding the link" into arbitrary code execution.
 *   - `accessKey` / `accessKeyGenerated` — the shared secret. A viewer already
 *     used it to get in; echoing it back lets them redistribute the link.
 *   - provider `args` and `tunnelCommand` — an operator may keep `--token=…` in
 *     a custom command line.
 *
 * Everything read-only stays: that a tunnel is up, where it points, whether dsh
 * web has a session. That is enough for the panel to render honestly.
 *
 * @param {object} full - the complete snapshot.
 * @param {boolean} remote - true when the request arrived through the tunnel.
 * @returns {object} the snapshot safe for that audience.
 */
export function redactSnapshot(full, remote) {
  // Always present, on both paths, so the client can test one field instead of
  // inferring "is absent" from "no control token".
  if (!remote) return { ...full, remote: false }

  const out = { ...full, remote: true }
  delete out.controlToken
  delete out.accessKey
  delete out.accessKeyGenerated

  out.config = {}
  for (const [key, group] of Object.entries(full.config || {})) {
    out.config[key] = Object.fromEntries(
      Object.entries(group || {}).filter(([name]) => name !== 'args'),
    )
  }

  // The command line embeds the arguments just removed.
  out.tunnelCommand = ''

  return out
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {any} config
 */
export function apply(ctx, config) {
  // A plugin that throws while applying stops dsh web from starting at all.
  // Everything below is therefore wrapped: a broken tunnel is a missing
  // feature, not a broken application.
  const log = (line) => {
    try {
      ctx.logger?.info?.(`[dsh-tunnel] ${line}`)
    } catch {
      /* logging must never be the thing that fails */
    }
  }

  /** Control token: minted per process, handed only to the same-origin panel. */
  const controlToken = randomBytes(18).toString('base64url')

  /** Mutable state the routes read and write. */
  const state = {
    accessKey: String(config.accessKey || '') || randomBytes(18).toString('base64url'),
    proxy: /** @type {import('node:http').Server|null} */ (null),
    // `||` would treat a legitimate 0 as "unset" and silently bind 8443 — which
    // is how a test that asked for an ephemeral port ended up colliding with a
    // real tunnel. 0 is meaningful: it asks the OS for a free port.
    proxyPort: Number.isInteger(Number(config.port)) ? Number(config.port) : 8443,
    tunnel: /** @type {{id: string, url: string, child: any, command: string, args: string[]}|null} */ (null),
    sessionCookie: '',
    lastError: '',
    starting: false,
    startedAt: 0,
  }

  /** The upstream dsh web origin, read from the webserver service each time. */
  function upstreamOrigin() {
    try {
      const webServer = ctx.get?.('webServer')
      if (webServer?.getOrigin) return webServer.getOrigin()
    } catch {
      /* not bound yet */
    }
    return ''
  }

  /**
   * Obtain a `dsh-auth-*` cookie valid for this process.
   *
   * `connection.authenticatedUrl()` adds the process launch token to a URL; a
   * request to it makes dsh web mint a browser cookie and redirect. This is the
   * only supported way for a plugin to hold a session: the cookie is bound to
   * this listener's authority, so it cannot be forged or reused elsewhere.
   *
   * Returns `''` when the host does not expose the capability (older builds) —
   * the proxy then answers 503 with an explanation instead of a mystery 401.
   */
  async function refreshSessionCookie() {
    try {
      const connection = ctx.get?.('connection')
      const origin = upstreamOrigin()
      if (!connection || !origin || typeof connection.authenticatedUrl !== 'function') return
      const signed = connection.authenticatedUrl(`${origin}/`)
      const response = await fetch(signed, { redirect: 'manual', signal: AbortSignal.timeout(5000) })
      const raw = response.headers.getSetCookie?.() ?? []
      const header = raw.length ? raw.join('\n') : response.headers.get('set-cookie') || ''
      const match = header.match(/dsh-auth-[^=\s]+=[^;\s]+/)
      if (match) {
        if (match[0] !== state.sessionCookie) log('session cookie acquired')
        state.sessionCookie = match[0]
      }
    } catch {
      /* keep the previous cookie; a transient failure is not worth clearing it */
    }
  }

  /**
   * Load `./proxy.js`, importing a fresh copy when the file has changed.
   *
   * dsh web does not hot-reload server code: an edited plugin takes effect only
   * after the whole app restarts. Nearly everything that ever needs editing lives
   * in `proxy.js`, so that made every one-line experiment cost a restart — and a
   * restart is not free when the person driving the tunnel is on a tablet and the
   * machine is somewhere else.
   *
   * The proxy is constructed on each "start", which gives a natural reload point.
   * Importing by modification time turns the loop into "edit, stop, start". The
   * installed copy never changes under a running process, so in normal use this
   * costs one `stat` per start and nothing else.
   */
  let proxyModule
  let proxyModuleStamp

  async function loadProxy() {
    const url = new URL('./proxy.js', import.meta.url)
    let stamp = ''
    try {
      stamp = String((await stat(url)).mtimeMs)
    } catch {
      /* unreadable: fall back to the ordinary module instance below */
    }
    if (!proxyModule || (stamp && stamp !== proxyModuleStamp)) {
      proxyModule = stamp ? await import(`${url.href}?v=${stamp}`) : await import(url.href)
      proxyModuleStamp = stamp
    }
    return proxyModule
  }

  /** Start the loopback proxy if it is not already listening. */
  async function ensureProxy() {
    if (state.proxy) return true
    const origin = upstreamOrigin()
    if (!origin) {
      state.lastError = 'dsh web is not listening yet'
      return false
    }
    await refreshSessionCookie()

    // A previous module instance may still be holding this port. Clear it before
    // binding, otherwise the failure looks like "another process" when it is our
    // own leaked listener — and an old proxy answering with an old key is a
    // genuinely confusing thing to debug.
    if (reclaimProxy(state.proxyPort)) {
      log(`released a leftover proxy on port ${state.proxyPort} from a previous load`)
    }

    const { createProxy: makeProxy } = await loadProxy()
    const server = makeProxy({
      upstream: origin,
      // A getter, not a snapshot: 「重置密钥」 must take effect on the running
      // proxy. Passing `state.accessKey` here made rotation cosmetic — the panel
      // showed a new key while the old one kept working.
      accessKey: () => state.accessKey,
      cookie: () => state.sessionCookie,
      log,
    })

    const ok = await new Promise((resolve) => {
      server.once('error', (error) => {
        state.lastError =
          `proxy failed to listen on ${config.host}:${state.proxyPort}: ${error.message}` +
          (error.code === 'EADDRINUSE'
            ? ' Another process is using that port — set a different port, or stop the tunnel that owns it.'
            : '')
        resolve(false)
      })
      server.listen(state.proxyPort, config.host, () => resolve(true))
    })
    if (!ok) return false

    // Port 0 asks the OS for a free port; the real one is only knowable after
    // listening, and the tunnel must be told the actual number, not 0.
    const bound = server.address()
    if (bound && typeof bound === 'object') state.proxyPort = bound.port

    state.proxy = server
    state.startedAt = Date.now()
    state.lastError = ''
    rememberProxy(state.proxyPort, server)
    log(`proxy listening on ${config.host}:${state.proxyPort} → ${origin}`)
    return true
  }

  /**
   * Stop the proxy, if running.
   *
   * `server.close()` alone does not release the port. It stops accepting new
   * connections and then waits for existing ones to finish — and this server
   * relays long-lived WebSockets (`/api/remote.mux`) plus an endless SSE channel
   * (`/plugins/events`), so those connections never finish on their own. The
   * callback therefore never fires, the listening handle stays open, and the next
   * start fails with EADDRINUSE against *our own* port. Observed exactly that:
   * the panel reported "proxy stopped" while the socket was still bound.
   *
   * `closeAllConnections()` (Node 18.2+) is what actually tears the sockets down.
   * It runs after `close()` so the two are not racing for the listener.
   */
  async function stopProxy() {
    const server = state.proxy
    state.proxy = null
    // Otherwise a stale EADDRINUSE stays pinned to the panel forever: the only
    // other place that clears it is a *successful* ensureProxy(), and a user who
    // just freed the port and pressed 「全部停止」 would still see the red line.
    state.lastError = ''
    if (!server) return
    await new Promise((resolve) => {
      let settled = false
      const done = () => {
        if (!settled) {
          settled = true
          resolve()
        }
      }
      server.close(done)
      try {
        server.closeAllConnections?.()
      } catch {
        /* older Node: fall back to the timer below */
      }
      // Never hang a shutdown on a socket that refuses to die.
      const timer = setTimeout(done, 1500)
      timer.unref?.()
    })
    forgetProxy(state.proxyPort, server)
    log('proxy stopped')
  }

  /**
   * Start the configured tunnel and wait for its public URL.
   *
   * Cloudflare Quick Tunnel is the one provider that can fail for reasons that
   * are purely transient: it has to reach `api.trycloudflare.com` to be assigned
   * a hostname, and on a slow or filtered network that request times out. The
   * failure arrives about twenty seconds later as a line of Cloudflare's own
   * logging, which tells the user nothing.
   *
   * So two things happen here that used to not:
   *
   *   1. A preflight probe. If the control plane is plainly unreachable, fail in
   *      seconds with a sentence instead of in twenty with a log excerpt.
   *   2. A bounded retry, because the probe is lenient and the first try often
   *      succeeds on a network that is merely slow rather than blocked.
   *
   * Both are skipped for providers that do not depend on Cloudflare.
   */
  async function startProvider(id) {
    if (id === 'off') {
      await stopProvider()
      return
    }
    if (!(await ensureProxy())) throw new Error(state.lastError || 'proxy unavailable')

    state.starting = true
    try {
      if (id === 'cloudflared') {
        // Used one way only: to fail fast when the route is plainly dead. A
        // positive probe is *not* a promise — Node and cloudflared use different
        // protocols, and this machine has seen "reachable (3214ms)" alongside
        // three consecutive cloudflared timeouts. So the real attempt always runs.
        const probe = await probeControlPlane()
        if (!probe.ok) {
          log(`cloudflare control plane unreachable: ${probe.detail}`)
          throw new Error(
            `api.trycloudflare.com is not reachable from this machine (${probe.detail}). ` +
              'A quick tunnel cannot be created without it. Check your network or proxy settings, ' +
              'or switch to Tailscale Funnel, which connects to a different endpoint.',
          )
        }
        log(`cloudflare control plane reachable (${probe.detail}); this does not guarantee QUIC`)
      }

      const attempts = id === 'cloudflared' ? 3 : 1
      let lastError
      for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
          const started = await startTunnel({
            id,
            config,
            port: state.proxyPort,
            upstream: upstreamOrigin(),
            log,
            attempt,
          })
          state.tunnel = { id, ...started }
          state.lastError = ''
          // The tunnel is only useful while its process lives, and nothing was
          // watching that process once this promise resolved. See watchTunnel.
          watchTunnel(id, started.child)
          log(`${id} up at ${started.url}`)
          return
        } catch (error) {
          lastError = error
          // Nothing is left running from a failed attempt: `startTunnel` kills
          // the child before rejecting, so a retry cannot leak a process.
          if (attempt < attempts) {
            log(`attempt ${attempt} failed, retrying: ${String(error?.message || error).slice(0, 120)}`)
            await new Promise((resolve) => setTimeout(resolve, 1500 * attempt))
          }
        }
      }

      const hint = attempts > 1 ? ` (tried ${attempts} times)` : ''
      throw new Error(`${String(lastError?.message || lastError)}${hint}`)
    } finally {
      state.starting = false
    }
  }

  /** Stop the running tunnel. */
  async function stopProvider() {
    const tunnel = state.tunnel
    // Nulled *first*: watchTunnel's exit handler treats "not the current child"
    // as an intentional stop, so a deliberate stop never triggers a reconnect.
    state.tunnel = null
    clearRestartTimers()
    restartAttempt = 0
    if (!tunnel) return
    await stopTunnel({ id: tunnel.id, child: tunnel.child, config, log })
    log(`${tunnel.id} stopped`)
  }

  // ── supervision ────────────────────────────────────────────────────────────
  // `startTunnel` listens for `exit` only until it has a URL to report; after
  // that the child is unsupervised. That is right for the promise, and wrong for
  // the feature: `ssh -N -R` never reconnects, Windows has no autossh, and a
  // reboot or a dropped connection left the public URL answering 502 while this
  // panel kept saying 「已对外开放」, because `state.tunnel` still held a process
  // that had already exited. cloudflared reconnects on its own, but reporting it
  // as up when it is in its retry loop is still a lie.
  //
  // So the exit is owned here: the snapshot drops back to not-exposed, the reason
  // is kept for the panel, and a new child is spawned on a backoff ladder.
  const RESTART_BACKOFF_MS = [5_000, 15_000, 30_000, 60_000]
  // Long enough that "it ran for a minute" counts as working rather than flapping,
  // which is what resets the ladder back to five seconds.
  const STABLE_AFTER_MS = 60_000
  let restartAttempt = 0
  let restartTimer = null
  let stableTimer = null

  function clearRestartTimers() {
    if (restartTimer) {
      clearTimeout(restartTimer)
      restartTimer = null
    }
    if (stableTimer) {
      clearTimeout(stableTimer)
      stableTimer = null
    }
  }

  /**
   * Take ownership of one tunnel child.
   * @param {string} id
   * @param {import('node:child_process').ChildProcess} child
   */
  function watchTunnel(id, child) {
    clearRestartTimers()
    stableTimer = setTimeout(() => {
      restartAttempt = 0
    }, STABLE_AFTER_MS)
    stableTimer.unref?.()

    child.once('exit', (code, signal) => {
      // Replaced or stopped on purpose: `state.tunnel` is either null already or
      // a different child, and restarting here would fight the operator.
      if (state.tunnel?.child !== child) return
      state.tunnel = null
      clearRestartTimers()
      const reason = `${id} exited (code ${code === null ? 'none' : code}${signal ? `, ${signal}` : ''})`
      log(reason)
      scheduleRestart(id, reason)
    })
  }

  /**
   * Try the same provider again after a loss.
   *
   * Bounded ladder, not exponential forever: five seconds covers a network blip,
   * and a minute is slow enough that a host with no route to the provider does
   * not spawn a process every tick for hours.
   *
   * @param {string} id
   * @param {string} reason
   */
  function scheduleRestart(id, reason) {
    const delay = RESTART_BACKOFF_MS[Math.min(restartAttempt, RESTART_BACKOFF_MS.length - 1)]
    restartAttempt += 1
    const seconds = Math.round(delay / 1000)
    state.lastError = `${reason}; reconnecting in ${seconds}s`
    log(state.lastError)
    restartTimer = setTimeout(() => {
      restartTimer = null
      void (async () => {
        try {
          await startProvider(id)
          log(`${id} reconnected`)
        } catch (error) {
          // startProvider already logged the specific failure; keep the loop
          // alive, otherwise one bad attempt ends supervision for good.
          scheduleRestart(id, String(error?.message || error).slice(0, 200))
        }
      })()
    }, delay)
    restartTimer.unref?.()
  }

  /** The complete snapshot; `viewOf` narrows it for the caller's audience. */
  function snapshot() {
    return {
      ok: true,
      controlToken,
      // What is *in effect*, not what the profile patch says. Starting a tunnel
      // from the panel does not rewrite the patch (that would need a restart),
      // so reporting `config.provider` here made a live tunnel display
      // 「提供者：关闭」 right next to 「已对外开放」.
      //
      // The fallback used to be `config.provider`, which lied in the other
      // direction: after the tunnel process died, the panel still named it as
      // the running provider. A provider is only "in effect" while its process
      // is alive, so a dead tunnel falls back to 'off' and `lastError` explains.
      provider: state.tunnel ? state.tunnel.id : 'off',
      // Explicit, so a caller never has to infer liveness from `publicUrl`.
      tunnelUp: Boolean(state.tunnel),
      // Kept separate so the panel can explain why the two disagree.
      configuredProvider: String(config.provider || 'off'),
      providers: PROVIDER_IDS,
      port: state.proxyPort,
      host: String(config.host || '127.0.0.1'),
      proxyRunning: state.proxy !== null,
      upstream: upstreamOrigin(),
      hasSession: Boolean(state.sessionCookie),
      accessKey: state.accessKey,
      accessKeyGenerated: !String(config.accessKey || ''),
      publicUrl: state.tunnel ? state.tunnel.url : '',
      tunnelProvider: state.tunnel ? state.tunnel.id : '',
      tunnelCommand: state.tunnel ? `${state.tunnel.command} ${state.tunnel.args.join(' ')}`.trim() : '',
      starting: state.starting,
      lastError: state.lastError,
      startedAt: state.startedAt,
      platform: process.platform,
      versions: process.versions,
      // Provider settings, so the panel can seed its form with what is actually
      // in effect instead of showing placeholders and making the user retype.
      config: {
        cloudflared: { ...(config.cloudflared || {}) },
        tailscale: { ...(config.tailscale || {}) },
        custom: { ...(config.custom || {}) },
      },
    }
  }

  /**
   * The snapshot as one audience may see it.
   * @param {boolean} remote - whether the request arrived through the tunnel.
   */
  function viewOf(remote) {
    return redactSnapshot(snapshot(), remote)
  }

  // ── routes ───────────────────────────────────────────────────────────────
  // Guarded because `webServer` may be absent (a headless profile serves no
  // browser) and because a failed registration must not stop the host.
  try {
    const webServer = ctx.get?.('webServer')
    if (webServer?.register) {
      const routes = [
        {
          path: STATUS_PATH,
          handler: async (req, res) => {
            // Read-only, so a viewer may call it — but the payload is not the
            // same for both audiences. `redactSnapshot` drops the control token
            // and the key for anything that arrived through the tunnel.
            if (rejectControlRequest(ctx, req, res, { token: controlToken, mutate: false })) return
            sendJson(res, 200, viewOf(cameThroughTunnel(req)))
          },
        },
        {
          path: START_PATH,
          handler: async (req, res) => {
            if (rejectControlRequest(ctx, req, res, { token: controlToken, mutate: true })) return
            if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
            try {
              const body = await readJson(req)
              const id = String(body.provider || config.provider || 'off')
              if (!PROVIDER_IDS.includes(id)) return sendJson(res, 400, { error: `unknown provider: ${id}` })
              await stopProvider()
              await startProvider(id)
              sendJson(res, 200, viewOf(cameThroughTunnel(req)))
            } catch (error) {
              state.lastError = String(error && error.message ? error.message : error)
              log(`start failed: ${state.lastError}`)
              sendJson(res, 500, { ...viewOf(cameThroughTunnel(req)), ok: false, lastError: state.lastError })
            }
          },
        },
        {
          path: STOP_PATH,
          handler: async (req, res) => {
            if (rejectControlRequest(ctx, req, res, { token: controlToken, mutate: true })) return
            if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
            try {
              await stopProvider()
              await stopProxy()
              sendJson(res, 200, viewOf(cameThroughTunnel(req)))
            } catch (error) {
              sendJson(res, 500, { ...viewOf(cameThroughTunnel(req)), ok: false, lastError: String(error?.message || error) })
            }
          },
        },
        {
          path: CONFIG_PATH,
          handler: async (req, res) => {
            if (rejectControlRequest(ctx, req, res, { token: controlToken, mutate: true })) return
            if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
            try {
              const body = await readJson(req)
              // Only the provider settings are writable from the panel. The key
              // and protocol stay in the profile patch so they survive upgrades.
              for (const key of ['cloudflared', 'tailscale', 'custom']) {
                if (body[key] && typeof body[key] === 'object') {
                  // `sanitizeProviderSettings` throws on a refused `custom`
                  // group, which the catch below turns into a 400.
                  config[key] = { ...config[key], ...sanitizeProviderSettings(key, body[key], config[key]) }
                }
              }
              if (body.accessKey !== undefined) {
                // Accepted only to restore a key the operator saved elsewhere.
                // It is still length-checked: a caller who sends "abc" would
                // otherwise downgrade the gate from 144 bits to 24, and nothing
                // else in the system would notice.
                const proposed = String(body.accessKey)
                if (proposed.length < MIN_ACCESS_KEY_LENGTH) {
                  throw new Error(
                    `accessKey must be at least ${MIN_ACCESS_KEY_LENGTH} characters; ` +
                      'use the regenerate button, or paste the full key',
                  )
                }
                state.accessKey = proposed
              }
              sendJson(res, 200, viewOf(cameThroughTunnel(req)))
            } catch (error) {
              sendJson(res, 400, { error: String(error?.message || error) })
            }
          },
        },
        {
          path: REGENERATE_PATH,
          handler: async (req, res) => {
            if (rejectControlRequest(ctx, req, res, { token: controlToken, mutate: true })) return
            if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' })
            state.accessKey = randomBytes(18).toString('base64url')
            log('access key regenerated')
            sendJson(res, 200, viewOf(cameThroughTunnel(req)))
          },
        },
      ]

      for (const route of routes) {
        ctx.effect(
          () => webServer.register({ kind: 'exact', path: route.path, handler: route.handler }),
          `dsh-tunnel: ${route.path}`,
        )
      }
      log('control routes registered')
    } else {
      log('webServer service unavailable; panel routes not registered')
    }
  } catch (error) {
    log(`route registration failed: ${error && error.message}`)
  }

  // ── lifecycle ────────────────────────────────────────────────────────────
  // The cookie rotates when dsh web restarts (its authority changes), so poll
  // rather than fetch once.
  ctx.effect(() => {
    const timer = setInterval(() => {
      void refreshSessionCookie()
    }, COOKIE_REFRESH_MS)
    timer.unref?.()
    void refreshSessionCookie()
    return () => clearInterval(timer)
  }, 'dsh-tunnel: session cookie refresh')

  // Start the configured tunnel on boot only when the user asked for one.
  // Default is 'off', so installing this plugin changes nothing until it is
  // configured — a tunnel is a security decision, never a side effect.
  ctx.effect(() => {
    const provider = String(config.provider || 'off')
    if (provider === 'off') {
      log('provider is off; nothing is exposed')
      return
    }
    void (async () => {
      try {
        await startProvider(provider)
      } catch (error) {
        state.lastError = String(error && error.message ? error.message : error)
        log(`autostart failed: ${state.lastError}`)
        // Boot is exactly when a tunnel is most likely to fail fast: the network
        // stack may still be coming up, or the far end may not be ready yet. Used
        // to give up here and stay down until someone opened the panel.
        scheduleRestart(provider, `autostart failed: ${state.lastError}`.slice(0, 200))
      }
    })()
    return async () => {
      await stopProvider()
      await stopProxy()
    }
  }, 'dsh-tunnel: autostart')

  // Teardown that runs on *every* unload, not only when a provider was configured
  // at boot. Without this, a tunnel started from the panel survives the plugin
  // being reloaded: the module goes away, the listening socket does not, and the
  // next instance cannot bind its own port. The registry above is the belt to
  // this braces — it also covers a reload that happens without a clean teardown.
  ctx.effect(() => {
    return async () => {
      await stopProvider()
      await stopProxy()
      reclaimProxy(state.proxyPort)
      log('torn down')
    }
  }, 'dsh-tunnel: teardown')
}

/** Re-exported for tests and for anyone embedding the proxy directly. */
export { createProxy, upstreamPath, parseCookies, ACCESS_COOKIE } from './proxy.js'
export { PROVIDERS, PROVIDER_IDS, resolveBinary } from './providers.js'
