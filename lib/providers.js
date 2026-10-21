/**
 * Tunnel providers.
 *
 * A provider only has to do three things: spawn a process, report the public URL
 * it produced, and die cleanly. Everything else — restarts, backoff, the
 * access-key gate — belongs to the manager, so adding a provider never means
 * re-implementing lifecycle logic.
 *
 * Four are shipped, because "free" and "stable" pull in different directions and
 * the user is the only one who can weigh them:
 *
 *   cloudflared  free, no account, but a new hostname on every restart, and the
 *                quick-tunnel API does not support SSE.
 *   tailscale    free, permanent `*.ts.net` hostname, supports SSE and
 *                WebSocket. Needs a Tailscale account and `tailscale up` once.
 *   custom       whatever the user runs. A command that prints its public URL
 *                on stdout works with no adapter code.
 *   off          nothing public. For LAN-only operation.
 *
 * @module dsh-tunnel/providers
 */

import { spawn, execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { delimiter, join } from 'node:path'

/** Locate an executable on PATH, or accept an absolute path. */
export function resolveBinary(name, configured) {
  if (configured) return existsSync(configured) ? configured : ''
  if (process.platform === 'win32') {
    const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
    for (const dir of (process.env.PATH || '').split(delimiter)) {
      if (!dir) continue
      for (const ext of exts) {
        const candidate = join(dir, name + ext.toLowerCase())
        if (existsSync(candidate)) return candidate
        const upper = join(dir, name + ext.toUpperCase())
        if (existsSync(upper)) return upper
      }
    }
    return ''
  }
  for (const dir of (process.env.PATH || '').split(delimiter)) {
    if (!dir) continue
    const candidate = join(dir, name)
    if (existsSync(candidate)) return candidate
  }
  return ''
}

/**
 * A provider describes how to run one tunnel. It is a plain object rather than a
 * class so a user can add one in a config file without patching this module.
 *
 * @typedef {object} Provider
 * @property {string} id
 * @property {string} label - shown in the panel.
 * @property {string} requirement - what the user must arrange first, shown as a hint.
 * @property {string[]} options - config keys this provider reads.
 * @property {(ctx: {port: number, config: object, upstream: string}) => {command: string, args: string[]}|{error: string}} prepare
 * @property {(line: string) => string|undefined} [extractUrl] - parse a public URL out of stdout/stderr.
 */

/**
 * Pull the assigned hostname out of a cloudflared log line.
 *
 * Two things make the naive `/https:\/\/[a-z0-9-]+\.trycloudflare\.com/` wrong:
 *
 *   - cloudflared's banner wraps the URL in a box of `|` characters with
 *     padding, so the captured match can pick up the box art;
 *   - **error** lines mention `api.trycloudflare.com`, the control-plane host,
 *     which is not a tunnel. A failed start therefore looked like a success
 *     that handed out `https://api.trycloudflare.com`.
 *
 * So: only accept the subdomain shape a quick tunnel actually gets (three or
 * more hyphen-joined words), and never accept the API host.
 */
const QUICK_TUNNEL_HOST = /^[a-z0-9]+(?:-[a-z0-9]+){2,}$/

const tryCloudflare = (line) => {
  if (/\b(?:api|control|dash|www)\.trycloudflare\.com\b/i.test(line) && !/trycloudflare\.com\/\?/i.test(line)) {
    // A control-plane mention without an assigned hostname: not a tunnel.
    const hosts = [...line.matchAll(/https:\/\/([a-z0-9-]+)\.trycloudflare\.com/gi)]
      .map((m) => m[1])
      .filter((label) => label !== 'api' && label !== 'control' && label !== 'dash' && label !== 'www')
    if (!hosts.length) return undefined
  }
  const match = line.match(/https:\/\/([a-z0-9-]+)\.trycloudflare\.com/gi)
  if (!match) return undefined
  for (const candidate of match) {
    const label = candidate.replace(/^https:\/\//i, '').replace(/\.trycloudflare\.com$/i, '')
    if (QUICK_TUNNEL_HOST.test(label)) return candidate
  }
  return undefined
}

/** A line from `tailscale funnel status` or our own stderr reporting the URL. */
const tsNet = (line) => {
  const match = line.match(/https:\/\/[a-z0-9.-]+\.ts\.net(?::\d+)?/i)
  return match ? match[0] : undefined
}

/**
 * Cloudflare Quick Tunnel: no account, no configuration.
 *
 * `--no-autoupdate` matters — on Windows cloudflared cannot self-update and
 * prints a warning every start otherwise. The URL only appears on stderr, and
 * only once the edge accepts the connector, so the manager waits for it.
 */
const cloudflared = {
  id: 'cloudflared',
  label: 'Cloudflare Quick Tunnel',
  requirement: 'cloudflared on PATH, or set its absolute path below. No account needed.',
  options: ['cloudflared.path', 'cloudflared.extraArgs'],
  prepare({ port, config }) {
    const path = resolveBinary('cloudflared', config.path)
    if (!path) return { error: 'cloudflared was not found. Install it, or set cloudflared.path.' }
    const extra = Array.isArray(config.extraArgs) ? config.extraArgs.map(String) : []
    return {
      command: path,
      args: ['tunnel', '--url', `http://127.0.0.1:${port}`, '--no-autoupdate', ...extra],
    }
  },
  extractUrl: tryCloudflare,
}

/**
 * Tailscale Funnel: permanent hostname, SSE works.
 *
 * Funnel only accepts ports 443, 8443 and 10000 — the proxy default is 8443 so
 * that one setting serves every provider. `--bg` keeps it running after the
 * command returns; a foreground process would tie the tunnel to this plugin's
 * lifetime and lose it on reload.
 */
const tailscale = {
  id: 'tailscale',
  label: 'Tailscale Funnel',
  requirement:
    'Tailscale installed and `tailscale up` completed once. HTTPS certificates must be enabled for your tailnet.',
  options: ['tailscale.path', 'tailscale.port', 'tailscale.hostname'],
  prepare({ port, config }) {
    const path = resolveBinary('tailscale', config.path)
    if (!path) return { error: 'tailscale was not found. Install it, or set tailscale.path.' }
    const listenPort = Number(config.port) || port
    if (![443, 8443, 10000].includes(listenPort)) {
      return { error: 'Tailscale Funnel only supports ports 443, 8443 and 10000.' }
    }
    return { command: path, args: ['funnel', '--bg', String(listenPort)] }
  },
  // Funnel prints the URL on stdout when not in the background, but in `--bg`
  // mode it may print nothing, so the manager falls back to asking
  // `tailscale status --json` for the DNS name.
  extractUrl: tsNet,
}

/**
 * Custom command.
 *
 * The contract is one line of text: print the public URL containing `https://`
 * on stdout or stderr and the manager picks it up. That covers `bore`, `frp`,
 * `ngrok`, a `ssh -R` invocation with a helper script, or anything else.
 *
 * `{port}` in the args is substituted with the proxy port.
 */
const custom = {
  id: 'custom',
  label: 'Custom command',
  requirement: 'A command that prints its public https:// URL once it is up.',
  options: ['custom.command', 'custom.args'],
  prepare({ port, config }) {
    const command = String(config.command || '').trim()
    if (!command) return { error: 'Set custom.command to the executable to run.' }
    const args = Array.isArray(config.args)
      ? config.args.map((value) => String(value).replace(/\{port\}/g, String(port)))
      : []
    return { command, args }
  },
  extractUrl: (line) => {
    const match = line.match(/https:\/\/[^\s"'<>]+/i)
    return match ? match[0] : undefined
  },
}

/** Everything the manager can run. `off` is handled by the manager itself. */
export const PROVIDERS = new Map([
  [cloudflared.id, cloudflared],
  [tailscale.id, tailscale],
  [custom.id, custom],
])

/** Provider ids the panel offers, in the order it should show them. */
export const PROVIDER_IDS = ['off', cloudflared.id, tailscale.id, custom.id]

/**
 * Start one tunnel and wait until it has a public URL.
 *
 * Resolves as soon as the URL is known, so the panel can show it without the
 * user reloading. Rejects when the process exits before printing a URL, or when
 * the timeout elapses — both are actionable, so the message says what to check.
 *
 * @param {object} options
 * @param {string} options.id - provider id.
 * @param {object} options.config - plugin config, already merged with defaults.
 * @param {number} options.port - port the proxy listens on.
 * @param {string} options.upstream - loopback origin of dsh web.
 * @param {(line: string) => void} options.log
 * @param {number} [options.timeoutMs]
 * @returns {Promise<{url: string, child: import('node:child_process').ChildProcess, command: string, args: string[]}>}
 */
/**
 * Does the host itself declare a proxy?
 *
 * On Windows this is the system proxy setting, not an environment variable: the
 * environment is exactly what might be stale. Elsewhere there is no equivalent
 * authority, so an exported variable is taken at face value.
 *
 * @returns {boolean}
 */
function hostDeclaresProxy() {
  if (process.platform !== 'win32') {
    return Boolean(process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY)
  }
  try {
    // Reading the registry needs a child process; doing it synchronously on
    // every spawn would cost more than the correction is worth, so the value is
    // cached after the first read.
    if (hostProxyCache === undefined) {
      const { execFileSync } = require('node:child_process')
      const out = execFileSync(
        'reg',
        ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyEnable'],
        { encoding: 'utf8', timeout: 3000, windowsHide: true },
      )
      hostProxyCache = /ProxyEnable\s+REG_DWORD\s+0x1/i.test(out)
    }
    return hostProxyCache
  } catch {
    // Cannot tell: assume the environment knows better than we do.
    hostProxyCache = true
    return true
  }
}

/** Cached result of {@link hostDeclaresProxy}; `undefined` until first read. */
let hostProxyCache

/**
 * Environment for the tunnel child process.
 *
 * The parent environment is inherited, with two corrections.
 *
 * **1. Stale proxy variables are dropped.** A shell that once exported
 * `HTTPS_PROXY` for a different job leaves it set for everything it starts;
 * `cloudflared` then sends its QUIC handshake at that proxy, which does not speak
 * QUIC, and the tunnel dies with a bare "context deadline exceeded". The
 * environment cannot tell a good proxy from a stale one, but the system setting
 * can — so when the system declares none, the variable is treated as leftover.
 *
 * **2. Go is told to use its own DNS resolver.** `cloudflared` is a Go program,
 * and on one machine this plugin was developed on, the default resolver path
 * returned AAAA records first on a network with no working IPv6: TCP to
 * Cloudflare's IPv6 addresses failed, TCP to their IPv4 addresses succeeded, and
 * the tunnel request timed out "awaiting headers". Setting `GODEBUG=netdns=go`
 * made the same binary that had just failed register a QUIC connection on the
 * next try.
 *
 * Honest caveat: that network was *intermittently* bad, and later attempts
 * succeeded without the variable. So this is a mitigation found by experiment,
 * not a diagnosed cause, and it is not claimed to fix every timeout. It is
 * harmless when unnecessary, and it is cheap insurance on IPv4-only networks.
 *
 * @param {NodeJS.ProcessEnv} source
 * @returns {NodeJS.ProcessEnv}
 */
export function childEnvironment(source = process.env) {
  const env = { ...source }
  if (!hostDeclaresProxy()) {
    for (const name of [
      'HTTPS_PROXY',
      'https_proxy',
      'HTTP_PROXY',
      'http_proxy',
      'ALL_PROXY',
      'all_proxy',
    ]) {
      delete env[name]
    }
  }
  // Merge rather than overwrite: a caller may have set GODEBUG for something else.
  env.GODEBUG = env.GODEBUG ? `${env.GODEBUG},netdns=go` : 'netdns=go'
  return env
}

/**
 * Is the Cloudflare control plane reachable?
 *
 * A *negative* answer here is trustworthy: if Node's TLS client cannot open a
 * connection to `api.trycloudflare.com`, `cloudflared` will not manage it either.
 * A *positive* answer is not — the two speak different protocols (Node: TCP/TLS;
 * cloudflared: QUIC/UDP 7844 for the tunnel, plus HTTPS for the control plane),
 * and a network can happily pass one and drop the other.
 *
 * Measured on the machine this plugin was written on: the probe returned
 * "reachable (3214ms)" while cloudflared failed three times in a row with
 * `context deadline exceeded` against the same URL. So this function is only
 * ever used to fail *fast* on an obvious block — never to promise success, and
 * never to skip the real attempt.
 *
 * Deliberately lenient about the status code: any HTTP response counts, because
 * the question is reachability, not whether this particular request is
 * well-formed.
 *
 * @param {string} [url]
 * @param {number} [timeoutMs]
 * @returns {Promise<{ok: boolean, detail: string}>}
 */
export async function probeControlPlane(url = 'https://api.trycloudflare.com/tunnel', timeoutMs = 8000) {
  const started = Date.now()
  try {
    await fetch(url, { method: 'POST', signal: AbortSignal.timeout(timeoutMs) })
    return { ok: true, detail: `${Date.now() - started}ms` }
  } catch (error) {
    const code = error?.cause?.code || error?.name || 'unknown'
    return { ok: false, detail: `${code} after ${Date.now() - started}ms` }
  }
}

/**
 * Start one tunnel and wait until it has a public URL.
 *
 * Resolves as soon as the URL is known, so the panel can show it without the
 * user reloading. Rejects when the process exits before printing a URL, or when
 * the timeout elapses — both are actionable, so the message says what to check.
 *
 * @param {object} options
 * @param {string} options.id - provider id.
 * @param {object} options.config - plugin config, already merged with defaults.
 * @param {number} options.port - port the proxy listens on.
 * @param {string} options.upstream - loopback origin of dsh web.
 * @param {(line: string) => void} options.log
 * @param {number} [options.timeoutMs]
 * @param {1|2|3} [options.attempt] - which try this is, for the message only.
 * @returns {Promise<{url: string, child: import('node:child_process').ChildProcess, command: string, args: string[]}>}
 */
export function startTunnel({ id, config, port, upstream, log, timeoutMs = 60_000, attempt = 1 }) {
  const provider = PROVIDERS.get(id)
  if (!provider) return Promise.reject(new Error(`Unknown provider: ${id}`))

  const settings = config[id] && typeof config[id] === 'object' ? config[id] : {}
  const prepared = provider.prepare({ port, config: settings, upstream })
  if (prepared.error) return Promise.reject(new Error(prepared.error))

  const { command, args } = prepared
  log(`spawning ${provider.id}: ${command} ${args.join(' ')}${attempt > 1 ? ` (attempt ${attempt})` : ''}`)

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: childEnvironment(),
    })

    let settled = false
    let collected = ''

    const finish = (url) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ url, child, command, args })
    }

    const fail = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        child.kill()
      } catch {
        /* already gone */
      }
      reject(error)
    }

    const timer = setTimeout(() => {
      fail(new Error(`No public URL after ${Math.round(timeoutMs / 1000)}s. Last output: ${collected.slice(-400) || '(none)'}`))
    }, timeoutMs)
    timer.unref?.()

    const onLine = (line) => {
      if (!line) return
      collected = (collected + line + '\n').slice(-4000)
      log(`[${provider.id}] ${line}`)
      const url = provider.extractUrl ? provider.extractUrl(line) : undefined
      if (url) finish(url)
    }

    // Both streams: cloudflared reports the URL on stderr, most other tools on
    // stdout, and a custom command might use either.
    for (const stream of [child.stdout, child.stderr]) {
      let buffer = ''
      stream.setEncoding('utf8')
      stream.on('data', (chunk) => {
        buffer += chunk
        let index
        while ((index = buffer.indexOf('\n')) >= 0) {
          onLine(buffer.slice(0, index).trim())
          buffer = buffer.slice(index + 1)
        }
        // Some tools print the URL without a trailing newline.
        if (buffer.includes('https://') && provider.extractUrl) {
          const url = provider.extractUrl(buffer)
          if (url) onLine(buffer.trim())
        }
      })
    }

    child.on('error', (error) => fail(new Error(`Failed to start ${command}: ${error.message}`)))

    child.on('exit', (code, signal) => {
      if (settled) {
        log(`tunnel exited (code=${code} signal=${signal})`)
        return
      }
      fail(new Error(`${provider.id} exited with code ${code} before reporting a URL. ${explainOutput(provider.id, collected)}`))
    })
  })
}

/**
 * Turn a provider's raw output into something a user can act on.
 *
 * The interesting failures here are not bugs in this plugin, so a stack of
 * cloudflared log lines is the wrong thing to show. Two are common enough to
 * deserve their own sentence, and both were hit by real users of this plugin:
 *
 *   - Quick Tunnel cannot be requested, because the request never reached
 *     `api.trycloudflare.com`. Usually a firewall, a VPN, or a proxy that the
 *     child process does not inherit. The fix is "try again, or use Tailscale",
 *     not "read this TLS error".
 *   - `cloudflared` is installed but too old, or not the real binary.
 *
 * Everything else keeps the raw tail, because a mystery is worse than noise.
 *
 * @param {string} id - provider id.
 * @param {string} collected - accumulated stdout/stderr.
 * @returns {string} a sentence, never empty.
 */
export function explainOutput(id, collected) {
  const text = String(collected || '')

  if (id === 'cloudflared' && /failed to request quick Tunnel|api\.trycloudflare\.com/i.test(text)) {
    if (/deadline exceeded|timeout|no such host|dial tcp|connection refused|EOF/i.test(text)) {
      return (
        'Could not reach api.trycloudflare.com, so no temporary hostname could be created. ' +
        'This is a network problem, not a configuration one: retry, or switch to Tailscale ' +
        'Funnel if your network blocks Cloudflare. Raw output: ' +
        tail(text)
      )
    }
    return `Cloudflare refused to create the tunnel. Raw output: ${tail(text)}`
  }

  if (id === 'cloudflared' && /no such file|not recognized|ENOENT/i.test(text)) {
    return `cloudflared was not found. Set cloudflared.path in the profile patch. Raw output: ${tail(text)}`
  }

  if (id === 'tailscale' && /not logged|Logged out|needs login/i.test(text)) {
    return `Tailscale is not signed in. Run \`tailscale up\` on this machine first. Raw output: ${tail(text)}`
  }

  if (id === 'tailscale' && /Funnel is not enabled|funnel is not enabled/i.test(text)) {
    return (
      'Tailscale Funnel is disabled for this tailnet. Enable HTTPS certificates and Funnel ' +
      `in the Tailscale admin console first. Raw output: ${tail(text)}`
    )
  }

  return `Output: ${tail(text) || '(none)'}`
}

/** Last few hundred characters, on one line. */
function tail(text) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim()
  return clean.length > 400 ? '…' + clean.slice(-400) : clean
}

/**
 * Stop a tunnel started by {@link startTunnel}.
 *
 * `tailscale funnel` runs detached, so killing the child is not enough: the
 * funnel has to be turned off explicitly or it keeps serving a port the user
 * has just switched away from.
 */
export async function stopTunnel({ id, child, config, log }) {
  if (id === 'tailscale') {
    const settings = config.tailscale && typeof config.tailscale === 'object' ? config.tailscale : {}
    const path = resolveBinary('tailscale', settings.path)
    if (path) {
      await new Promise((resolve) => {
        const proc = spawn(path, ['funnel', '--bg', 'off'], { stdio: 'ignore', windowsHide: true })
        proc.on('exit', resolve)
        proc.on('error', resolve)
        setTimeout(resolve, 5000).unref?.()
      })
      log('tailscale funnel turned off')
    }
    return
  }

  if (!child || child.exitCode !== null) return
  try {
    child.kill('SIGTERM')
  } catch {
    /* already gone */
  }
  // Give it a moment, then insist — cloudflared can take a second to unwind.
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
      resolve()
    }, 3000)
    timer.unref?.()
    child.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}
