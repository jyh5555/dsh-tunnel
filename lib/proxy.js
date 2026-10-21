/**
 * The reverse proxy that a tunnel points at.
 *
 * Why a separate server instead of pointing the tunnel at dsh web directly:
 * dsh web's `/api` fence (`isTrustedApiRequest`) only accepts loopback, the
 * listener's own bind address, or an authority declared with `--trusted-host`.
 * A tunnel terminates on a public hostname, so every request arrives with a
 * foreign `Host` and gets 403. There is no configuration that fixes this from
 * the inside, because the fence is checked before any route runs.
 *
 * So this proxy sits in front and does four things. Each one was measured
 * against a real dsh web, not guessed (see README "The four rewrites").
 *
 *   1. Rewrite `Host` to the loopback authority.
 *   2. Strip `Origin`, `sec-fetch-*`, `Referer`, and the caller's cookie —
 *      the fence rejects cross-site markers, and those are exactly what a
 *      browser attaches to a request addressed to a public hostname.
 *   3. Inject this process's `dsh-auth-*` session cookie.
 *   4. Pass SSE and WebSocket through untouched.
 *
 * Everything here is dependency-free on purpose: a tunnel plugin that drags in
 * a framework is harder to audit, and this file is the part users should read.
 *
 * @module dsh-tunnel/proxy
 */

import http from 'node:http'
import net from 'node:net'
import { timingSafeEqual, createHmac } from 'node:crypto'

/** Cookie this proxy sets to remember an accepted access key. */
export const ACCESS_COOKIE = 'dshtunnel'

/**
 * Path of the sign-in form.
 *
 * A key in a query string is in the URL: the tunnel provider logs it before this
 * process sees the request, the browser keeps it in history, and any `Referer`
 * carries it onward. A POST body has none of those properties. The query form is
 * still accepted for links already handed out, but this is what the panel gives
 * people now.
 */
export const ENTRY_PATH = '/__tunnel'

/** Longest sign-in body accepted. It carries one short string. */
const MAX_FORM_BODY = 4 * 1024

/**
 * Header added to every forwarded request, marking it as *having come through
 * the public listener*.
 *
 * This is the whole basis of the viewer/operator split. dsh web cannot tell a
 * tunnel visitor from someone sitting at the machine — the proxy always connects
 * from `127.0.0.1`, so every upstream request looks local. Stamping the hop here
 * is the only reliable signal, and it must be applied by the proxy *after*
 * stripping whatever the client sent, so it cannot be forged from outside.
 *
 * The panel then reads: marker present ⇒ remote ⇒ no secrets, no control token.
 *
 * Declared above `STRIP_REQUEST` on purpose: that set references it, and a
 * `const` used before initialisation throws at module load.
 */
export const TUNNEL_HOP_HEADER = 'x-dsh-tunnel-hop'

/** Request headers the fence would reject, or that must not cross the hop. */
const STRIP_REQUEST = new Set([
  'host',
  'origin',
  'referer',
  'cookie',
  'connection',
  'upgrade',
  'keep-alive',
  'transfer-encoding',
  'content-length',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
  'te',
  'trailer',
  'proxy-connection',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'x-real-ip',
  'forwarded',
  'cf-connecting-ip',
  'cf-ray',
  'cf-visitor',
  'cf-ipcountry',
  'cdn-loop',
  // The hop marker is stamped by this proxy and must never arrive from a client:
  // a visitor who could set it would be indistinguishable from the operator.
  TUNNEL_HOP_HEADER,
])

/** Hop-by-hop response headers. `content-length` is kept: the body is streamed as-is. */
const STRIP_RESPONSE = new Set([
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
])


/**
 * Request path, verbatim.
 *
 * `new URL(req.url, base)` cannot be used here. dsh web serves plugin bundles
 * from `/plugins/??a/client.js,b/client.js&rev=…`, where the doubled question
 * mark is the bundler's virtual-path convention, not a query separator. WHATWG
 * URL splits at the first `?`, so the pathname becomes `/plugins/` and one `?`
 * is silently dropped — upstream answers 404 and the whole front end fails to
 * boot. Only absolute-form request lines (a client configured to use this as an
 * HTTP proxy) need parsing, and those are rare enough to handle separately.
 *
 * @param rawUrl - the request line's target.
 * @returns an origin-form path with its query intact.
 */
export function upstreamPath(rawUrl) {
  const value = String(rawUrl || '/')
  if (!/^https?:\/\//i.test(value)) return value.startsWith('/') ? value : `/${value}`
  try {
    const parsed = new URL(value)
    return parsed.pathname + parsed.search
  } catch {
    return '/'
  }
}

/** Constant-time comparison; length mismatch is a fast no. */
function safeEqual(left, right) {
  const a = Buffer.from(String(left))
  const b = Buffer.from(String(right))
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/** Cookie value stored in the browser: HMAC of the key, never the key itself. */
function tokenFor(key) {
  return createHmac('sha256', String(key)).update('dshtunnel-v1').digest('base64url')
}

/** Parse a `Cookie` header into a plain object. Malformed pairs are skipped. */
export function parseCookies(header) {
  const out = {}
  for (const part of String(header || '').split(';')) {
    const index = part.indexOf('=')
    if (index < 0) continue
    const name = part.slice(0, index).trim()
    if (name) out[name] = part.slice(index + 1).trim()
  }
  return out
}

/** Copy `headers`, dropping every name in `deny`. */
function filtered(headers, deny) {
  const out = {}
  for (const [name, value] of Object.entries(headers || {})) {
    if (deny.has(name.toLowerCase())) continue
    if (value === undefined || value === null || value === '') continue
    out[name] = Array.isArray(value) ? value.join(', ') : String(value)
  }
  return out
}

/**
 * Options the proxy needs from the plugin. Kept as a plain object so the proxy
 * has no Cordis dependency and can be unit-tested on its own.
 *
 * @typedef {object} ProxyOptions
 * @property {string} upstream - loopback origin of dsh web, e.g. `http://127.0.0.1:47996`.
 * @property {string | (() => string)} accessKey - the shared secret a caller must
 *   present once. Pass a **function** when the key can be rotated: a string is
 *   read once at construction, so `POST /dsh-tunnel/key` would update the panel
 *   while the running proxy kept accepting the old key — a security bug, not a
 *   cosmetic one. A getter is re-read on every request.
 * @property {() => string} [cookie] - current `dsh-auth-*` cookie, or `''`.
 * @property {(line: string) => void} [log] - one line per request, for diagnosis.
 */

/**
 * Build the proxy server. Not listening yet: the caller decides when.
 *
 * @param {ProxyOptions} options
 * @returns {http.Server}
 */
export function createProxy(options) {
  const upstreamOrigin = new URL(options.upstream)
  const log = options.log || (() => {})

  /**
   * The accepted cookie value, recomputed per use.
   *
   * `tokenFor(key)` is an HMAC, so a rotation changes the expected cookie. The
   * key is therefore read through a getter rather than captured here: capturing
   * it made rotation a no-op on the wire while the panel displayed the new key,
   * which is worse than no rotation button at all.
   */
  const keyOf = typeof options.accessKey === 'function' ? options.accessKey : () => options.accessKey
  const expectedToken = () => tokenFor(keyOf() || '')
  /** Compare a presented cookie against the current key's HMAC (constant time). */
  const cookieAccepted = (presented) => safeEqual(String(presented || ''), expectedToken())
  /** Compare a `?key=` value against the current plaintext key (constant time). */
  const keyAccepted = (presented) => safeEqual(String(presented || ''), String(keyOf() || ''))

  /**
   * The `Set-Cookie` value for an accepted sign-in.
   *
   * `HttpOnly` so script cannot read it, `Secure` because the tunnel is HTTPS,
   * `SameSite=Lax` so a cross-site form cannot ride it, and 12 hours so a stolen
   * cookie does not outlive the day it was taken.
   */
  const accessCookie = () =>
    `${ACCESS_COOKIE}=${expectedToken()}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`

  /**
   * Read a urlencoded body, bounded.
   *
   * The sign-in form is the only consumer, and it carries one short string, so
   * anything larger is either a mistake or an attempt to make the proxy buffer.
   *
   * @param {import('node:http').IncomingMessage} req
   * @returns {Promise<Record<string, string>>}
   */
  function readForm(req) {
    return new Promise((resolve) => {
      const chunks = []
      let total = 0
      let done = false
      const finish = (value) => {
        if (done) return
        done = true
        resolve(value)
      }
      req.on('data', (chunk) => {
        total += chunk.length
        if (total > MAX_FORM_BODY) {
          req.destroy()
          return finish({})
        }
        chunks.push(chunk)
      })
      req.on('end', () => {
        const out = {}
        try {
          for (const [name, value] of new URLSearchParams(Buffer.concat(chunks).toString('utf8'))) {
            out[name] = value
          }
        } catch {
          /* an unparseable body yields no fields, so the key check fails closed */
        }
        finish(out)
      })
      req.on('error', () => finish({}))
    })
  }

  /** Snapshot of the session cookie, re-read per request so rotation is free. */
  const sessionCookie = () => (typeof options.cookie === 'function' ? options.cookie() || '' : '')

  // ── failed-attempt throttle ───────────────────────────────────────────────
  // A 144-bit key is not brute-forceable, but an unthrottled gate still invites
  // a slow drip of guesses and gives an attacker unlimited attempts. This is a
  // cheap in-memory counter, not a security boundary: it exists so that guessing
  // is *observable and slow*, never so that it is impossible.
  //
  // Keyed by peer address. Behind a tunnel every request arrives from loopback,
  // so in practice this throttles the tunnel as a whole — which is the right
  // granularity here, because the tunnel is what an attacker is hitting.
  const failures = new Map()
  const FAILURE_WINDOW_MS = 60_000
  const FAILURE_LIMIT = 10

  /** @param {string} peer */
  function throttled(peer) {
    const entry = failures.get(peer)
    if (!entry) return false
    if (Date.now() - entry.first > FAILURE_WINDOW_MS) {
      failures.delete(peer)
      return false
    }
    return entry.count >= FAILURE_LIMIT
  }

  /** @param {string} peer */
  function noteFailure(peer) {
    const now = Date.now()
    const entry = failures.get(peer)
    if (!entry || now - entry.first > FAILURE_WINDOW_MS) {
      failures.set(peer, { first: now, count: 1 })
      return
    }
    entry.count += 1
  }

  /** @param {string} peer */
  function noteSuccess(peer) {
    failures.delete(peer)
  }

  /** Peer address, or a stable placeholder when the socket is already gone. */
  const peerOf = (req) => String(req.socket?.remoteAddress || 'unknown')

  /**
   * The sign-in form.
   *
   * Served instead of a 401 page when a browser asks for HTML without a cookie,
   * so the first thing a visitor sees is a way in rather than an error. The form
   * posts to `ENTRY_PATH`, which keeps the key out of the URL bar, history, and
   * the tunnel provider's access log.
   *
   * `autocomplete="off"` and a `password` input keep the browser from offering to
   * save it: this is not a password the user will want suggested next time.
   */
  function sendEntryForm(res, note = '') {
    const body = Buffer.from(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="referrer" content="no-referrer"/>
<title>Access key · dsh-tunnel</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;box-sizing:border-box}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:26px 30px;max-width:420px;width:100%}
h1{font-size:17px;margin:0 0 10px}
p{color:#8b949e;font-size:13px;line-height:1.7;margin:0 0 16px}
label{display:block;font-size:12px;color:#8b949e;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #30363d;
background:#0d1117;color:#e6edf3;font:inherit;font-size:13px}
input:focus{outline:none;border-color:#388bfd}
button{margin-top:14px;width:100%;padding:10px 12px;border-radius:8px;border:1px solid #2ea043;
background:#238636;color:#fff;font:inherit;font-size:13px;font-weight:500;cursor:pointer}
button:hover{background:#2ea043}
.err{color:#f85149;font-size:12px;margin:0 0 12px}
</style></head><body><div class="card">
<h1>Access key required</h1>
<p>This address is reachable from the internet, so it asks for the access key once.
The key is shown in the dsh-tunnel panel inside dsh web.</p>
${note ? `<p class="err">${note}</p>` : ''}
<form method="post" action="${ENTRY_PATH}" autocomplete="off">
<label for="key">Access key</label>
<input id="key" name="key" type="password" autocomplete="off" autocapitalize="none"
 autocorrect="off" spellcheck="false" required autofocus>
<button type="submit">Continue</button>
</form>
</div></body></html>`,
      'utf8',
    )
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': String(body.length),
      // Never cache a sign-in page, and never let it be framed.
      'cache-control': 'no-store',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    })
    res.end(body)
  }

  function rewriteRequest(raw) {
    const out = filtered(raw, STRIP_REQUEST)
    out.Host = upstreamOrigin.host
    const cookie = sessionCookie()
    if (cookie) out.Cookie = cookie
    // Stamped here, after `filtered()` has already dropped any value the client
    // sent under this name. dsh web uses its presence to tell a tunnel visitor
    // from someone sitting at the machine, and the two get different powers.
    out[TUNNEL_HOP_HEADER] = '1'
    return out
  }

  function smallPage(status, title, detail) {
    const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} · dsh-tunnel</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;box-sizing:border-box}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:26px 30px;max-width:480px;width:100%}
h1{font-size:17px;margin:0 0 10px}
.code{color:#f85149;font-size:12px;margin-bottom:8px}
.msg{color:#8b949e;font-size:13px;line-height:1.7;word-break:break-word}
code{background:#0d1117;padding:1px 5px;border-radius:4px;font-size:12px}
</style></head><body><div class="card"><h1>${title}</h1>
<div class="code">HTTP ${status}</div><p class="msg">${detail}</p></div></body></html>`
    return Buffer.from(body, 'utf8')
  }

  function reply(res, status, title, detail, extraHeaders = {}) {
    const body = smallPage(status, title, detail)
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': String(body.length),
      'cache-control': 'no-store',
      ...extraHeaders,
    })
    res.end(body)
  }

  const server = http.createServer(async (req, res) => {
    const startedAt = Date.now()
    const url = new URL(req.url || '/', 'http://proxy.invalid')

    // PWA manifest and favicon are fetched without credentials by spec, so they
    // can never pass the key gate. Neither carries user data; answer locally
    // instead of showing the browser a 401.
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (url.pathname === '/manifest.webmanifest') {
        const manifest = Buffer.from(
          JSON.stringify({
            name: 'DeepSeek Harness',
            short_name: 'dsh',
            start_url: './',
            scope: './',
            display: 'standalone',
            background_color: '#151517',
            theme_color: '#151517',
          }),
          'utf8',
        )
        res.writeHead(200, {
          'content-type': 'application/manifest+json; charset=utf-8',
          'content-length': String(manifest.length),
          'cache-control': 'public, max-age=3600',
        })
        return res.end(manifest)
      }
      if (url.pathname === '/favicon.ico') {
        res.writeHead(204, { 'cache-control': 'public, max-age=86400' })
        return res.end()
      }
    }

    // ── access gate ────────────────────────────────────────────────────────
    const cookies = parseCookies(req.headers.cookie)
    const presented = cookies[ACCESS_COOKIE] || ''
    const queryKey = url.searchParams.get('key')
    const peer = peerOf(req)

    // Refuse before doing any work, so a guessing client cannot even make the
    // proxy hash a candidate key while throttled.
    if (!cookieAccepted(presented) && throttled(peer)) {
      log(`${req.method} ${url.pathname} 429 (too many failed keys)`)
      return reply(
        res,
        429,
        'Too many attempts',
        'Too many wrong access keys from this address in the last minute. ' +
          'Wait a minute and try again.',
        { 'retry-after': '60' },
      )
    }

    if (cookieAccepted(presented)) {
      // Already authorised.
      noteSuccess(peer)
    } else if (req.method === 'POST' && url.pathname === ENTRY_PATH) {
      // The preferred way in: a one-off form whose body carries the key.
      // The key never touches the URL, so it cannot land in the provider's
      // request log or leak through a `Referer` header.
      const form = await readForm(req)
      if (!keyAccepted(form.key)) {
        noteFailure(peer)
        log(`POST ${ENTRY_PATH} 401 (wrong key)`)
        return reply(res, 401, 'Wrong access key', 'The key you submitted does not match.')
      }
      noteSuccess(peer)
      log(`POST ${ENTRY_PATH} 303 (key accepted)`)
      res.writeHead(303, {
        location: form.next || '/',
        'set-cookie': accessCookie(),
        'cache-control': 'no-store',
      })
      return res.end()
    } else if (queryKey !== null) {
      // Legacy entry: `/​?key=…`. Still supported so existing links keep working,
      // but it is no longer what the panel hands out, because the URL reaches the
      // provider's logs before this process ever sees it.
      if (!keyAccepted(queryKey)) {
        noteFailure(peer)
        log(`${req.method} ${url.pathname} 401 (wrong key)`)
        return reply(res, 401, 'Wrong access key', 'The <code>?key=</code> you supplied does not match.')
      }
      noteSuccess(peer)
      url.searchParams.delete('key')
      const location = url.pathname + (url.search || '')
      log(`${req.method} ${url.pathname} 303 (key accepted, legacy query form)`)
      res.writeHead(303, {
        location,
        'set-cookie': accessCookie(),
        'cache-control': 'no-store',
      })
      return res.end()
    } else if (req.method === 'GET' && (req.headers.accept || '').includes('text/html')) {
      // A browser asking for a page without a cookie gets the entry form rather
      // than a dead end.
      return sendEntryForm(res)
    } else {
      noteFailure(peer)
      log(`${req.method} ${url.pathname} 401 (no key)`)
      return reply(
        res,
        401,
        'Access key required',
        'This address is reachable from the internet, so it needs the access key once. ' +
          `Open <code>${ENTRY_PATH}</code> in a browser and enter it. The key is shown in the ` +
          'dsh-tunnel panel inside dsh web.',
      )
    }

    // ── no session cookie yet ──────────────────────────────────────────────
    if (!sessionCookie()) {
      log(`${req.method} ${url.pathname} 503 (no session cookie)`)
      return reply(
        res,
        503,
        'No dsh web session yet',
        'The proxy is running but has not obtained a <code>dsh-auth-*</code> cookie from the host ' +
          'process. This resolves on its own once dsh web finishes starting; if it persists, ' +
          'restart dsh web.',
      )
    }

    // ── forward ────────────────────────────────────────────────────────────
    const upstream = http.request(
      {
        protocol: upstreamOrigin.protocol,
        hostname: upstreamOrigin.hostname,
        port: upstreamOrigin.port,
        method: req.method,
        path: upstreamPath(req.url),
        headers: rewriteRequest(req.headers),
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode || 502, filtered(upstreamRes.headers, STRIP_RESPONSE))
        log(`${req.method} ${url.pathname} ${upstreamRes.statusCode} ${Date.now() - startedAt}ms`)
        // Streamed, never buffered: `/plugins/events` is an endless SSE channel.
        upstreamRes.pipe(res)
        upstreamRes.on('error', () => {
          try {
            res.destroy()
          } catch {
            /* the client is already gone */
          }
        })
      },
    )

    upstream.on('error', (error) => {
      log(`${req.method} ${url.pathname} 502 ${error.message}`)
      if (res.headersSent) {
        try {
          res.destroy()
        } catch {
          /* ignore */
        }
        return
      }
      reply(
        res,
        502,
        'Cannot reach dsh web',
        `Upstream <code>${upstreamOrigin.origin}</code> refused the connection: ` +
          `<code>${String(error && error.message).replace(/[<>&]/g, '')}</code>`,
      )
    })

    req.pipe(upstream)
  })

  // ── WebSocket ─────────────────────────────────────────────────────────────
  // Raw socket relay rather than a library: this keeps every subprotocol and
  // extension intact. Dropping `Sec-WebSocket-Extensions` makes the server skip
  // permessage-deflate while the browser still expects it, and frames are then
  // misread — which presents as "connects, then immediately reconnects".
  server.on('upgrade', (req, socket, head) => {
    const cookies = parseCookies(req.headers.cookie)
    const peer = String(socket.remoteAddress || 'unknown')
    if (!cookieAccepted(cookies[ACCESS_COOKIE] || '')) {
      // Same throttle as the HTTP path: an upgrade without a cookie is a guess
      // like any other, and WebSocket frames are cheap to send in bulk.
      if (throttled(peer)) {
        log(`UPGRADE ${upstreamPath(req.url)} 429 (too many failed keys)`)
        socket.write('HTTP/1.1 429 Too Many Requests\r\nretry-after: 60\r\ncontent-length: 0\r\nconnection: close\r\n\r\n')
        socket.destroy()
        return
      }
      noteFailure(peer)
      log(`UPGRADE ${upstreamPath(req.url)} 401 (no key)`)
      socket.write('HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    noteSuccess(peer)

    const target = upstreamPath(req.url)
    const headers = rewriteRequest(req.headers)
    headers.Connection = 'Upgrade'
    headers.Upgrade = String(req.headers.upgrade || 'websocket')
    if (req.headers['sec-websocket-protocol']) {
      headers['Sec-WebSocket-Protocol'] = req.headers['sec-websocket-protocol']
    }
    if (req.headers['sec-websocket-extensions']) {
      headers['Sec-WebSocket-Extensions'] = req.headers['sec-websocket-extensions']
    }

    const upstreamSocket = net.connect(Number(upstreamOrigin.port || 80), upstreamOrigin.hostname, () => {
      let head_ = `${req.method} ${target} HTTP/1.1\r\n`
      for (const [name, value] of Object.entries(headers)) head_ += `${name}: ${value}\r\n`
      head_ += '\r\n'
      upstreamSocket.write(head_)
      if (head && head.length) upstreamSocket.write(head)
    })

    // Report the handshake result before relaying, so the panel can show whether
    // the upstream accepted the upgrade (101) or refused it.
    upstreamSocket.once('data', (chunk) => {
      const statusLine = chunk.toString('latin1').split('\r\n')[0]
      log(`UPGRADE ${target} ${statusLine}`)
      socket.write(chunk)
      upstreamSocket.pipe(socket)
      socket.pipe(upstreamSocket)
    })

    const close = () => {
      try {
        socket.destroy()
      } catch {
        /* ignore */
      }
      try {
        upstreamSocket.destroy()
      } catch {
        /* ignore */
      }
    }
    // Both sockets own a copy of every frame, so a half-close on either side
    // must tear down both. Without `end` handling a peer that closes cleanly
    // leaves the other direction open and the process never exits.
    upstreamSocket.on('error', close)
    upstreamSocket.on('close', close)
    upstreamSocket.on('end', close)
    socket.on('error', close)
    socket.on('close', close)
    socket.on('end', close)
  })

  return server
}
