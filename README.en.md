# dsh-tunnel

[中文说明](./README.md) · **English**

**A public address for your DeepSeek Harness — through the tunnel you choose.**

`dsh web` listens on loopback only, and for good reason: its `/api` fence trusts
exactly three authorities — loopback, the listener's own bind address, or one you
declare with `--trusted-host`. The fence is checked **before any route runs**, so
putting a tunnel in front is not enough; every request arrives with a foreign
`Host` and gets a 403.

This plugin runs a small reverse proxy that performs the rewrites `dsh web`
requires, then **you decide** how traffic reaches that proxy:

| Provider | Cost | Address | SSE | Needs |
|---|---|---|---|---|
| **Tailscale Funnel** | free | permanent `*.ts.net` | ✅ | a Tailscale account, one `tailscale up` |
| **Cloudflare Quick Tunnel** | free | new address each restart | ❌ | `cloudflared` installed |
| **Custom command** | whatever you run | whatever you run | up to you | a command that prints an `https://` URL |
| **Off** | — | — | — | nothing exposed |

No account system, no relay server, no vendor lock-in. The proxy is about 450
lines of **zero-runtime-dependency** Node code you can read in one sitting.

> **Security note:** holding the access key means "may use your `dsh web`", not
> "may control this machine". The plugin enforces that split on the server —
> a visitor cannot stop the tunnel, change its config, or read the key.
> The full threat model, including what is deliberately *not* protected, is in
> [SECURITY.md](./SECURITY.md). Read it before exposing anything.

---

## Install

```bash
# from npm (once published)
dsh plugin install dsh-tunnel

# from a local checkout
dsh plugin install link:/absolute/path/to/this/plugin
```

Restart `dsh web` afterwards. The plugin appears as a **sidebar row named
「隧道」**, and also under **Settings → 隧道**.

`provider` defaults to `off`, which means: **installing this exposes nothing
until you choose.** A tunnel is a security decision, never an install side effect.

---

## Configure

### Tailscale Funnel (recommended for daily use)

```yaml
- id: dsh-tunnel
  name: dsh-tunnel
  config:
    provider: "tailscale"
    tailscale:
      port: 8443
```

Requires `tailscale up` once, and HTTPS certificates enabled for your tailnet in
the Tailscale admin console. Funnel only publishes 443, 8443, or 10000.

The advantage over a quick tunnel: the hostname is permanent, and SSE works
(so plugin hot-reload reaches you remotely).

### Cloudflare Quick Tunnel

```yaml
- id: dsh-tunnel
  name: dsh-tunnel
  config:
    provider: "cloudflared"
```

```bash
# Windows:  winget install Cloudflare.cloudflared
# macOS:    brew install cloudflared
# Linux:    see the official download page
```

Free and accountless, but the hostname changes on every restart and **Quick
Tunnel does not support SSE** — so hot-reload will not reach you remotely.
Chat, tools, and approvals go over WebSocket and are unaffected.

### Custom command

```yaml
- id: dsh-tunnel
  name: dsh-tunnel
  config:
    provider: "custom"
    custom:
      command: "bore"
      args: ["local", "{port}", "--to", "bore.pub"]
```

`{port}` is replaced with the proxy port. The command must print a public
`https://` URL on stdout or stderr once it is up.

> The panel can tune a `custom` command but cannot install one from scratch:
> shells are refused, and arguments may not contain shell metacharacters.

---

## The four rewrites

Each one was measured against a real `dsh web`, not guessed.

### 1. `Host` must be rewritten to the loopback authority

That is what the fence compares against.

### 2. `Origin` and `sec-fetch-*` must be stripped

The fence rejects cross-site markers, and those are exactly what a browser
attaches to a request addressed to a public hostname.

### 3. A `dsh-auth-*` session cookie must be injected

Obtained through `connection.authenticatedUrl()`, which is the only supported way
for a plugin to hold a session. The cookie is bound to this listener's authority,
so it cannot be forged or reused elsewhere.

### 4. `/plugins/??a,b` must not be parsed as a URL

dsh web serves plugin bundles from `/plugins/??a/client.js,b/client.js&rev=…`,
where the doubled question mark is the bundler's virtual-path convention. WHATWG
`URL` splits at the first `?`, so the pathname becomes `/plugins/` and one `?` is
silently dropped — upstream answers 404 and the whole front end fails to boot.

### Bonus: WebSocket extensions must pass through untouched

Drop `Sec-WebSocket-Extensions` and the server skips `permessage-deflate` while
the browser still expects it. Frames are then misread, which presents as
"connects, then immediately reconnects, forever".

---

## Access key

The tunnel address is public. Every request is checked for the shared key before
being forwarded; without it you get a 401 page and never reach `dsh web`.

- First visit: `https://<host>/?key=<key>` — sets a `Secure`, `HttpOnly` cookie
  (12 hours) and removes the key from the address bar.
- Regenerating the key in the panel invalidates every previously issued device
  **immediately** — the cookie is an HMAC of the key, so a new key revokes all old
  cookies.
- Ten wrong attempts per minute are throttled (`429` + `Retry-After: 60`); one
  correct key clears the counter.
- `manifest.webmanifest` and `favicon.ico` are answered locally: browsers fetch
  those without credentials by spec, so they could never pass the gate.

### Visitors and operators are different powers

This is the most important design decision in the plugin. Holding the key makes
you a **viewer**:

| | Viewer (has the key) | Operator (on the machine) |
|---|---|---|
| Use dsh web (chat, tools, files, terminal) | ✅ | ✅ |
| See whether the tunnel is up, and its address | ✅ | ✅ |
| Start / stop the tunnel | ❌ 403 | ✅ |
| Change provider configuration | ❌ 403 | ✅ |
| See the plaintext key or control token | ❌ never sent | ✅ |

The proxy stamps `x-dsh-tunnel-hop: 1` on every request it forwards — **after
stripping any client-supplied value for that header**, so it cannot be forged
from outside. Seeing the marker, the plugin treats the request as remote:
`/status` withholds the control token and the key, and
`/start`, `/stop`, `/config`, `/key` all answer 403.

When the panel is read-only it says so, and hides the controls that would only
ever return 403.

> Earlier builds had no such split: `/status` returned the control token to
> anyone holding the key, and the `custom` provider is a
> `spawn(command, args)` — so "has the link" meant "can execute arbitrary
> commands on this machine". Fixed in 0.2.0; see [CHANGELOG](./CHANGELOG.md)
> and [SECURITY.md](./SECURITY.md).

---

## What this plugin deliberately does **not** do

- **No end-to-end encryption.** TLS terminates at the tunnel edge, so the
  provider can see plaintext in principle. If that matters, run a tunnel you
  control, or don't expose anything.
- **No accounts, device list, or remote sign-out.** The door has one shared key;
  the only way to revoke is to regenerate it.
- **No usage limits.** Past the gate, a viewer is a full `dsh web` user and will
  consume your model quota.
- **No auto-update.** The tunnel command is the one you configured.

---

## Configuration reference

In the profile's `cordis.patch.yml` (see
[`examples/profile-cordis.patch.yml`](examples/profile-cordis.patch.yml)):

```yaml
- id: dsh-tunnel
  name: dsh-tunnel
  config:
    provider: "off"        # off | cloudflared | tailscale | custom
    port: 8443             # proxy listen port; 8443 works for every provider
    host: "127.0.0.1"      # keep it loopback: the tunnel is on this machine
    accessKey: ""          # blank = generated per start
    cloudflared:
      path: ""             # blank = find on PATH
      extraArgs: []
    tailscale:
      path: ""             # blank = find on PATH
      port: 8443           # 443 | 8443 | 10000
    custom:
      command: ""          # e.g. "bore"
      args: []             # e.g. ["local", "{port}", "--to", "bore.pub"]
```

---

## Development

Zero runtime dependencies — every `import` in `lib/` is a `node:` builtin. That is
deliberate: the file that exposes your machine to the internet should be readable
in one sitting, and a dependency chain is a supply chain.

```bash
npm run test:all         # everything: unit + end-to-end + attacks + client contract
npm test                 # unit (proxy / config / providers / security)
npm run test:e2e         # real proxy + fake upstream, full attack chain
npm run test:real        # real proxy in front of the live dsh web (needs it running)
npm run test:attacks     # five attacker stories, asserted end to end
npm run test:client      # read-only panel contract
npm run test:integration # drives apply() against a mock ctx
npm run test:live        # actually launches cloudflared (if installed)
```

| Test | Covers |
|---|---|
| `test/proxy.test.js` | path handling (including the `??` trap), the key gate, header rewrites, WebSocket relay with extensions, **key rotation actually taking effect** |
| `test/config.test.js` | the hand-written Standard Schema: defaults, ranges, coercion, unknown-field rejection |
| `test/providers.test.js` | URL extraction (including the control-plane line once mistaken for a tunnel), whether failures read like sentences, child-process environment hygiene, the control-plane probe |
| `test/security.test.js` | the hop marker cannot be forged (WebSocket path included), the `redactSnapshot` boundary, `custom` command validation, the throttle |
| `test/e2e-viewer.mjs` | real proxy + fake upstream; replays the old "viewer gets the token → runs a command" chain and asserts 403 at every step |
| `test/e2e-real-dsh.mjs` | the same proxy pointed at the **live dsh web**: the real origin fence accepts it, the real app loads, the real `/api` answers, the real WebSocket upgrades |
| `test/attack-scenarios.mjs` | five narrated attacks: a snooping visitor, a takeover attempt, a stolen token, a malicious page, a mistyped shell |
| `test/client-contract.mjs` | the read-only view really hides every control that would 403; a real remote snapshot (fields missing) does not crash the panel |
| `test/integration.mjs` | real `apply()` against a mock `ctx`: route registration, token gate, key rotation, start/stop, config writes |
| `test/smoke-after-restart.mjs` | loads the *deployed* code and checks what a restart will actually produce |
| `test/provider-live.mjs` | actually launches `cloudflared`; both the success and failure branches count as a pass |

The proxy and provider modules import nothing from Cordis, so they are testable
without running `dsh web`. The config schema hand-implements the Standard Schema
interface (`~standard.validate`) — `schemastery` was removed because it dragged in
`cosmokit` and a long chain for a dozen defaults.

The client bundle is hand-written too: `window.__ModuleLoader__.load({id,
factory})` is the entire protocol, and a settings panel is not worth a build step.

### Each test exists because of a bug that was *run into*

1. **Token deadlock.** `GET /status` required the control token, but the token
   could only come from `/status`. Now: reads are gated by the Host/Origin fence;
   only mutations require the token.
2. **Port 0 swallowed into 8443.** `Number(config.port) || 8443` treated a
   legitimate `0` ("give me a free port") as unset, so a test grabbed the port of
   a real running tunnel. Also: after listening, read the real port back from
   `server.address()`, because the tunnel must be told the actual number.
3. **A failed start looked like a success.** The URL extractor matched
   `api.trycloudflare.com` inside cloudflared's *error* line and returned it as
   the tunnel address. It now requires a three-word subdomain and rejects
   control-plane hosts.
4. **Key rotation was decorative.** `createProxy()` froze the key's HMAC at
   construction, so the panel showed a new key while the running proxy kept
   accepting the old one and rejecting the new one — worse than having no rotate
   button. The key is now read through a getter per request.
5. **The sidebar panel would not scroll on a phone.** `main` panels mount in an
   `overflow:hidden` flex column, so the panel must be its own scroll container;
   it previously declared neither height nor overflow.
6. **The Plugins page was blown up by the tunnel panel.** `plugins.item` is for
   plugins with a small config form; a full operation console made that page
   enormous. The entry was removed; sidebar and Settings remain.

---

## License

MIT.
