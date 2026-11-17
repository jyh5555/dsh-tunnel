# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — unreleased

### Security

This release fixes three vulnerabilities that were demonstrated against a live
tunnel before being fixed. **Every earlier copy should be considered unsafe to
expose publicly.**

- **A visitor could take over the host.** `GET /dsh-tunnel/status` returned the
  panel's control token to anyone holding the access key, and every mutation
  route accepted that token as proof of being local. A visitor could therefore
  write `custom.command` and start the `custom` provider, which is a
  `spawn(command, args)` — remote code execution as the user running `dsh web`.
  Demonstrated end to end by writing a file on the host from a browser behind
  the tunnel.

  Fixed by separating viewers from operators. The proxy now stamps
  `x-dsh-tunnel-hop: 1` on every forwarded request (after stripping any
  client-supplied value under that name), and the plugin refuses every mutation
  that carries the marker. The control token is no longer included in the
  snapshot served to a remote caller.

- **A visitor could stop the tunnel.** `/dsh-tunnel/start` calls `stopProvider()`
  before starting, so any visitor could disconnect the operator. Covered by the
  same fix.

- **The `custom` provider was a remote shell.** Besides the token issue, the
  config route accepted any command and any arguments. Now: a shell
  (`cmd`, `pwsh`, `bash`, …) is refused outright, arguments may not contain shell
  metacharacters, and a blank command is ignored rather than applied.

- **Key rotation did nothing.** `createProxy()` captured an HMAC of the access
  key once at construction, so `POST /dsh-tunnel/key` updated the display while
  the running proxy kept accepting the old key *and rejecting the new one*.
  The key is now read through a getter on every request.

- **The access key could be weakened through `/config`.** The route accepted any
  non-empty string, so a caller could replace a 144-bit generated key with `abc`
  and nothing else would notice. Keys shorter than 24 characters are now refused.

- **No rate limit on the key gate.** Ten failures per minute per peer, then
  `429` with `Retry-After`. A successful key clears the counter. Applied to the
  WebSocket upgrade path too.

- **Session cookie lifetime** reduced from 30 days to 12 hours.

### Added

- The page can be installed as an app. dsh web's manifest declares no `icons`, so
  Chromium refuses to install it — and says only 「无法安装此应用」, with the real
  reason (`manifest-missing-suitable-icon`, minimum 144px) visible only through the
  DevTools protocol. The proxy now publishes its own manifest, and serves icons
  built from dsh's own whale: the upstream `favicon.svg` is read at runtime and
  composited onto a white tile, because the mark is drawn in black and would
  vanish on a dark launcher. Scalable SVG rather than PNG — one file is correct at
  48px and 512px — and reading the artwork instead of embedding its path keeps
  DeepSeek's logo out of this repository. Verified against the engine itself:
  `Page.getInstallabilityErrors` went from two errors to none. Both the manifest
  and the icons answer without the access cookie, because Chrome fetches them
  credential-less by spec; tests cover that, the composition, the maskable inset,
  the fallback when the upstream favicon is missing, and that an undeclared path
  still needs the key.
- `SECURITY.md` documenting the viewer/operator model, the threat model, and
  what is deliberately *not* protected.
- A read-only panel view. Reached through the tunnel, the panel says so and
  hides the controls that would only ever return 403, instead of offering
  buttons that fail.
- `explainOutput()` turns provider failures into sentences: an unreachable
  `api.trycloudflare.com` now says "network problem, retry or use Tailscale"
  instead of surfacing an unrelated cloudflared log line.
- Bounded retry for Cloudflare Quick Tunnel (three attempts, backing off), since
  its control plane fails transiently on slow or filtered networks.
- A control-plane preflight that fails *fast* when the route is plainly dead. It
  never promises success: on the machine this was written on, the probe reported
  "reachable (3214ms)" while cloudflared timed out three times in a row, because
  Node speaks TCP/TLS and cloudflared speaks QUIC.
- Tunnel child processes no longer inherit a stale `HTTPS_PROXY` when the host
  declares no proxy (checked against the Windows system setting, not the
  environment — the environment is what might be stale).
- `cloudflared` is spawned with `GODEBUG=netdns=go`. On an IPv4-only network the
  default resolver path returned AAAA records first and the control-plane request
  timed out "awaiting headers"; with Go resolving on its own, the same binary
  registered a QUIC connection. Recorded as a mitigation, not a diagnosed fix:
  that network was intermittent, and later attempts succeeded without it.
- The tunnel child is now supervised. `startTunnel` stopped listening for `exit`
  as soon as it had a URL to report, which is correct for a promise and wrong for
  a feature: `ssh -N -R` never reconnects, Windows ships no `autossh`, and one
  dropped connection left the tunnel down for good. The plugin now keeps the exit:
  the panel drops back to 「未对外开放」, the reason stays visible, and the tunnel is
  retried on a 5s / 15s / 30s / 60s ladder that resets after a minute of uptime. A
  deliberate stop cancels the ladder. A *boot-time* failure is retried too, because
  boot is exactly when the network is least ready.
- Test suites: `test/security.test.js`, `test/e2e-viewer.mjs`,
  `test/e2e-real-dsh.mjs` (real `dsh web`), `test/attack-scenarios.mjs`,
  `test/client-contract.mjs`, `test/smoke-after-restart.mjs`,
  `test/supervision.mjs` (boots the real `apply()` and kills the child on purpose).
  `npm run test:all` runs everything.

### Changed

- `snapshot()` is split into `snapshot()` (everything) and `redactSnapshot()`
  (what one audience may see), so the security boundary is a pure function that
  can be unit-tested.
- The `plugins.item` entry is no longer registered: the tunnel panel is an
  operation console, and rendering it inline in the Plugins page made that page
  enormous. The sidebar and Settings entries remain.
- `peerDependencies` no longer lists `@deepseek-ai/dsh`. The host always provides
  it, and declaring it made a plain `npm install dsh-tunnel` pull the whole
  harness into a standalone project — it hung for minutes and then left a
  dependency tree nobody wanted. Only `react` is declared now, which is what the
  other DSH plugins do.
- `engines.dsh` dropped: npm does not know that key, and the compatibility
  contract is documented in the README instead.

### Fixed

- A dead tunnel still displayed 「已对外开放」. `publicUrl` came from the configured
  address, and `state.tunnel` was only cleared by an explicit stop, so after the
  child exited the panel described a process that no longer existed — for hours,
  in the case that prompted the supervisor above. A provider is now only reported
  as running while its child is alive, and the snapshot carries an explicit
  `tunnelUp` flag so nothing has to infer liveness from a URL string.

- The sidebar panel could not scroll on a phone. `main` panels are mounted in a
  flex column with `overflow: hidden`, so the panel has to be its own scroll
  container; it previously declared no height and no overflow.
- The panel showed 「提供者：关闭」 next to 「已对外开放」 for a tunnel started
  from the panel, because it displayed the configured provider instead of the
  running one.
- 「全部停止」 did not clear `lastError`, so a stale error stayed pinned to the
  panel after the cause was gone.

## [0.1.0] — initial

- First release: a loopback reverse proxy that makes `dsh web` accept traffic
  from a tunnel, plus four provider choices (`off`, Cloudflare Quick Tunnel,
  Tailscale Funnel, custom command), a settings panel, and a sidebar entry.
- Four rewrites make the `/api` Host fence accept tunnel traffic: `Host`
  rewritten to the loopback authority, cross-site markers stripped, the
  process's `dsh-auth-*` cookie injected, and SSE/WebSocket passed through
  untouched.
- Zero runtime dependencies: every import in `lib/` is a `node:` builtin.

[0.2.0]: https://github.com/jyh5555/dsh-tunnel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jyh5555/dsh-tunnel/releases/tag/v0.1.0
