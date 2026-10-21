# Security policy

## The model in one paragraph

`dsh-tunnel` puts a public address in front of a `dsh web` that only listens on
loopback. Holding the access key proves you may **use** that dsh web. It does not
prove you may **control** it. Those are two different powers, and the plugin
enforces the split on the server, not in the UI.

```
visitor with the key ──▶  can read and write dsh web: chat, tools, files, terminal
                          CANNOT stop the tunnel, change its config, read the key,
                          or reach the control token

operator at the machine ──▶  everything above, plus full control of the tunnel
```

The split is implemented by the reverse proxy stamping `x-dsh-tunnel-hop: 1` on
every request it forwards. The plugin strips any client-supplied value for that
header first, so it cannot be forged from outside. `index.js` treats a marked
request as remote and removes the control token, the access key, the provider
`args` and the command line from the panel snapshot.

## What is not protected

Be clear-eyed before exposing a machine. This plugin is a **door**, not a
vault, and the following are by design:

**The tunnel provider can read your traffic.** TLS terminates at the provider's
edge, so Cloudflare (or Tailscale, or whoever runs the tunnel) can see plaintext
in principle. There is no end-to-end encryption here — the plugin has no
application-layer crypto. If this matters, use Tailscale `serve` on a private
tailnet, or run a tunnel you control.

**The access key is a bearer token.** Anyone who has it is a viewer. It is
144 bits of entropy, which is not brute-forceable, but it travels in a URL
(`?key=…`) the first time, so it will appear in the tunnel provider's request
logs. Treat a leaked key as a leaked key: regenerate it.

**Rotation is the only revocation.** There is no account system, no device list,
and no remote sign-out. Regenerating the key invalidates every previously issued
cookie, because the cookie is an HMAC of the key.

**A viewer is a full dsh web user.** Once past the key gate, the visitor can do
whatever `dsh web` allows — including running tools and reading files — because
that is the point of remote access. The gate protects the *machine's tunnel
controls*, not the dsh web session.

**A viewer can also use up your model quota.** Nothing here meters or rate-limits
the dsh web session itself.

## Threat model, concretely

Protected against:

- Someone scanning `*.trycloudflare.com` subdomains and finding your address —
  they hit a 401 without the key.
- Someone with the link but not the key — 401.
- Someone with the key trying to take over the machine — 403 on every control
  route; `custom` provider commands cannot be installed or altered remotely.
- A web page you visit trying to reach the control routes — the origin fence
  rejects cross-site and foreign-`Host` requests.
- Key guessing at volume — ten failures per minute per peer, then 429.

Not protected against:

- The tunnel provider reading your conversation.
- Someone who has both the link and the key doing whatever dsh web permits.
- Physical or OS-level compromise of the host.
- Anything `dsh web` itself leaves open.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer
listed in `package.json`. Please do not file a public issue for anything that
lets a tunnel visitor escalate to operator.

Include the plugin version, whether the tunnel was public at the time, and the
smallest reproduction you have. A proof of concept is welcome; a weaponised one
is not.

Expect an acknowledgement within a few days. This is a spare-time project, so
please allow reasonable time before disclosure.

## What counts as a vulnerability

Yes:

- A viewer learning the access key or the control token.
- A viewer mutating any `/dsh-tunnel/*` route.
- Forging the hop marker or otherwise making a remote request look local.
- A response that leaks operator-only data (for example, the provider command
  line, which may embed a token).
- Any input that makes the plugin run an unintended command.

Not a vulnerability, but worth knowing:

- The provider can see plaintext (documented above).
- The key travels in a URL on first use (documented above).
- A viewer can use dsh web fully (that is the feature).
- `provider: custom` runs a command from your profile patch — that is the
  documented escape hatch, and it is only readable/writable locally.

## Supported versions

`0.1.x` is the current line. Security fixes land on `main` and are released as a
patch version. There is no backport policy yet.
