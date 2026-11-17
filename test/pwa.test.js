/**
 * "Add to home screen" has to work, so the manifest and the icons it points at
 * are part of the contract.
 *
 * The failure this locks down was silent in the browser: Chrome's install sheet
 * says only 「无法安装此应用」, and the reason — `manifest-missing-suitable-icon` —
 * is visible only through the DevTools protocol. dsh web ships a manifest with no
 * `icons` at all, so the proxy publishes its own, composited from dsh's own whale.
 *
 * Both the manifest and the icons must answer *without* the access cookie: Chrome
 * fetches them credential-less by spec, so an icon behind the key gate is an icon
 * the installer never sees.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createProxy } from '../lib/proxy.js'

/** dsh's real favicon is a whale; a triangle is enough to prove it is composed in. */
const UPSTREAM_FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" viewBox="0 0 50 50" fill="none">
  <path id="whale" d="M10 40 L25 10 L40 40 Z" fill="#000"/></svg>`

/**
 * Boot a proxy in front of a stub upstream.
 * @param {(base: string) => Promise<void>} run
 * @param {{favicon?: string | null}} [options] - omit a favicon to exercise the fallback.
 */
async function withProxy(run, options = {}) {
  const favicon = options.favicon === undefined ? UPSTREAM_FAVICON : options.favicon

  const upstream = http.createServer((req, res) => {
    if (req.url === '/favicon.svg' && favicon !== null) {
      res.writeHead(200, { 'content-type': 'image/svg+xml' })
      res.end(favicon)
      return
    }
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${upstream.address().port}`

  const server = createProxy({ upstream: origin, accessKey: 'test-key-0123456789abcdef', cookie: () => '', log: () => {} })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`

  try {
    return await run(base)
  } finally {
    await new Promise((resolve) => server.close(resolve))
    server.closeAllConnections?.()
    await new Promise((resolve) => upstream.close(resolve))
  }
}

/** Plain request: no redirects, no cookie jar, raw body. */
function get(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }))
      })
      .on('error', reject)
  })
}

test('the manifest is published without a key and declares installable icons', async () => {
  await withProxy(async (base) => {
    const response = await get(`${base}/manifest.webmanifest`)
    assert.equal(response.status, 200)
    assert.match(String(response.headers['content-type']), /manifest\+json/)

    const manifest = JSON.parse(response.body)
    assert.equal(manifest.display, 'standalone')
    assert.equal(manifest.start_url, './')
    assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 1, 'needs at least one icon')

    // Chrome's threshold, quoted from its own error: minimum-icon-size-in-pixels = 144.
    // A scalable SVG declares `any`, which satisfies it at every size.
    const scalable = manifest.icons.filter((icon) => icon.sizes === 'any' && icon.type === 'image/svg+xml')
    assert.ok(scalable.length >= 1, 'needs a scalable icon')
    assert.ok(
      manifest.icons.some((icon) => String(icon.purpose || '').includes('maskable')),
      'a maskable icon, or Android crops the mark off',
    )
  })
})

test('every icon the manifest lists is served without a key, as an SVG on a white tile', async () => {
  await withProxy(async (base) => {
    const manifest = JSON.parse((await get(`${base}/manifest.webmanifest`)).body)
    for (const icon of manifest.icons) {
      const response = await get(`${base}${icon.src}`)
      assert.equal(response.status, 200, `${icon.src} must be served without a cookie`)
      assert.match(String(response.headers['content-type']), /image\/svg\+xml/)
      assert.match(response.body, /^<svg\b/, `${icon.src} is not an SVG document`)
      assert.match(response.body, /<rect[^>]*fill="#ffffff"/, 'black artwork needs a white tile behind it')
      assert.match(response.body, /width="512" height="512"/, 'a rasterising launcher needs a size')
    }
  })
})

test("the icon is dsh's own artwork, not a substitute", async () => {
  await withProxy(async (base) => {
    const icon = await get(`${base}/__tunnel/icon.svg`)
    assert.match(icon.body, /M10 40 L25 10 L40 40 Z/, 'the upstream path must be embedded')
    assert.match(icon.body, /viewBox="0 0 50 50"/, 'the upstream coordinate system must be kept')
  })
})

test('a maskable icon is inset further so a circular launcher cannot crop the mark', async () => {
  await withProxy(async (base) => {
    const plain = await get(`${base}/__tunnel/icon.svg`)
    const maskable = await get(`${base}/__tunnel/icon-maskable.svg`)
    // The whale fills its 50x50 box, so both are pulled in a little; the maskable
    // one lands inside the safe zone.
    assert.match(plain.body, /scale\(0\.92\)/, 'the plain icon keeps a little air')
    assert.match(maskable.body, /transform="translate\([^"]*\) scale\(0\.8\)"/, 'the maskable one is scaled in')
  })
})

test('an upstream without a favicon still yields an installable icon', async () => {
  await withProxy(
    async (base) => {
      const icon = await get(`${base}/__tunnel/icon.svg`)
      assert.equal(icon.status, 200)
      assert.match(icon.body, /^<svg\b/)
      assert.match(icon.body, /fill="#ffffff"/)
      // The fallback must not pretend to be the whale it never read.
      assert.doesNotMatch(icon.body, /M10 40 L25 10 L40 40 Z/)
    },
    { favicon: null },
  )
})

test('an unknown icon path still needs the key', async () => {
  await withProxy(async (base) => {
    // Only the two declared icons are public; anything else goes through the gate.
    const response = await get(`${base}/__tunnel/icon-512.png`)
    assert.equal(response.status, 401)
  })
})
