/**
 * "Add to home screen" has to work, so the manifest and the icons it points at
 * are part of the contract.
 *
 * The failure this locks down was silent in the browser: Chrome's install sheet
 * says only 「无法安装此应用」, and the reason — `manifest-missing-suitable-icon`
 * — is visible only through the DevTools protocol. dsh web ships a manifest with
 * no `icons` at all, so the proxy publishes its own.
 *
 * Both the manifest and the icons must answer *without* the access cookie: Chrome
 * fetches the manifest and its icons as credential-less requests by spec, so an
 * icon behind the key gate is an icon the installer never sees.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createProxy } from '../lib/proxy.js'

/** Boot a proxy in front of a stub upstream; the tests only touch local routes. */
async function withProxy(run) {
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<html><title>upstream</title></html>')
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

/** Minimal request that does not follow redirects and keeps the raw bytes. */
function get(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }),
        )
      })
      .on('error', reject)
  })
}

test('the manifest is published without a key, and names an icon big enough to install', async () => {
  await withProxy(async (base) => {
    const response = await get(`${base}/manifest.webmanifest`)
    assert.equal(response.status, 200)
    assert.match(String(response.headers['content-type']), /manifest\+json/)

    const manifest = JSON.parse(response.body.toString('utf8'))
    assert.equal(manifest.display, 'standalone')
    assert.equal(manifest.start_url, './')
    assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 2, 'needs at least two icons')

    // Chrome's threshold, quoted from its own error: minimum-icon-size-in-pixels = 144.
    const widths = manifest.icons.map((icon) => Number(String(icon.sizes).split('x')[0]))
    assert.ok(Math.max(...widths) >= 144, `largest icon is ${Math.max(...widths)}`)
    assert.ok(widths.includes(192) && widths.includes(512), 'the sizes Android asks for')
    assert.ok(
      manifest.icons.some((icon) => String(icon.purpose || '').includes('maskable')),
      'a maskable icon, or Android crops the mark off',
    )
  })
})

test('every icon the manifest lists is a real PNG of the size it claims', async () => {
  await withProxy(async (base) => {
    const manifest = JSON.parse((await get(`${base}/manifest.webmanifest`)).body.toString('utf8'))
    for (const icon of manifest.icons) {
      const response = await get(`${base}${icon.src}`)
      assert.equal(response.status, 200, `${icon.src} must be served without a cookie`)
      assert.equal(response.headers['content-type'], 'image/png')

      // PNG signature, then IHDR: width and height big-endian at bytes 16 and 20.
      assert.equal(
        response.body.subarray(0, 8).toString('hex'),
        '89504e470d0a1a0a',
        `${icon.src} is not a PNG`,
      )
      const [width, height] = [response.body.readUInt32BE(16), response.body.readUInt32BE(20)]
      assert.equal(`${width}x${height}`, icon.sizes, `${icon.src} claims ${icon.sizes}`)
    }
  })
})

test('an unknown icon path still needs the key', async () => {
  await withProxy(async (base) => {
    // Only the three declared icons are public; anything else goes through the gate.
    const response = await get(`${base}/__tunnel/icon-192.png.bak`)
    assert.equal(response.status, 401)
  })
})
