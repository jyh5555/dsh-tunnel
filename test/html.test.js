/**
 * The document is rewritten in flight, so the rewrite needs its own tests.
 *
 * Why a rewrite at all: on a phone the browser keeps the layout viewport full
 * height and draws the keyboard over it, so a composer pinned to the bottom of a
 * `100%` layout sits under the keyboard and the user types blind.
 * `interactive-widget=resizes-content` makes the layout shrink instead — a
 * one-attribute change, but one that has to survive whatever the app already puts
 * in its viewport tag, and must never touch a non-HTML response.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createProxy } from '../lib/proxy.js'

const ACCESS_KEY = 'test-key-0123456789abcdef'

function request({ port, method = 'GET', path = '/', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    // `agent: false` keeps the client from holding a keep-alive socket open, which
    // would keep the proxy's `close()` from ever resolving and hang the test run.
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent: false }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
      )
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

/**
 * Boot a proxy in front of a stub upstream that answers one document.
 * @param {(cookie: string, port: number) => Promise<void>} run
 * @param {{body: string, type: string, encoding?: string}} upstreamResponse
 */
async function withProxy(run, upstreamResponse) {
  const upstream = http.createServer((req, res) => {
    const headers = { 'content-type': upstreamResponse.type }
    if (upstreamResponse.encoding) headers['content-encoding'] = upstreamResponse.encoding
    res.writeHead(200, headers)
    res.end(upstreamResponse.body)
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))

  const server = createProxy({
    upstream: `http://127.0.0.1:${upstream.address().port}`,
    accessKey: ACCESS_KEY,
    cookie: () => 'dsh-auth-test=1',
    log: () => {},
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port

  try {
    // Sign in the way a browser does, so the document request is past the gate.
    const login = await request({
      port,
      method: 'POST',
      path: '/__tunnel',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `key=${ACCESS_KEY}`,
    })
    const cookie = String(login.headers['set-cookie'] || '').split(';')[0]
    assert.ok(cookie.startsWith('dshtunnel='), 'the stub login must hand out the tunnel cookie')
    return await run(cookie, port)
  } finally {
    const closed = new Promise((resolve) => server.close(resolve))
    server.closeAllConnections?.()
    await closed
    // The proxy talks to the stub over the global agent, which keeps its socket
    // alive; without this the upstream's `close()` never resolves.
    upstream.closeAllConnections?.()
    await new Promise((resolve) => upstream.close(resolve))
  }
}

const fetchDocument = (cookie, port) =>
  request({ port, path: '/', headers: { cookie, accept: 'text/html' } })

test('the keyboard-resize hint is appended to the app viewport tag', async () => {
  const html =
    '<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>t</title></head><body>x</body></html>'
  await withProxy(
    async (cookie, port) => {
      const response = await fetchDocument(cookie, port)
      assert.equal(response.status, 200)
      assert.match(
        response.body,
        /content="width=device-width, initial-scale=1, interactive-widget=resizes-content"/,
      )
      // Length must describe the transformed body, or the browser truncates it.
      assert.equal(Number(response.headers['content-length']), Buffer.byteLength(response.body))
    },
    { body: html, type: 'text/html; charset=utf-8' },
  )
})

test('a viewport hint that is already there is left alone', async () => {
  const html =
    '<html><head><meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content"></head></html>'
  await withProxy(
    async (cookie, port) => {
      const response = await fetchDocument(cookie, port)
      assert.equal(response.body.match(/interactive-widget/g).length, 1, 'must not be added twice')
    },
    { body: html, type: 'text/html; charset=utf-8' },
  )
})

test('a document with no viewport tag gets one', async () => {
  await withProxy(
    async (cookie, port) => {
      const response = await fetchDocument(cookie, port)
      assert.match(
        response.body,
        /<meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content"\/>/,
      )
    },
    { body: '<html><head><title>t</title></head><body>x</body></html>', type: 'text/html' },
  )
})

test('non-HTML responses are passed through untouched', async () => {
  const payload = JSON.stringify({ note: '<meta name="viewport" content="width=device-width">' })
  await withProxy(
    async (cookie, port) => {
      const response = await request({ port, path: '/', headers: { cookie } })
      assert.equal(response.body, payload, 'JSON must not be rewritten')
    },
    { body: payload, type: 'application/json' },
  )
})

test('an already-compressed document is not rewritten', async () => {
  // Rewriting would mean decompressing and recompressing; skipping is the honest
  // trade — dsh web serves its document plainly, and a wrong gunzip is worse than
  // a missing hint.
  const html = '<html><head><meta name="viewport" content="width=device-width"></head></html>'
  await withProxy(
    async (cookie, port) => {
      const response = await fetchDocument(cookie, port)
      assert.equal(response.body, html)
      assert.doesNotMatch(response.body, /interactive-widget/)
    },
    { body: html, type: 'text/html', encoding: 'gzip' },
  )
})
