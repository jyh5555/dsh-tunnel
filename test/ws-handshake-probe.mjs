// Probe a WebSocket handshake through the public tunnel without a browser.
//
// Written because the failure is browser-specific: the page loads in Chrome but
// its live channel never connects, while the same page is fine in Yandex. A raw
// TLS + handshake gives the one fact that a browser console would give — the
// status line — and nothing else in the chain is involved.
//
// Usage: node tmp-ws-probe.mjs <host> [--cookie name=value] [--basic user:pass] [paths...]
import tls from 'node:tls'
import { randomBytes } from 'node:crypto'

const [host, ...rest] = process.argv.slice(2)
let cookie = ''
let basic = ''
const paths = []
for (let i = 0; i < rest.length; i++) {
  if (rest[i] === '--cookie') cookie = rest[++i]
  else if (rest[i] === '--basic') basic = rest[++i]
  else paths.push(rest[i])
}

function probe(path) {
  return new Promise((resolve) => {
    const lines = [
      `GET ${path} HTTP/1.1`,
      `Host: ${host}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${randomBytes(16).toString('base64')}`,
      'Sec-WebSocket-Version: 13',
      `Origin: https://${host}`,
      'User-Agent: probe',
    ]
    if (cookie) lines.push(`Cookie: ${cookie}`)
    if (basic) lines.push(`Authorization: Basic ${Buffer.from(basic).toString('base64')}`)
    const request = lines.join('\r\n') + '\r\n\r\n'

    const socket = tls.connect({ host, port: 443, servername: host }, () => {
      socket.write(request)
    })
    let buffer = ''
    const done = (result) => {
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(15000, () => done(`${path}: timeout`))
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      const end = buffer.indexOf('\r\n\r\n')
      if (end >= 0) {
        const head = buffer.slice(0, end)
        const status = head.split('\r\n')[0]
        const upgrade = /^upgrade:/im.test(head) ? 'upgrade-present' : 'no-upgrade'
        // A 401 from Caddy's basic_auth is distinguishable from a 401 from the
        // tunnel proxy: only Caddy sends a challenge.
        const challenge = /^www-authenticate:/im.test(head) ? 'caddy-basic-auth' : 'from-tunnel-proxy'
        const server = (head.match(/^server:\s*(.+)$/im) || [, ''])[1].trim()
        done(`${path}: ${status} [${upgrade}] [${challenge}]${server ? ` [server=${server}]` : ''}`)
      }
    })
    socket.on('error', (error) => done(`${path}: error ${error.message}`))
  })
}

for (const path of paths) console.log(await probe(path))
