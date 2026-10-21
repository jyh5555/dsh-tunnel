/**
 * Tests for the hand-written config schema.
 *
 * The loader validates through the Standard Schema interface, so the contract
 * worth locking down is: valid input yields a fully-populated value (so
 * `apply()` can index it without guards), and invalid input yields issues
 * instead of throwing.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { validateConfig, Config, PROVIDER_IDS } from '../lib/config.js'

test('empty input yields every default', () => {
  const { value, issues } = validateConfig({})
  assert.equal(issues, undefined)
  assert.equal(value.provider, 'off')
  assert.equal(value.port, 8443)
  assert.equal(value.host, '127.0.0.1')
  assert.equal(value.accessKey, '')
  assert.deepEqual(value.cloudflared, { path: '', extraArgs: [] })
  assert.deepEqual(value.tailscale, { path: '', port: 8443, hostname: '' })
  assert.deepEqual(value.custom, { command: '', args: [] })
})

test('undefined input is treated as empty', () => {
  const { value } = validateConfig(undefined)
  assert.equal(value.provider, 'off')
})

test('every provider id is accepted', () => {
  for (const id of PROVIDER_IDS) {
    const { value, issues } = validateConfig({ provider: id })
    assert.equal(issues, undefined, `provider ${id} was rejected`)
    assert.equal(value.provider, id)
  }
})

test('an unknown provider is an issue, not a throw', () => {
  const { value, issues } = validateConfig({ provider: 'ngrok' })
  assert.ok(Array.isArray(issues) && issues.length)
  assert.equal(value, undefined)
  assert.match(issues[0].message, /provider must be one of/)
  assert.deepEqual(issues[0].path, ['provider'])
})

test('port bounds are enforced', () => {
  for (const bad of [0, -1, 70000, 1.5, 'abc']) {
    const { issues } = validateConfig({ port: bad })
    assert.ok(issues, `port ${bad} should be rejected`)
  }
  const ok = validateConfig({ port: 3000 })
  assert.equal(ok.value.port, 3000)
})

test('numeric strings are coerced to numbers', () => {
  const { value } = validateConfig({ port: '3000' })
  assert.equal(value.port, 3000)
})

test('tailscale funnel port is restricted to the three allowed values', () => {
  for (const allowed of [443, 8443, 10000]) {
    const { value, issues } = validateConfig({ tailscale: { port: allowed } })
    assert.equal(issues, undefined, `${allowed} should be allowed`)
    assert.equal(value.tailscale.port, allowed)
  }
  const rejected = validateConfig({ tailscale: { port: 8080 } })
  assert.ok(rejected.issues)
  assert.match(rejected.issues[0].message, /443, 8443 or 10000/)
})

test('an array field rejects non-string members', () => {
  const { issues } = validateConfig({ custom: { args: ['ok', 42] } })
  assert.ok(issues)
  assert.deepEqual(issues[0].path, ['custom', 'args'])
})

test('unknown keys are dropped so a drifted layer cannot smuggle state in', () => {
  const { value } = validateConfig({ provider: 'off', sneaky: 'value', cloudflared: { path: '/x', extra: 1 } })
  assert.equal(value.sneaky, undefined)
  assert.equal(value.cloudflared.extra, undefined)
  assert.equal(value.cloudflared.path, '/x')
})

test('Config exposes the Standard Schema surface cordis calls', () => {
  const standard = Config['~standard']
  assert.ok(standard, 'Config must carry ~standard')
  assert.equal(typeof standard.validate, 'function')
  assert.equal(standard.version, 1)
  const result = standard.validate({ provider: 'tailscale' })
  assert.ok(result.value)
  assert.equal(result.value.provider, 'tailscale')
})
