/**
 * Configuration schema.
 *
 * The loader validates a plugin's `Config` through the Standard Schema
 * interface — `resolveConfig()` calls `runtime.Config['~standard'].validate()`
 * and expects `{ value }` or `{ issues }`. Schemastery implements that, but it
 * pulls in a dependency chain (`schemastery` → `cosmokit` → …) for what amounts
 * to a dozen defaults.
 *
 * Since this plugin's promise is that users can read and audit every line that
 * opens their machine to the internet, the schema is written out by hand here.
 * It is ~80 lines, has no imports, and can be unit-tested directly.
 *
 * @module dsh-tunnel/config
 */

/** Provider ids the loader will accept. */
export const PROVIDER_IDS = ['off', 'cloudflared', 'tailscale', 'custom']

/** Ports Tailscale Funnel is willing to publish. */
const FUNNEL_PORTS = new Set([443, 8443, 10000])

/**
 * A validation issue in Standard Schema shape.
 * @param {string} message
 * @param {string[]} path
 * @returns {{message: string, path: string[]}}
 */
const issue = (message, path) => ({ message, path })

/**
 * Validate and normalise a config value.
 *
 * Unknown keys are dropped (the loader may merge layers whose shape has drifted)
 * and every default is applied, so `apply()` can index the result without
 * guarding every access. Errors are reported as issues rather than thrown, which
 * is what the Standard Schema contract wants.
 *
 * @param {unknown} input
 * @returns {{value?: object, issues?: {message: string, path: string[]}[]}}
 */
export function validateConfig(input) {
  const issues = []
  const raw = input && typeof input === 'object' ? input : {}

  const provider = raw.provider === undefined ? 'off' : String(raw.provider)
  if (!PROVIDER_IDS.includes(provider)) {
    issues.push(issue(`provider must be one of ${PROVIDER_IDS.join(', ')}`, ['provider']))
  }

  const port = raw.port === undefined ? 8443 : Number(raw.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    issues.push(issue('port must be an integer between 1 and 65535', ['port']))
  }

  const host = raw.host === undefined ? '127.0.0.1' : String(raw.host)
  if (!host.trim()) issues.push(issue('host must not be empty', ['host']))

  const accessKey = raw.accessKey === undefined ? '' : String(raw.accessKey)

  /** Validate one provider's settings group; returns a normalised copy. */
  const group = (name, fields) => {
    const source = raw[name] && typeof raw[name] === 'object' ? raw[name] : {}
    const out = {}
    for (const [key, spec] of Object.entries(fields)) {
      const value = source[key]
      if (value === undefined) {
        out[key] = spec.default
        continue
      }
      if (spec.type === 'string') {
        out[key] = String(value)
      } else if (spec.type === 'string[]') {
        if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
          issues.push(issue(`${name}.${key} must be an array of strings`, [name, key]))
          out[key] = spec.default
        } else {
          out[key] = value.slice()
        }
      } else if (spec.type === 'port') {
        const parsed = Number(value)
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
          issues.push(issue(`${name}.${key} must be a port number`, [name, key]))
          out[key] = spec.default
        } else if (name === 'tailscale' && key === 'port' && !FUNNEL_PORTS.has(parsed)) {
          issues.push(issue('tailscale.port must be 443, 8443 or 10000', [name, key]))
          out[key] = spec.default
        } else {
          out[key] = parsed
        }
      }
    }
    return out
  }

  const value = {
    provider,
    port,
    host,
    accessKey,
    cloudflared: group('cloudflared', {
      path: { type: 'string', default: '' },
      extraArgs: { type: 'string[]', default: [] },
    }),
    tailscale: group('tailscale', {
      path: { type: 'string', default: '' },
      port: { type: 'port', default: 8443 },
      hostname: { type: 'string', default: '' },
    }),
    custom: group('custom', {
      command: { type: 'string', default: '' },
      args: { type: 'string[]', default: [] },
    }),
  }

  if (issues.length) return { issues }
  return { value }
}

/**
 * The value exported as `Config` for the loader. `~standard` is the only member
 * cordis reads; `validate` is also exported separately so tests can call it
 * without going through the vendor wrapper.
 */
export const Config = {
  '~standard': {
    version: /** @type {const} */ (1),
    vendor: 'dsh-tunnel',
    validate: validateConfig,
  },
}
