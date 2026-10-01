import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, errorMessage, formatBytes, formatDate, formatRelative, setCsrfToken } from './api'
import type { ApiError } from './api'

interface Call {
  url: string
  method: string
  headers: Record<string, string>
  body: string | undefined
  credentials: RequestCredentials | undefined
}

function stubFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const calls: Call[] = []
  const mock = vi.fn(async (url: string, init: RequestInit = {}) => {
    const h: Record<string, string> = {}
    new Headers(init.headers).forEach((v, k) => {
      h[k.toLowerCase()] = v
    })
    calls.push({
      url: String(url),
      method: init.method ?? 'GET',
      headers: h,
      body: typeof init.body === 'string' ? init.body : undefined,
      credentials: init.credentials,
    })
    const text = body === undefined || status === 204 ? null : JSON.stringify(body)
    return new Response(text, { status, headers: { 'Content-Type': 'application/json', ...headers } })
  })
  vi.stubGlobal('fetch', mock)
  return calls
}

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrfToken('')
})

describe('api()', () => {
  it('sends the CSRF token on mutations only', async () => {
    setCsrfToken('csrf-123')
    const calls = stubFetch(200, { data: { ok: true } })

    await api('/api/v1/me')
    expect(calls[0].headers['x-csrf-token']).toBeUndefined()

    await api('/api/v1/me/devices', { method: 'POST', json: { name: 'phone' } })
    expect(calls[1].headers['x-csrf-token']).toBe('csrf-123')
    expect(calls[1].headers['content-type']).toBe('application/json')
    expect(calls[1].body).toBe(JSON.stringify({ name: 'phone' }))
    expect(calls[1].credentials).toBe('same-origin')
  })

  it('returns undefined data for 204 responses', async () => {
    stubFetch(204, undefined)
    const r = await api<void>('/api/v1/me/devices/d1/revoke', { method: 'POST' })
    expect(r.data).toBeUndefined()
  })

  it('maps the uniform error envelope', async () => {
    stubFetch(410, {
      error: { code: 'gone', message: 'This resource is no longer available.' },
      request_id: 'req-1',
    })
    const e = await api('/api/v1/me/devices/d1/profile').catch((err: ApiError) => err)
    expect(e).toMatchObject({ code: 'gone', status: 410, request_id: 'req-1' })
    expect(errorMessage(e)).toBe('This resource is no longer available.')
  })

  it('falls back when the body is not JSON', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('<html>proxy error</html>', { status: 502 })),
    )
    const e = await api('/api/v1/health').catch((err: ApiError) => err)
    expect(e).toMatchObject({ code: 'http_error', status: 502 })
  })

  it('exposes validation details when present', async () => {
    stubFetch(400, {
      error: { code: 'validation_failed', message: 'invalid', details: { field: 'name' } },
    })
    const e = await api('/api/v1/me/devices', { method: 'POST', json: {} }).then(
      () => undefined,
      (err: ApiError) => err,
    )
    expect(e?.details).toEqual({ field: 'name' })
    expect(e?.code).toBe('validation_failed')
    expect(e?.status).toBe(400)
  })
})

describe('formatters', () => {
  it('formats byte counts', () => {
    expect(formatBytes(0)).toBe('0 o')
    expect(formatBytes(-5)).toBe('0 o')
    expect(formatBytes(1)).toBe('1 o')
    expect(formatBytes(1536)).toBe('1.5 Ko')
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1.0 Go')
    expect(formatBytes(102400)).toBe('100 Ko')
  })

  it('never divides by zero on missing timestamps', () => {
    expect(formatDate(null)).toBe('—')
    expect(formatDate(undefined)).toBe('—')
    expect(formatDate(0)).toBe('—')
    expect(formatRelative(null)).toBe('jamais')
    expect(formatRelative(undefined)).toBe('jamais')
    expect(formatRelative(Math.floor(Date.now() / 1000) - 30)).toBe('à l’instant')
    expect(formatRelative(Math.floor(Date.now() / 1000) - 600)).toBe('il y a 10 min')
    expect(formatRelative(Math.floor(Date.now() / 1000) - 7200)).toBe('il y a 2 h')
    expect(formatRelative(Math.floor(Date.now() / 1000) - 86400 * 3)).toBe('il y a 3 j')
  })

  it('returns a friendly message for unknown failures', () => {
    expect(errorMessage(null)).toBe('Une erreur est survenue.')
    expect(errorMessage('boom')).toBe('Une erreur est survenue.')
    expect(errorMessage({ message: 'nope' })).toBe('nope')
  })
})
