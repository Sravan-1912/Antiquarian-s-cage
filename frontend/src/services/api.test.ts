import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, describeError, qs } from './api'

afterEach(() => {
  vi.restoreAllMocks()
  document.cookie = 'cage_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
})

function mockFetch(status = 200, body: unknown = {}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))
}

describe('api client', () => {
  it('attaches the CSRF token to state-changing requests only', async () => {
    document.cookie = 'cage_csrf=tok123'
    const f = mockFetch()
    await api.post('/x', { a: 1 })
    await api.get('/y')
    const postHeaders = f.mock.calls[0][1]!.headers as Record<string, string>
    const getHeaders = f.mock.calls[1][1]!.headers as Record<string, string>
    expect(postHeaders['X-CSRF-Token']).toBe('tok123')
    expect(getHeaders['X-CSRF-Token']).toBeUndefined()
    expect(f.mock.calls[0][1]!.credentials).toBe('same-origin')
  })

  it('normalises error responses', async () => {
    mockFetch(403, { detail: 'You do not have permission to perform this action' })
    await expect(api.get('/z')).rejects.toMatchObject({ status: 403, message: 'You do not have permission to perform this action' })
  })

  it('formats validation errors without echoing values', () => {
    const e = new ApiError(422, 'Validation failed', [{ loc: ['body', 'email'], msg: 'value is not a valid email address' }])
    expect(describeError(e)).toBe('email: value is not a valid email address')
  })

  it('builds query strings skipping empty values', () => {
    expect(qs({ a: 'x', b: '', c: undefined, d: 2 })).toBe('?a=x&d=2')
    expect(qs({})).toBe('')
  })
})
