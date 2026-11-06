/**
 * Central API client. Sends the session cookie (same-origin), attaches the CSRF token to every
 * state-changing request, and normalises errors. Authorization is enforced by the backend.
 */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public fieldErrors: { loc: (string | number)[]; msg: string }[] = [],
  ) {
    super(message)
  }
}

const BASE = '/api/v1'
const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export function readCookie(name: string): string | null {
  const match = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`))
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

export async function request<T>(method: string, path: string, body?: unknown, opts: { raw?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (UNSAFE.has(method)) {
    const token = readCookie('cage_csrf')
    if (token) headers['X-CSRF-Token'] = token
  }
  const res = await fetch(BASE + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    let detail = res.statusText || 'Request failed'
    let fieldErrors: ApiError['fieldErrors'] = []
    try {
      const data = await res.json()
      if (typeof data.detail === 'string') detail = data.detail
      if (Array.isArray(data.errors)) fieldErrors = data.errors
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 401 && onUnauthorized && !path.startsWith('/auth/login') && !path.startsWith('/auth/mfa')) {
      onUnauthorized()
    }
    throw new ApiError(res.status, detail, fieldErrors)
  }
  if (opts.raw) return res as unknown as T
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export const api = {
  get: <T>(p: string) => request<T>('GET', p),
  post: <T>(p: string, b?: unknown) => request<T>('POST', p, b ?? {}),
  put: <T>(p: string, b?: unknown) => request<T>('PUT', p, b ?? {}),
  patch: <T>(p: string, b?: unknown) => request<T>('PATCH', p, b ?? {}),
  del: <T>(p: string) => request<T>('DELETE', p),
}

export function qs(params: Record<string, string | number | undefined | null>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  const s = u.toString()
  return s ? `?${s}` : ''
}

/** Download a CSV through fetch so the CSRF/cookie rules and error handling stay consistent. */
export async function download(path: string, filename: string) {
  const res = await request<Response>('GET', path, undefined, { raw: true })
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.fieldErrors.length) return e.fieldErrors.map((f) => `${f.loc.slice(1).join('.')}: ${f.msg}`).join('; ')
    return e.message
  }
  return 'Unexpected error. Check your connection and try again.'
}
