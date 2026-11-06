import { startAuthentication, startRegistration, browserSupportsWebAuthn } from '@simplewebauthn/browser'
import { api } from './api'

export const passkeysSupported = () => browserSupportsWebAuthn()

/** Usernameless passkey sign-in. Biometric/PIN checks happen inside the user's authenticator; nothing biometric is sent. */
export async function signInWithPasskey(): Promise<void> {
  const { challenge_id, options } = await api.post<{ challenge_id: string; options: Parameters<typeof startAuthentication>[0]['optionsJSON'] }>('/auth/passkeys/login/options')
  const credential = await startAuthentication({ optionsJSON: options })
  await api.post('/auth/passkeys/login/verify', { challenge_id, credential })
}

export async function registerPasskey(name: string): Promise<void> {
  const { challenge_id, options } = await api.post<{ challenge_id: string; options: Parameters<typeof startRegistration>[0]['optionsJSON'] }>('/auth/passkeys/register/options')
  const credential = await startRegistration({ optionsJSON: options })
  await api.post('/auth/passkeys/register/verify', { challenge_id, credential, name })
}

/** Post-login destination for SSO. Only our own OIDC authorize endpoint is allowed — never an arbitrary URL. */
export function safeNext(next: string | null): string | null {
  if (!next) return null
  if (!next.startsWith('/api/v1/oidc/authorize?') || next.includes('//') || next.includes('\\')) return null
  return next
}

const KEY = 'cage_sso_next'
export function rememberNext(next: string | null) {
  try { if (next) sessionStorage.setItem(KEY, next); else sessionStorage.removeItem(KEY) } catch { /* storage unavailable */ }
}
export function takeNext(): string | null {
  try { const v = sessionStorage.getItem(KEY); sessionStorage.removeItem(KEY); return safeNext(v) } catch { return null }
}

export function describePasskeyError(e: unknown): string | null {
  if (e instanceof Error && (e.name === 'NotAllowedError' || e.name === 'AbortError')) return 'Passkey prompt was cancelled or timed out.'
  if (e instanceof Error && e.name === 'InvalidStateError') return 'This device already has a passkey for your account.'
  return null
}
