/**
 * Cage Authenticator core: secure storage of paired accounts, the biometric-bound key, and the server API.
 *
 * Key: RSA-2048 generated inside the Android Keystore / iOS Keychain by react-native-biometrics with "user
 * authentication required": the private key never leaves secure hardware/OS storage, and every signature needs a
 * fresh fingerprint or face match. One key serves every paired account (the library has a single key slot).
 * Messages signed must match backend/app/services/phone_auth.py exactly.
 */
import * as Crypto from 'expo-crypto'
import * as SecureStore from 'expo-secure-store'
import ReactNativeBiometrics from 'react-native-biometrics'

const rnb = new ReactNativeBiometrics({ allowDeviceCredentials: false }) // biometric only - no PIN fallback

export type Account = {
  server: string
  authenticatorId: string
  pollSecret: string
  account: string
  name: string
}

export type PendingRequest = {
  id: string
  challenge: string
  purpose: 'console' | 'windows' | 'windows_enroll'
  choices: number[]
  created_at: string
  expires_at: string
  ip: string | null
  client: string | null
  context: Record<string, string>
  organization: string | null
  account: Account
}

const ACCOUNTS = 'cage.accounts.v1'
const PUBKEY = 'cage.publickey.v1'
const STORE_OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY }

// ------------------------------------------------------------------------------------------- storage
export async function loadAccounts(): Promise<Account[]> {
  const raw = await SecureStore.getItemAsync(ACCOUNTS, STORE_OPTS)
  return raw ? (JSON.parse(raw) as Account[]) : []
}

async function saveAccounts(list: Account[]): Promise<void> {
  await SecureStore.setItemAsync(ACCOUNTS, JSON.stringify(list), STORE_OPTS)
}

export async function forgetAccount(a: Account): Promise<void> {
  const list = (await loadAccounts()).filter((x) => x.authenticatorId !== a.authenticatorId)
  await saveAccounts(list)
}

// ------------------------------------------------------------------------------------------- key
function toPem(b64: string): string {
  const body = b64.replace(/\s+/g, '')
  return `-----BEGIN PUBLIC KEY-----\n${body.match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----\n`
}

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64.replace(/\s+/g, ''))
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export async function biometricAvailable(): Promise<{ ok: boolean; kind: string | null; reason?: string }> {
  const r = await rnb.isSensorAvailable()
  return { ok: r.available, kind: r.biometryType ?? null, reason: r.error }
}

/** Public key (PEM) of the biometric key, creating the key on first use and reusing it afterwards. */
async function publicKey(): Promise<string> {
  const stored = await SecureStore.getItemAsync(PUBKEY, STORE_OPTS)
  const { keysExist } = await rnb.biometricKeysExist()
  if (stored && keysExist) return stored
  const { publicKey: b64 } = await rnb.createKeys()
  const pem = toPem(b64)
  await SecureStore.setItemAsync(PUBKEY, pem, STORE_OPTS)
  return pem
}

/** Signs with the hardware key. Shows the system fingerprint/face prompt; throws if cancelled or not matched. */
async function sign(message: string, prompt: string): Promise<string> {
  const r = await rnb.createSignature({ promptMessage: prompt, payload: message, cancelButtonText: 'Cancel' })
  if (!r.success || !r.signature) throw new Error(r.error ?? 'Biometric confirmation was cancelled')
  return r.signature.replace(/\s+/g, '') // Android Base64.DEFAULT inserts line breaks
}

async function fingerprint(pem: string): Promise<string> {
  const der = b64ToBytes(pem.replace(/-----[A-Z ]+-----/g, ''))
  const digest = await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA256, der)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

// ------------------------------------------------------------------------------------------- server
/** https everywhere; plain http only for private LAN addresses (development servers), flagged in the UI. */
export function checkServer(url: string): { ok: boolean; insecure: boolean; reason?: string } {
  let u: URL
  try { u = new URL(url) } catch { return { ok: false, insecure: false, reason: 'Invalid server address in the code' } }
  if (u.protocol === 'https:') return { ok: true, insecure: false }
  const privateHost = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(u.hostname)
  if (u.protocol === 'http:' && privateHost) return { ok: true, insecure: true }
  return { ok: false, insecure: false, reason: 'The server must use https (http is allowed only for a development server on your local network)' }
}

async function call<T>(server: string, path: string, body: unknown): Promise<T> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), 10_000)
  try {
    const r = await fetch(`${server}/api/v1${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ctrl.signal,
    })
    const data = await r.json().catch(() => ({}))
    if (!r.ok) {
      const err = new Error(typeof data.detail === 'string' ? data.detail : `Server error ${r.status}`) as Error & { status?: number }
      err.status = r.status
      throw err
    }
    return data as T
  } finally { clearTimeout(t) }
}

export type PairingCode = { v: number; type: 'cage-pair'; server: string; token: string; account?: string }

export function parsePairingCode(text: string): PairingCode {
  let d: PairingCode
  try { d = JSON.parse(text) } catch { throw new Error('This is not an Antiquarian\'s Cage pairing code') }
  if (d?.type !== 'cage-pair' || d.v !== 1 || typeof d.server !== 'string' || typeof d.token !== 'string') {
    throw new Error('This is not an Antiquarian\'s Cage pairing code')
  }
  const s = checkServer(d.server)
  if (!s.ok) throw new Error(s.reason)
  return d
}

export async function pair(code: PairingCode, deviceName: string, platform: 'android' | 'ios'): Promise<Account> {
  const pem = await publicKey()
  const fp = await fingerprint(pem)
  const signature = await sign(`CAGE-PAIR-V1|${code.token}|${fp}`, 'Confirm it\'s you to pair this phone')
  const r = await call<{ authenticator_id: string; poll_secret: string; account: string; name: string }>(
    code.server, '/authenticator/pair',
    { token: code.token, public_key_pem: pem, key_alg: 'RS256', name: deviceName, platform, signature })
  const acct: Account = { server: code.server, authenticatorId: r.authenticator_id, pollSecret: r.poll_secret,
    account: r.account, name: r.name }
  const list = (await loadAccounts()).filter((a) => !(a.server === acct.server && a.account === acct.account))
  await saveAccounts([...list, acct])
  return acct
}

/** Pending requests for all accounts. Accounts the server no longer recognises (removed/offboarded) are reported. */
export async function fetchPending(accounts: Account[]): Promise<{ requests: PendingRequest[]; revoked: Account[]; errors: string[] }> {
  const requests: PendingRequest[] = []
  const revoked: Account[] = []
  const errors: string[] = []
  await Promise.all(accounts.map(async (a) => {
    try {
      const r = await call<{ requests: Omit<PendingRequest, 'account'>[] }>(a.server, '/authenticator/pending',
        { authenticator_id: a.authenticatorId, poll_secret: a.pollSecret })
      r.requests.forEach((x) => requests.push({ ...x, account: a }))
    } catch (e) {
      if ((e as { status?: number }).status === 401) revoked.push(a)
      else errors.push(`${a.account}: ${(e as Error).message}`)
    }
  }))
  return { requests, revoked, errors }
}

export async function decide(req: PendingRequest, decision: 'approve' | 'deny', number: number): Promise<'approved' | 'denied'> {
  const prompt = decision === 'approve' ? 'Confirm it\'s you to approve this sign-in' : 'Confirm it\'s you to deny this sign-in'
  const signature = await sign(`CAGE-APPROVE-V1|${req.id}|${req.challenge}|${decision}|${number}`, prompt)
  const a = req.account
  const r = await call<{ result: 'approved' | 'denied' }>(a.server, '/authenticator/decide', {
    authenticator_id: a.authenticatorId, poll_secret: a.pollSecret, request_id: req.id, decision, number, signature,
  })
  return r.result
}
