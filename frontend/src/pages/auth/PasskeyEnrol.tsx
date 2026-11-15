import { useState, type FormEvent } from 'react'
import { KeyRound } from 'lucide-react'
import { Alert, Button, Field, Input } from '@/components/ui/primitives'
import { describeError } from '@/services/api'
import { describePasskeyError, enrolPasskey, passkeysSupported } from '@/services/passkeys'

/**
 * Passwordless enrolment ceremony shared by bootstrap, invitations and recovery: the caller supplies a single-use
 * token; on success the server has signed the user in, and onDone() runs (usually navigate to the dashboard).
 */
export function PasskeyEnrol({ token, defaultName = 'This device', cta = 'Create passkey', onDone }: {
  token: string | null; defaultName?: string; cta?: string; onDone: () => void | Promise<void>
}) {
  const [name, setName] = useState(defaultName)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!token) return setError('This link is missing its token. Use the link exactly as you received it.')
    if (!passkeysSupported()) return setError('This browser or device does not support passkeys. Use a device with a fingerprint, face unlock, Windows Hello or a security key.')
    setBusy(true)
    try {
      await enrolPasskey(token, name.trim() || 'Passkey')
      await onDone()
    } catch (err) {
      setError(describePasskeyError(err) ?? describeError(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      {error && <Alert>{error}</Alert>}
      <p className="text-sm text-silver-400">
        You'll be asked for your fingerprint, face, device PIN, Windows Hello, or a security key. Your biometrics never
        leave your device — only a public key is stored. This is your password-free sign-in from now on.
      </p>
      <Field label="Name this passkey" htmlFor="pkname"><Input id="pkname" required maxLength={64} value={name}
        onChange={(e) => setName(e.target.value)} placeholder="e.g. Work laptop, iPhone" /></Field>
      <Button type="submit" className="w-full" loading={busy} disabled={!token}><KeyRound />{cta}</Button>
    </form>
  )
}
