import { useState, type FormEvent } from 'react'
import { KeyRound } from 'lucide-react'
import { PasskeyEnrol } from './PasskeyEnrol'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AuthLayout } from '@/layouts/AuthLayout'
import { Alert, Button, Field, Input, Spinner } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'
import { useAuth } from '@/hooks/useAuth'
import { describePasskeyError, passkeysSupported, safeNext, signInWithPasskey } from '@/services/passkeys'

export function LoginPage() {
  const { me, refresh } = useAuth()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const next = safeNext(params.get('next'))
  const appName = params.get('app')
  const stepUp = params.get('step_up') === '1'
  const [error, setError] = useState<string | null>(null)
  const [pkBusy, setPkBusy] = useState(false)
  const setup = useQuery({ queryKey: ['bootstrap'], queryFn: () => api.get<{ needs_setup: boolean }>('/auth/bootstrap-status') })

  if (me && next && !stepUp) { window.location.assign(next); return null }  // already signed in, returning to an app
  if (me && !next) return <Navigate to="/" replace />
  if (setup.data?.needs_setup) return <Navigate to="/setup" replace />

  async function done() {
    if (next) { window.location.assign(next); return }
    await refresh()
    nav('/')
  }

  async function passkey() {
    setPkBusy(true)
    setError(null)
    try {
      await signInWithPasskey()
      await done()
    } catch (err) {
      setError(describePasskeyError(err) ?? describeError(err))
    } finally {
      setPkBusy(false)
    }
  }

  const subtitle = appName ? `to continue to ${appName}` : 'Antiquarian\'s Cage console and workspace'
  return (
    <AuthLayout title="Sign in" subtitle={subtitle}>
      <div className="space-y-4">
        {stepUp && <Alert tone="warning">{appName ?? 'This application'} requires a passkey sign-in to continue.</Alert>}
        {error && <Alert>{error}</Alert>}
        {passkeysSupported()
          ? <Button type="button" variant="primary" className="w-full" onClick={passkey} loading={pkBusy}><KeyRound />Sign in with a passkey</Button>
          : <Alert>This browser does not support passkeys. Use a device with Windows Hello, Touch ID, or a security key.</Alert>}
        <p className="text-center text-xs text-silver-600">Lost your passkey? Ask an administrator to send you a recovery link.</p>
      </div>
    </AuthLayout>
  )
}

export function SsoErrorPage() {
  const [params] = useSearchParams()
  return (
    <AuthLayout title="Sign-in request rejected" subtitle="The application sent a request this identity provider will not accept.">
      <div className="space-y-4">
        <Alert>{params.get('description') ?? 'Unknown error'} <span className="font-mono text-xs opacity-70">({params.get('error')})</span></Alert>
        <p className="text-sm text-silver-500">For your safety you were not sent back to the application. Contact your administrator if this keeps happening.</p>
        <Button asChild variant="secondary" className="w-full"><Link to="/">Go to your workspace</Link></Button>
      </div>
    </AuthLayout>
  )
}

export function SetupPage() {
  const { refresh } = useAuth()
  const nav = useNavigate()
  const [form, setForm] = useState({ organization_name: '', full_name: '', email: '' })
  const [error, setError] = useState<string | null>(null)
  const [enrollToken, setEnrollToken] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const setup = useQuery({ queryKey: ['bootstrap'], queryFn: () => api.get<{ needs_setup: boolean }>('/auth/bootstrap-status') })

  if (setup.isLoading) return <div className="grid h-full place-items-center"><Spinner /></div>
  if (setup.data && !setup.data.needs_setup && !enrollToken) return <Navigate to="/login" replace />

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value })

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const r = await api.post<{ detail: string; enroll_token: string | null }>('/auth/register', form)
      setEnrollToken(r.enroll_token)  // passwordless bootstrap returns the token for the passkey ceremony
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  async function done() { await refresh(); nav('/') }

  if (enrollToken) {
    return (
      <AuthLayout title="Create your passkey" subtitle="Finish setting up the first Super Admin. No password needed.">
        <PasskeyEnrol token={enrollToken} defaultName="This device" cta="Create passkey and sign in" onDone={done} />
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title="Set up your organisation" subtitle="Create the first Super Admin account. Registration closes once this account exists.">
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <Field label="Organisation name" htmlFor="org"><Input id="org" required minLength={2} value={form.organization_name} onChange={set('organization_name')} /></Field>
        <Field label="Full name" htmlFor="name"><Input id="name" required minLength={2} autoComplete="name" value={form.full_name} onChange={set('full_name')} /></Field>
        <Field label="Work email" htmlFor="email"><Input id="email" type="email" required autoComplete="email" value={form.email} onChange={set('email')} /></Field>
        <Button type="submit" className="w-full" loading={busy}>Continue to passkey</Button>
      </form>
    </AuthLayout>
  )
}

/** Passkey recovery (admin-issued or break-glass link): register a fresh passkey from a single-use token. */
export function RecoverPage() {
  const { refresh } = useAuth()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const token = params.get('token')
  async function done() { await refresh(); nav('/') }
  return (
    <AuthLayout title="Register a new passkey" subtitle="Recover access to your account. Any old passkeys are replaced.">
      <PasskeyEnrol token={token} defaultName="New device" cta="Register passkey and sign in" onDone={done} />
    </AuthLayout>
  )
}

/** Invitation acceptance: register a passkey (the invite link doubles as a passkey-enrolment token). No password. */
export function AcceptInvitePage() {
  const { refresh } = useAuth()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const token = params.get('token')
  async function done() { await refresh(); nav('/') }
  return (
    <AuthLayout title="Activate your account" subtitle="Finish accepting your invitation by creating a passkey.">
      <PasskeyEnrol token={token} defaultName="This device" cta="Create passkey and sign in" onDone={done} />
    </AuthLayout>
  )
}
