import { useEffect, useRef, useState, type FormEvent } from 'react'
import { KeyRound, Smartphone } from 'lucide-react'
import { PhoneApproval } from './PhoneSignIn'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AuthLayout } from '@/layouts/AuthLayout'
import { Alert, Button, Field, Input, Spinner } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'
import { useAuth } from '@/hooks/useAuth'
import { describePasskeyError, passkeysSupported, rememberNext, safeNext, signInWithPasskey, takeNext } from '@/services/passkeys'

function PasswordHint() {
  return <>At least 12 characters with three of: lowercase, uppercase, digit, symbol. Avoid names and common words.</>
}

export function LoginPage() {
  const { me, refresh } = useAuth()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const next = safeNext(params.get('next'))
  const appName = params.get('app')
  const stepUp = params.get('step_up') === '1'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [pkBusy, setPkBusy] = useState(false)
  const [phoneMode, setPhoneMode] = useState(false)
  const setup = useQuery({ queryKey: ['bootstrap'], queryFn: () => api.get<{ needs_setup: boolean }>('/auth/bootstrap-status') })

  useEffect(() => {  // already signed in and returning to an application (no step-up needed) → continue the SSO flow
    if (me && next && !stepUp) window.location.assign(next)
  }, [me, next, stepUp])

  if (me && !next) return <Navigate to="/" replace />
  if (setup.data?.needs_setup) return <Navigate to="/setup" replace />

  async function done() {
    if (next) { window.location.assign(next); return }
    await refresh()
    nav('/')
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const r = await api.post<{ mfa_required: boolean }>('/auth/login', { email, password })
      if (r.mfa_required) { rememberNext(next); nav('/mfa') } else await done()
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
      setPassword('')
    }
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
  if (phoneMode) {
    return (
      <AuthLayout title="Sign in with your phone" subtitle={subtitle}>
        <PhoneApproval email={email} onApproved={() => void done()} onCancel={() => setPhoneMode(false)} />
      </AuthLayout>
    )
  }
  function phone() {
    setError(null)
    if (!/^\S+@\S+\.\S+$/.test(email)) { setError('Enter your work email first, then choose “Sign in with your phone”.'); return }
    setPhoneMode(true)
  }
  return (
    <AuthLayout title="Sign in" subtitle={subtitle}
      footer={<Link to="/forgot-password" className="text-emerald-400 hover:text-emerald-300">Forgot your password?</Link>}>
      <div className="space-y-4">
        {stepUp && <Alert tone="warning">{appName ?? 'This application'} requires multi-factor sign-in. Use a passkey, or sign in with your password and authenticator code.</Alert>}
        {error && <Alert>{error}</Alert>}
        {passkeysSupported() && (
          <>
            <Button type="button" variant={stepUp ? 'primary' : 'secondary'} className="w-full" onClick={passkey} loading={pkBusy}><KeyRound />Sign in with a passkey</Button>
            <div className="flex items-center gap-3 text-[11px] uppercase tracking-wider text-silver-600"><span className="h-px flex-1 bg-ink-700" />or<span className="h-px flex-1 bg-ink-700" /></div>
          </>
        )}
        <form onSubmit={submit} className="space-y-4">
          <Field label="Work email" htmlFor="email">
            <Input id="email" type="email" autoComplete="username webauthn" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field label="Password" htmlFor="password">
            <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <Button type="submit" className="w-full" variant={stepUp ? 'secondary' : 'primary'} loading={busy}>Sign in with password</Button>
        </form>
        <Button type="button" variant="outline" className="w-full" onClick={phone}><Smartphone />Sign in with your phone</Button>
      </div>
    </AuthLayout>
  )
}

export function MfaChallengePage() {
  const { refresh } = useAuth()
  const nav = useNavigate()
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/auth/mfa/verify', { code })
      const next = takeNext()
      if (next) { window.location.assign(next); return }
      await refresh()
      nav('/')
    } catch (err) {
      setError(describeError(err))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthLayout title="Two-step verification" subtitle="Enter the 6-digit code from your authenticator app."
      footer={<Link to="/login" className="text-silver-400 hover:text-silver-200">Use a different account</Link>}>
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <Field label="Authentication code" htmlFor="code">
          <Input id="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,8}" maxLength={8} required autoFocus
            className="font-mono tracking-[0.4em]" value={code} onChange={(e) => setCode(e.target.value)} />
        </Field>
        <Button type="submit" className="w-full" loading={busy}>Verify</Button>
      </form>
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
  const nav = useNavigate()
  const [form, setForm] = useState({ organization_name: '', full_name: '', email: '', password: '', confirm: '' })
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const setup = useQuery({ queryKey: ['bootstrap'], queryFn: () => api.get<{ needs_setup: boolean }>('/auth/bootstrap-status') })

  if (setup.isLoading) return <div className="grid h-full place-items-center"><Spinner /></div>
  if (setup.data && !setup.data.needs_setup && !done) return <Navigate to="/login" replace />

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value })

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (form.password !== form.confirm) return setError('Passwords do not match.')
    setBusy(true)
    try {
      const { confirm: _c, ...body } = form
      void _c
      const r = await api.post<{ detail: string }>('/auth/register', body)
      setDone(r.detail)
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  if (done) {
    return (
      <AuthLayout title="Check your email" subtitle={done}>
        <Button className="w-full" variant="secondary" onClick={() => nav('/login')}>Go to sign in</Button>
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
        <Field label="Password" htmlFor="pw" hint={undefined}>
          <Input id="pw" type="password" required minLength={12} autoComplete="new-password" value={form.password} onChange={set('password')} />
          <p className="mt-1 text-xs text-silver-600"><PasswordHint /></p>
        </Field>
        <Field label="Confirm password" htmlFor="pw2"><Input id="pw2" type="password" required autoComplete="new-password" value={form.confirm} onChange={set('confirm')} /></Field>
        <Button type="submit" className="w-full" loading={busy}>Create organisation</Button>
      </form>
    </AuthLayout>
  )
}

/** Runs a one-shot token action (email verification) on mount. */
export function VerifyEmailPage() {
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''
  const [state, setState] = useState<{ ok: boolean; msg: string } | null>(null)
  const ran = useRef(false)
  useEffect(() => {
    if (ran.current) return
    ran.current = true
    api.post<{ detail: string }>('/auth/verify-email', { token })
      .then((r) => setState({ ok: true, msg: r.detail }))
      .catch((e) => setState({ ok: false, msg: describeError(e) }))
  }, [token])
  return (
    <AuthLayout title="Email verification">
      {!state ? <Spinner /> : <div className="space-y-4"><Alert tone={state.ok ? 'success' : 'danger'}>{state.msg}</Alert>
        <Button asChild className="w-full" variant="secondary"><Link to="/login">Go to sign in</Link></Button></div>}
    </AuthLayout>
  )
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const r = await api.post<{ detail: string }>('/auth/password/forgot', { email })
      setMsg(r.detail)
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <AuthLayout title="Reset your password" subtitle="We will email a single-use link valid for 30 minutes."
      footer={<Link to="/login" className="text-emerald-400 hover:text-emerald-300">Back to sign in</Link>}>
      {msg ? <Alert tone="success">{msg}</Alert> : (
        <form onSubmit={submit} className="space-y-4">
          {error && <Alert>{error}</Alert>}
          <Field label="Work email" htmlFor="email"><Input id="email" type="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
          <Button type="submit" className="w-full" loading={busy}>Send reset link</Button>
        </form>
      )}
    </AuthLayout>
  )
}

function SetPasswordForm({ endpoint, field, title, subtitle }: { endpoint: string; field: 'new_password' | 'password'; title: string; subtitle: string }) {
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (pw !== confirm) return setError('Passwords do not match.')
    setBusy(true)
    try {
      const r = await api.post<{ detail: string }>(endpoint, { token, [field]: pw })
      setMsg(r.detail)
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <AuthLayout title={title} subtitle={subtitle}>
      {msg ? (
        <div className="space-y-4"><Alert tone="success">{msg}</Alert>
          <Button asChild className="w-full" variant="secondary"><Link to="/login">Go to sign in</Link></Button></div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          {!token && <Alert>This link is missing its token. Use the link from your email.</Alert>}
          {error && <Alert>{error}</Alert>}
          <Field label="New password" htmlFor="pw">
            <Input id="pw" type="password" required minLength={12} autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
            <p className="mt-1 text-xs text-silver-600"><PasswordHint /></p>
          </Field>
          <Field label="Confirm password" htmlFor="pw2"><Input id="pw2" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></Field>
          <Button type="submit" className="w-full" loading={busy} disabled={!token}>Set password</Button>
        </form>
      )}
    </AuthLayout>
  )
}

export const ResetPasswordPage = () => (
  <SetPasswordForm endpoint="/auth/password/reset" field="new_password" title="Choose a new password" subtitle="All existing sessions will be signed out." />
)
export const AcceptInvitePage = () => (
  <SetPasswordForm endpoint="/auth/invite/accept" field="password" title="Activate your account" subtitle="Set a password to finish accepting your administrator invitation." />
)
