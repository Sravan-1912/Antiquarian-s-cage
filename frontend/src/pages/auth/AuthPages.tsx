import { useState, type FormEvent } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AuthLayout } from '@/layouts/AuthLayout'
import { Alert, Button, Field, Input, Spinner } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'
import { useAuth } from '@/hooks/useAuth'
import { safeNext } from '@/services/passkeys'

export function LoginPage() {
  const { me, refresh } = useAuth()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const next = safeNext(params.get('next'))
  const appName = params.get('app')
  const stepUp = params.get('step_up') === '1'
  const [form, setForm] = useState({ email: '', password: '' })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const setup = useQuery({ queryKey: ['bootstrap'], queryFn: () => api.get<{ needs_setup: boolean }>('/auth/bootstrap-status') })

  if (me && me.must_change_password) return <Navigate to="/change-password" replace />
  if (me && next && !stepUp) { window.location.assign(next); return null }  // already signed in, returning to an app
  if (me && !next) return <Navigate to="/" replace />
  if (setup.data?.needs_setup) return <Navigate to="/setup" replace />

  async function done(mustChange: boolean) {
    if (mustChange) { nav('/change-password'); return }
    if (next) { window.location.assign(next); return }
    await refresh()
    nav('/')
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      const r = await api.post<{ must_change_password: boolean }>('/auth/login', form)
      await refresh()
      await done(r.must_change_password)
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  const subtitle = appName ? `to continue to ${appName}` : 'Antiquarian\'s Cage console and workspace'
  return (
    <AuthLayout title="Sign in" subtitle={subtitle}>
      <form onSubmit={submit} className="space-y-4">
        {stepUp && <Alert tone="warning">{appName ?? 'This application'} requires a stronger sign-in. Add a passkey from Account security, then sign in with it.</Alert>}
        {error && <Alert>{error}</Alert>}
        <Field label="Work email" htmlFor="email"><Input id="email" type="email" required autoComplete="username" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
        <Field label="Password" htmlFor="password"><Input id="password" type="password" required autoComplete="current-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
        <Button type="submit" variant="primary" className="w-full" loading={busy}>Sign in</Button>
        <p className="text-center text-xs text-silver-600">Were you given a temporary password? Sign in with it — you will be asked to set your own.</p>
      </form>
    </AuthLayout>
  )
}

/** Change your own password. Used both for the forced change after a handover and for a voluntary change. */
export function ChangePasswordPage() {
  const { me, refresh, logout } = useAuth()
  const nav = useNavigate()
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (!me) return <Navigate to="/login" replace />
  const forced = me.must_change_password
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value })

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (form.new_password !== form.confirm) { setError('The new passwords do not match.'); return }
    setBusy(true)
    try {
      await api.post('/auth/password', { current_password: form.current_password, new_password: form.new_password })
      await refresh()
      nav('/')
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthLayout title={forced ? 'Set your password' : 'Change your password'}
      subtitle={forced ? 'You signed in with a temporary password. Choose your own to continue.' : 'Choose a new password. Other sessions will be signed out.'}>
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <Field label={forced ? 'Temporary password' : 'Current password'} htmlFor="cur"><Input id="cur" type="password" required autoComplete="current-password" value={form.current_password} onChange={set('current_password')} /></Field>
        <Field label="New password" htmlFor="new"><Input id="new" type="password" required minLength={12} autoComplete="new-password" value={form.new_password} onChange={set('new_password')} /></Field>
        <Field label="Confirm new password" htmlFor="conf"><Input id="conf" type="password" required minLength={12} autoComplete="new-password" value={form.confirm} onChange={set('confirm')} /></Field>
        <p className="text-xs text-silver-600">At least 12 characters, using three of: lowercase, uppercase, digits, symbols.</p>
        <Button type="submit" variant="primary" className="w-full" loading={busy}>Save password</Button>
        {forced && <button type="button" className="w-full text-center text-xs text-silver-500 hover:text-silver-300" onClick={() => void logout()}>Sign out instead</button>}
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
  const { refresh } = useAuth()
  const nav = useNavigate()
  const [form, setForm] = useState({ organization_name: '', full_name: '', email: '', password: '' })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const setup = useQuery({ queryKey: ['bootstrap'], queryFn: () => api.get<{ needs_setup: boolean }>('/auth/bootstrap-status') })

  if (setup.isLoading) return <div className="grid h-full place-items-center"><Spinner /></div>
  if (setup.data && !setup.data.needs_setup) return <Navigate to="/login" replace />

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value })

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await api.post('/auth/register', form)  // creates the org + first Super Admin and signs in
      await refresh()
      nav('/')
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthLayout title="Set up your organisation" subtitle="Create the first Super Admin account. Registration closes once this account exists.">
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <Field label="Organisation name" htmlFor="org"><Input id="org" required minLength={2} value={form.organization_name} onChange={set('organization_name')} /></Field>
        <Field label="Full name" htmlFor="name"><Input id="name" required minLength={2} autoComplete="name" value={form.full_name} onChange={set('full_name')} /></Field>
        <Field label="Work email" htmlFor="email"><Input id="email" type="email" required autoComplete="username" value={form.email} onChange={set('email')} /></Field>
        <Field label="Password" htmlFor="pw"><Input id="pw" type="password" required minLength={12} autoComplete="new-password" value={form.password} onChange={set('password')} /></Field>
        <p className="text-xs text-silver-600">At least 12 characters, using three of: lowercase, uppercase, digits, symbols.</p>
        <Button type="submit" className="w-full" loading={busy}>Create organisation</Button>
      </form>
    </AuthLayout>
  )
}
