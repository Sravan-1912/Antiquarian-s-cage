import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { Monitor } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Field, Input, PageHeader, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import { describePasskeyError, passkeysSupported, registerPasskey } from '@/services/passkeys'
import { PhoneCard } from './PhoneCard'
import type { AuthEvent, SessionItem } from '@/types/api'
import { describeUserAgent, formatDateTime } from '@/utils/format'

function MfaCard() {
  const { me, refresh } = useAuth()
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null)
  const [qr, setQr] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null)

  useEffect(() => {
    // QR rendered locally; the secret never leaves the browser to a third-party service.
    if (setup) QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 176, color: { dark: '#0d0e10', light: '#eceef0' } }).then(setQr)
  }, [setup])

  const begin = useMutation({ mutationFn: () => api.post<{ secret: string; otpauth_uri: string }>('/auth/mfa/setup'), onSuccess: setSetup,
    onError: (e) => setMsg({ tone: 'danger', text: describeError(e) }) })
  const enable = useMutation({ mutationFn: () => api.post('/auth/mfa/enable', { code }),
    onSuccess: async () => { setSetup(null); setCode(''); setMsg({ tone: 'success', text: 'MFA enabled. You will be asked for a code at every sign-in.' }); await refresh() },
    onError: (e) => setMsg({ tone: 'danger', text: describeError(e) }) })
  const disable = useMutation({ mutationFn: () => api.post('/auth/mfa/disable', { code, password }),
    onSuccess: async () => { setCode(''); setPassword(''); setMsg({ tone: 'success', text: 'MFA disabled.' }); await refresh() },
    onError: (e) => setMsg({ tone: 'danger', text: describeError(e) }) })

  return (
    <Card>
      <CardHeader title="Multi-factor authentication" description="Time-based one-time codes (RFC 6238) from an authenticator app."
        action={me?.mfa_enabled ? <Badge tone="success">Enabled</Badge> : <Badge tone="warning">Not enabled</Badge>} />
      <div className="space-y-3 p-4">
        {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
        {me?.mfa_enabled ? (
          <form onSubmit={(e: FormEvent) => { e.preventDefault(); disable.mutate() }} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
            <Field label="Current password" htmlFor="mpw"><Input id="mpw" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
            <Field label="Authentication code" htmlFor="mcode"><Input id="mcode" inputMode="numeric" required maxLength={8} className="font-mono" value={code} onChange={(e) => setCode(e.target.value)} /></Field>
            <Button type="submit" variant="danger" loading={disable.isPending}>Disable MFA</Button>
          </form>
        ) : setup ? (
          <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
            <div className="rounded-md bg-silver-50 p-1.5">{qr ? <img src={qr} alt="Authenticator QR code" className="size-44" /> : <div className="grid size-44 place-items-center"><Spinner /></div>}</div>
            <form onSubmit={(e: FormEvent) => { e.preventDefault(); enable.mutate() }} className="space-y-3">
              <p className="text-sm text-silver-400">Scan the code with your authenticator app, or enter this key manually:</p>
              <code className="block break-all rounded bg-ink-800 px-2 py-1.5 font-mono text-xs text-silver-100">{setup.secret.match(/.{1,4}/g)?.join(' ')}</code>
              <Field label="Enter the 6-digit code to confirm" htmlFor="ecode"><Input id="ecode" inputMode="numeric" required maxLength={8} className="font-mono tracking-widest" value={code} onChange={(e) => setCode(e.target.value)} autoFocus /></Field>
              <div className="flex gap-2"><Button type="submit" loading={enable.isPending}>Enable MFA</Button><Button type="button" variant="ghost" onClick={() => setSetup(null)}>Cancel</Button></div>
            </form>
          </div>
        ) : (
          <Button onClick={() => { setMsg(null); begin.mutate() }} loading={begin.isPending}>Set up authenticator app</Button>
        )}
      </div>
    </Card>
  )
}

function PasswordCard() {
  const [f, setF] = useState({ current_password: '', new_password: '', confirm: '' })
  const [msg, setMsg] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null)
  const qc = useQueryClient()
  const m = useMutation({ mutationFn: () => api.post<{ detail: string }>('/auth/password/change', { current_password: f.current_password, new_password: f.new_password }),
    onSuccess: (r) => { setMsg({ tone: 'success', text: r.detail }); setF({ current_password: '', new_password: '', confirm: '' }); qc.invalidateQueries({ queryKey: ['sessions'] }) },
    onError: (e) => setMsg({ tone: 'danger', text: describeError(e) }) })
  return (
    <Card>
      <CardHeader title="Password" description="Changing your password signs out every other session." />
      <form className="space-y-3 p-4" onSubmit={(e) => { e.preventDefault(); if (f.new_password !== f.confirm) setMsg({ tone: 'danger', text: 'Passwords do not match.' }); else m.mutate() }}>
        {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Current password" htmlFor="cp"><Input id="cp" type="password" required autoComplete="current-password" value={f.current_password} onChange={(e) => setF({ ...f, current_password: e.target.value })} /></Field>
          <Field label="New password" htmlFor="np"><Input id="np" type="password" required minLength={12} autoComplete="new-password" value={f.new_password} onChange={(e) => setF({ ...f, new_password: e.target.value })} /></Field>
          <Field label="Confirm new password" htmlFor="np2"><Input id="np2" type="password" required autoComplete="new-password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></Field>
        </div>
        <Button type="submit" loading={m.isPending}>Change password</Button>
      </form>
    </Card>
  )
}

function SessionsCard() {
  const qc = useQueryClient()
  const sessions = useQuery({ queryKey: ['sessions'], queryFn: () => api.get<SessionItem[]>('/auth/sessions') })
  const revoke = useMutation({ mutationFn: (id: string) => api.del(`/auth/sessions/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }) })
  const others = useMutation({ mutationFn: () => api.post('/auth/sessions/revoke-others'), onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }) })
  return (
    <Card>
      <CardHeader title="Active sessions" description="Sessions expire after 30 minutes of inactivity or 12 hours."
        action={<Button size="sm" variant="outline" onClick={() => others.mutate()} loading={others.isPending} disabled={(sessions.data?.length ?? 0) < 2}>Sign out other sessions</Button>} />
      {sessions.isLoading ? <div className="p-4"><Spinner /></div> : (
        <ul className="divide-y divide-ink-800">
          {sessions.data?.map((s) => (
            <li key={s.id} className="flex items-center gap-3 px-4 py-2.5">
              <Monitor className="size-4 text-silver-500" />
              <div className="min-w-0 flex-1">
                <div className="text-sm text-silver-100">{describeUserAgent(s.user_agent)} {s.current && <Badge tone="success" className="ml-1">This session</Badge>}</div>
                <div className="text-xs text-silver-500">{s.ip ?? 'unknown IP'} · signed in {formatDateTime(s.created_at)} · last active {formatDateTime(s.last_seen_at)}</div>
              </div>
              {!s.current && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(s.id)} loading={revoke.isPending && revoke.variables === s.id}>Revoke</Button>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function HistoryCard() {
  const h = useQuery({ queryKey: ['login-history'], queryFn: () => api.get<AuthEvent[]>('/auth/login-history') })
  return (
    <Card>
      <CardHeader title="Authentication history" description="Your last 50 authentication events." />
      {h.isLoading ? <div className="p-4"><Spinner /></div> : (
        <Table>
          <thead><tr><Th>When</Th><Th>Event</Th><Th>Result</Th><Th>IP address</Th><Th>Device</Th></tr></thead>
          <tbody>{h.data?.map((e) => (
            <tr key={e.id}>
              <Td className="whitespace-nowrap text-silver-400">{formatDateTime(e.created_at)}</Td>
              <Td>{e.event_type.replace(/_/g, ' ')}{e.reason && <span className="ml-1 text-xs text-silver-500">({e.reason.replace(/_/g, ' ')})</span>}</Td>
              <Td>{e.success ? <Badge tone="success">success</Badge> : <Badge tone="danger">failed</Badge>}</Td>
              <Td className="font-mono text-xs">{e.ip ?? '—'}</Td>
              <Td className="text-xs text-silver-400">{describeUserAgent(e.user_agent)}</Td>
            </tr>
          ))}</tbody>
        </Table>
      )}
    </Card>
  )
}

interface PasskeyItem { id: string; name: string; created_at: string; last_used_at: string | null; synced: boolean; transports: string[] }

function PasskeysCard() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['passkeys'], queryFn: () => api.get<PasskeyItem[]>('/auth/passkeys') })
  const [name, setName] = useState('')
  const [msg, setMsg] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null)
  const add = useMutation({
    mutationFn: () => registerPasskey(name.trim() || 'Passkey'),
    onSuccess: () => { setName(''); setMsg({ tone: 'success', text: 'Passkey added. You can now sign in without a password.' }); qc.invalidateQueries({ queryKey: ['passkeys'] }) },
    onError: (e) => setMsg({ tone: 'danger', text: describePasskeyError(e) ?? describeError(e) }),
  })
  const revoke = useMutation({ mutationFn: (id: string) => api.del(`/auth/passkeys/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['passkeys'] }) })
  return (
    <Card>
      <CardHeader title="Passkeys" description="Phishing-resistant sign-in with Windows Hello, Touch ID, your phone or a security key. Your fingerprint or face never leaves your device — the server only stores a public key." />
      <div className="space-y-3 p-4">
        {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
        {!passkeysSupported() ? <Alert tone="warning">This browser does not support passkeys.</Alert> : (
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); setMsg(null); add.mutate() }}>
            <div className="w-64"><Field label="Name for this passkey" htmlFor="pkn"><Input id="pkn" maxLength={64} placeholder="e.g. Work laptop (Windows Hello)" value={name} onChange={(e) => setName(e.target.value)} /></Field></div>
            <Button type="submit" loading={add.isPending}>Add a passkey</Button>
          </form>
        )}
      </div>
      {list.isLoading ? <div className="p-4"><Spinner /></div> : !!list.data?.length && (
        <ul className="divide-y divide-ink-800 border-t border-ink-700">{list.data.map((p) => (
          <li key={p.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
            <div><div className="text-sm text-silver-100">{p.name} {p.synced ? <Badge>synced</Badge> : <Badge tone="info">device-bound</Badge>}</div>
              <div className="text-xs text-silver-500">Added {formatDateTime(p.created_at)} · last used {p.last_used_at ? formatDateTime(p.last_used_at) : 'never'}</div></div>
            <Button size="sm" variant="ghost" onClick={() => revoke.mutate(p.id)} loading={revoke.isPending && revoke.variables === p.id}>Remove</Button>
          </li>
        ))}</ul>
      )}
    </Card>
  )
}

interface Pref { category: string; label: string; in_app: boolean; email: boolean; min_severity: string; email_min_severity: string }
const SEVS = ['informational', 'low', 'medium', 'high', 'critical']

function NotificationPrefsCard() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['notif-prefs'], queryFn: () => api.get<Pref[]>('/notifications/preferences') })
  const [draft, setDraft] = useState<Pref[] | null>(null)
  const save = useMutation({
    mutationFn: (p: Pref[]) => api.put<Pref[]>('/notifications/preferences', p.map((x) => ({ category: x.category, in_app: x.in_app, email: x.email, min_severity: x.min_severity, email_min_severity: x.email_min_severity }))),
    onSuccess: () => { setDraft(null); qc.invalidateQueries({ queryKey: ['notif-prefs'] }) },
  })
  const rows = draft ?? q.data
  if (!rows) return null
  const upd = (i: number, patch: Partial<Pref>) => setDraft(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const sel = 'rounded border border-ink-600 bg-ink-900 px-1.5 py-1 text-xs text-silver-100'
  return (
    <Card>
      <CardHeader title="Notifications" description="Choose what reaches you in the console and by email. Email goes through a durable outbox with retries."
        action={draft && <Button size="sm" onClick={() => save.mutate(draft)} loading={save.isPending}>Save</Button>} />
      {save.error && <div className="px-4 pt-3"><Alert>{describeError(save.error)}</Alert></div>}
      <Table>
        <thead><tr><Th>Category</Th><Th>In-app</Th><Th>In-app from</Th><Th>Email</Th><Th>Email from</Th></tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={r.category}>
            <Td className="text-silver-200">{r.label}</Td>
            <Td><input type="checkbox" aria-label={`In-app ${r.label}`} className="size-4 accent-emerald-500" checked={r.in_app} onChange={(e) => upd(i, { in_app: e.target.checked })} /></Td>
            <Td><select aria-label={`In-app minimum severity ${r.label}`} className={sel} value={r.min_severity} onChange={(e) => upd(i, { min_severity: e.target.value })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></Td>
            <Td><input type="checkbox" aria-label={`Email ${r.label}`} className="size-4 accent-emerald-500" checked={r.email} onChange={(e) => upd(i, { email: e.target.checked })} /></Td>
            <Td><select aria-label={`Email minimum severity ${r.label}`} className={sel} value={r.email_min_severity} onChange={(e) => upd(i, { email_min_severity: e.target.value })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></Td>
          </tr>
        ))}</tbody>
      </Table>
    </Card>
  )
}

export function AccountSecurityPage() {
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Security settings" description="Manage how you sign in." />
      <PhoneCard />
      <PasskeysCard />
      <MfaCard />
      <PasswordCard />
      <NotificationPrefsCard />
      <SessionsCard />
      <HistoryCard />
    </div>
  )
}
