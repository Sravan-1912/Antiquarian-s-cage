import { useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Headset, Lock, Power, PowerOff, ShieldOff, UserCheck, UserX } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Field, Input, Spinner } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { Device, InspectState, RemoteAction, RemoteCommand, RemoteSession } from '@/types/api'
import { formatDateTime, relativeTime } from '@/utils/format'
import { SessionStatusBadge, TerminateButton } from './shared'

const LABEL: Record<string, string> = {
  'device.inspect': 'Status inspection', 'device.lock': 'Remote lock', 'device.restart': 'Remote restart',
  'device.restart_cancel': 'Cancel restart', 'account.disable': 'Disable local account', 'account.enable': 'Enable local account',
  'account.remove_admin': 'Remove from Administrators',
}
const SENSITIVE = new Set<RemoteCommand>(['device.restart', 'account.disable', 'account.enable', 'account.remove_admin'])

type Pending = { command: RemoteCommand; parameters: Record<string, unknown>; title: string; description: string; danger?: boolean; extra?: ReactNode }

function jobTone(s: RemoteAction['status'], r?: string) {
  if (s === 'succeeded') return r === 'needs_attention' ? 'warning' : 'success'
  if (s === 'failed' || s === 'expired' || s === 'revoked') return 'danger'
  return 'info'
}

function fmtUptime(s?: number) {
  if (s == null) return '—'
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  return d ? `${d}d ${h}h` : `${h}h ${m}m`
}

export function RemotePanel({ device }: { device: Device }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const remote = can('devices:remote')
  const [pending, setPending] = useState<Pending | null>(null)
  const [reason, setReason] = useState('')
  const [password, setPassword] = useState('')
  const [delay, setDelay] = useState(300)
  const [assistOpen, setAssistOpen] = useState(false)
  const [assistMinutes, setAssistMinutes] = useState(30)

  const actions = useQuery({ queryKey: ['device', device.id, 'actions'], queryFn: () => api.get<RemoteAction[]>(`/devices/${device.id}/actions`), refetchInterval: 5_000 })
  const sessions = useQuery({ queryKey: ['device', device.id, 'sessions'], queryFn: () => api.get<RemoteSession[]>(`/remote-sessions?device_id=${device.id}&limit=10`), refetchInterval: 5_000 })
  const refresh = () => { qc.invalidateQueries({ queryKey: ['device', device.id] }) }
  const reset = () => { setPending(null); setReason(''); setPassword(''); setAssistOpen(false) }

  const act = useMutation({
    mutationFn: (p: Pending) => api.post<RemoteAction>(`/devices/${device.id}/actions`, {
      command: p.command, parameters: p.command === 'device.restart' ? { ...p.parameters, delay_seconds: delay } : p.parameters,
      reason, ...(SENSITIVE.has(p.command) ? { confirm_password: password } : {}),
    }),
    onSuccess: () => { refresh(); reset() },
  })
  const assist = useMutation({
    mutationFn: () => api.post<RemoteSession>(`/devices/${device.id}/assist`, { reason, max_minutes: assistMinutes, confirm_password: password }),
    onSuccess: () => { refresh(); reset() },
  })

  const latestInspect = actions.data?.find((a) => a.command === 'device.inspect' && a.status === 'succeeded')
  const st = (latestInspect?.result.current_state ?? {}) as InspectState
  const admins = new Set((st.administrators ?? []).map((a) => a.name.split('\\').pop()!.toLowerCase()))
  const open = sessions.data?.find((x) => !['ended', 'denied', 'expired', 'cancelled', 'failed'].includes(x.status))
  const active = device.status === 'active'

  function ask(command: RemoteCommand, parameters: Record<string, unknown>, title: string, description: string, danger = false) {
    act.reset()
    setPending({ command, parameters, title, description, danger })
  }

  return (
    <div className="space-y-4">
      {open && (
        <Alert tone={open.status === 'active' ? 'warning' : 'info'}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span><Headset className="mr-1.5 inline size-4" />Remote assistance <b>{open.status.replace('_', ' ')}</b> — {open.requested_by_label}
              {open.expires_at && ` · ends ${formatDateTime(open.expires_at)}`}{open.status === 'requested' && ' · waiting for the endpoint'}</span>
            {remote && <TerminateButton session={open} onDone={refresh} />}
          </div>
        </Alert>
      )}
      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Remote administration" description="Allowlisted, signed, short-lived commands. Every action needs a reason and is audited." />
          {!remote ? <p className="px-4 py-3 text-sm text-silver-500">Your role cannot perform remote actions.</p> : !active ? <p className="px-4 py-3 text-sm text-silver-500">Endpoint is {device.status}; remote actions are disabled.</p> : (
            <div className="flex flex-wrap gap-2 p-4">
              <Button size="sm" variant="outline" onClick={() => ask('device.inspect', {}, 'Inspect live status', 'Collects uptime, load, signed-in users and local accounts (read-only).')}><Activity />Inspect status</Button>
              <Button size="sm" variant="outline" onClick={() => ask('device.lock', {}, 'Lock the endpoint', 'Locks the screen immediately; the user signs in again to continue. Unsaved work is kept.')}><Lock />Lock</Button>
              <Button size="sm" variant="outline" onClick={() => ask('device.restart', { message: 'Your IT administrator scheduled a restart. Save your work.' }, 'Restart the endpoint', 'Schedules a restart with an on-screen warning. Unsaved work in open applications may be lost.', true)}><Power />Restart</Button>
              <Button size="sm" variant="ghost" onClick={() => ask('device.restart_cancel', {}, 'Cancel scheduled restart', 'Aborts a pending restart if one is scheduled.')}><PowerOff />Cancel restart</Button>
              <Button size="sm" onClick={() => { assist.reset(); setAssistOpen(true) }} disabled={!!open || !device.online} title={!device.online ? 'Endpoint offline' : undefined}><Headset />Remote assistance</Button>
            </div>
          )}
          <div className="border-t border-ink-700 px-4 py-3">
            <div className="mb-2 text-xs font-medium text-silver-500">Live status {latestInspect && <span className="font-normal">· {relativeTime(latestInspect.completed_at ?? latestInspect.issued_at)}</span>}</div>
            {!latestInspect ? <p className="text-xs text-silver-600">Run “Inspect status” to collect a live snapshot.</p> : (
              <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 text-sm">
                <dt className="text-silver-500">Uptime</dt><dd>{fmtUptime(st.uptime_seconds)}</dd>
                <dt className="text-silver-500">CPU / memory</dt><dd>{st.cpu_percent ?? '—'}% / {st.memory_percent ?? '—'}%</dd>
                <dt className="text-silver-500">Signed-in users</dt><dd>{st.logged_on_users?.join(', ') || 'none'}</dd>
                <dt className="text-silver-500">Processes</dt><dd>{st.process_count ?? '—'}</dd>
              </dl>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Local accounts" description="From the latest status inspection. Changes require your password and never remove the last enabled administrator." />
          {!st.local_accounts ? <p className="px-4 py-3 text-sm text-silver-500">{st.local_accounts_error ?? 'Run “Inspect status” to list local accounts.'}</p> : (
            <ul className="divide-y divide-ink-800">{st.local_accounts.map((u) => {
              const isAdmin = admins.has(u.name.toLowerCase())
              return (
                <li key={u.sid} className="flex items-center justify-between gap-2 px-4 py-2">
                  <div className="min-w-0"><span className="text-sm text-silver-100">{u.name}</span>
                    <span className="ml-2 inline-flex gap-1">{u.enabled ? <Badge tone="success">enabled</Badge> : <Badge>disabled</Badge>}{isAdmin && <Badge tone="warning">admin</Badge>}</span>
                    <div className="text-xs text-silver-600">Last sign-in {u.last_logon ? formatDateTime(u.last_logon) : 'never'}</div></div>
                  {remote && active && (
                    <div className="flex shrink-0 gap-1">
                      {u.enabled ? <Button size="sm" variant="ghost" onClick={() => ask('account.disable', { username: u.name }, `Disable ${u.name}`, 'The account can no longer sign in to this device.', true)}><UserX />Disable</Button>
                        : <Button size="sm" variant="ghost" onClick={() => ask('account.enable', { username: u.name }, `Enable ${u.name}`, 'The account can sign in again.')}><UserCheck />Enable</Button>}
                      {isAdmin && <Button size="sm" variant="ghost" onClick={() => ask('account.remove_admin', { username: u.name }, `Remove ${u.name} from Administrators`, 'The account keeps working as a standard user.', true)}><ShieldOff />Demote</Button>}
                    </div>
                  )}
                </li>
              )
            })}</ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Remote action history" />
          {actions.isLoading ? <div className="p-4"><Spinner /></div> : !actions.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No remote actions yet.</p> : (
            <ul className="max-h-80 divide-y divide-ink-800 overflow-y-auto">{actions.data.map((a) => (
              <li key={a.id} className="px-4 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm text-silver-100">{LABEL[a.command] ?? a.command}{a.parameters.username ? ` · ${String(a.parameters.username)}` : ''}</span>
                  <Badge tone={jobTone(a.status, a.result.status)}>{a.result.status === 'needs_attention' ? 'needs attention' : a.status}</Badge>
                </div>
                <div className="text-xs text-silver-500">{a.requested_by_label} · {relativeTime(a.issued_at)} · “{String(a.parameters.reason ?? '')}”</div>
                {a.result.detail && <div className="text-xs text-silver-400">{a.result.detail}</div>}
              </li>
            ))}</ul>
          )}
        </Card>
        <Card>
          <CardHeader title="Remote assistance sessions" />
          {!sessions.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No sessions.</p> : (
            <ul className="max-h-80 divide-y divide-ink-800 overflow-y-auto">{sessions.data.map((x) => (
              <li key={x.id} className="px-4 py-2">
                <div className="flex items-center justify-between gap-2"><span className="text-sm text-silver-100">{x.requested_by_label}</span><SessionStatusBadge s={x.status} /></div>
                <div className="text-xs text-silver-500">{formatDateTime(x.created_at)} · “{x.reason}” · consent {x.require_consent ? (x.consent_decision ?? 'pending') : 'not required'}{x.consent_user ? ` by ${x.consent_user}` : ''}</div>
                {x.ended_at && <div className="text-xs text-silver-600">Ended {formatDateTime(x.ended_at)} by {x.ended_by?.replace('_', ' ')}{x.end_reason ? ` — ${x.end_reason}` : ''}</div>}
              </li>
            ))}</ul>
          )}
        </Card>
      </div>

      <Dialog open={!!pending} onOpenChange={(o) => !o && reset()} title={pending?.title ?? ''} description={pending?.description}>
        {pending && (
          <form onSubmit={(e: FormEvent) => { e.preventDefault(); act.mutate(pending) }} className="space-y-3">
            {act.error && <Alert>{describeError(act.error)}</Alert>}
            {pending.command === 'device.restart' && (
              <Field label="Warning delay before restart (seconds)" htmlFor="rd"><Input id="rd" type="number" min={60} max={3600} value={delay} onChange={(e) => setDelay(Number(e.target.value))} /></Field>
            )}
            <Field label="Reason (shown in the audit log)" htmlFor="rr"><Input id="rr" required minLength={3} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
            {SENSITIVE.has(pending.command) && (
              <Field label="Confirm with your password" htmlFor="rp"><Input id="rp" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
            )}
            <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={reset}>Cancel</Button>
              <Button type="submit" variant={pending.danger ? 'danger' : 'primary'} loading={act.isPending}>Send signed command</Button></div>
          </form>
        )}
      </Dialog>

      <Dialog open={assistOpen} onOpenChange={(o) => !o && reset()} title="Request remote assistance"
        description="The person at the endpoint is asked to allow the session (unless your organisation disabled consent). A red banner stays on their screen for the whole session and they can end it at any time. Screen sharing uses Windows Quick Assist, opened only after consent.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); assist.mutate() }} className="space-y-3">
          {assist.error && <Alert>{describeError(assist.error)}</Alert>}
          <Field label="Reason (shown to the user)" htmlFor="ar"><Input id="ar" required minLength={5} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <Field label="Maximum duration (minutes)" htmlFor="am"><Input id="am" type="number" min={5} max={120} value={assistMinutes} onChange={(e) => setAssistMinutes(Number(e.target.value))} /></Field>
          <Field label="Confirm with your password" htmlFor="ap"><Input id="ap" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          <div className="flex justify-end"><Button type="submit" loading={assist.isPending}><Headset />Send request</Button></div>
        </form>
      </Dialog>
    </div>
  )
}
