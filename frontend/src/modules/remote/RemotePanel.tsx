import { useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Headset, Lock, Monitor, MonitorSmartphone, Power, PowerOff, ShieldOff, Terminal, UserCheck, UserX } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Field, Input, Spinner } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { Device, InspectState, RemoteAction, RemoteCommand, RemoteSession } from '@/types/api'
import { formatDateTime, relativeTime } from '@/utils/format'
import { SessionStatusBadge, TerminateButton } from './shared'
import { ShellTerminal } from './ShellTerminal'
import { ScreenViewer } from './ScreenViewer'

const LABEL: Record<string, string> = {
  'device.inspect': 'Status inspection', 'device.lock': 'Remote lock', 'device.restart': 'Remote restart',
  'device.restart_cancel': 'Cancel restart', 'device.shutdown': 'Power off', 'device.logoff': 'Log off user',
  'account.disable': 'Disable local account', 'account.enable': 'Enable local account',
  'account.remove_admin': 'Remove from Administrators', 'device.isolate': 'Network isolate', 'device.release': 'Release isolation',
}
const SENSITIVE = new Set<RemoteCommand>(['device.restart', 'device.shutdown', 'device.logoff', 'account.disable', 'account.enable', 'account.remove_admin', 'device.isolate', 'device.release'])
const WITH_DELAY = new Set<RemoteCommand>(['device.restart', 'device.shutdown'])

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
  const canShell = can('devices:shell')
  const canShellElevated = can('devices:shell_elevated')
  const canIsolate = can('devices:isolate')
  const [pending, setPending] = useState<Pending | null>(null)
  const [reason, setReason] = useState('')
  const [stepPw, setStepPw] = useState('')
  const [delay, setDelay] = useState(300)
  const [assistOpen, setAssistOpen] = useState(false)
  const [rdpOpen, setRdpOpen] = useState(false)
  const [shellOpen, setShellOpen] = useState(false)
  const [shellElevated, setShellElevated] = useState(false)
  const [screenOpen, setScreenOpen] = useState(false)
  const [termSession, setTermSession] = useState<string | null>(null)
  const [screenSession, setScreenSession] = useState<string | null>(null)
  const [assistMinutes, setAssistMinutes] = useState(30)
  const [rdpConnectMsg, setRdpConnectMsg] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null)

  const actions = useQuery({ queryKey: ['device', device.id, 'actions'], queryFn: () => api.get<RemoteAction[]>(`/devices/${device.id}/actions`), refetchInterval: 5_000 })
  const sessions = useQuery({ queryKey: ['device', device.id, 'sessions'], queryFn: () => api.get<RemoteSession[]>(`/remote-sessions?device_id=${device.id}&limit=10`), refetchInterval: 5_000 })
  const refresh = () => { qc.invalidateQueries({ queryKey: ['device', device.id] }) }
  const reset = () => { setPending(null); setReason(''); setStepPw(''); setAssistOpen(false); setRdpOpen(false); setShellOpen(false); setShellElevated(false); setScreenOpen(false) }

  const act = useMutation({
    mutationFn: async (p: Pending) => {
      const step_up = SENSITIVE.has(p.command) ? { password: stepPw } : undefined  // password confirmation
      return api.post<RemoteAction>(`/devices/${device.id}/actions`, {
        command: p.command, parameters: WITH_DELAY.has(p.command) ? { ...p.parameters, delay_seconds: delay } : p.parameters,
        reason, ...(step_up ? { step_up } : {}),
      })
    },
    onSuccess: () => { refresh(); reset() },
  })
  const assist = useMutation({
    mutationFn: async () =>
      api.post<RemoteSession>(`/devices/${device.id}/assist`, { reason, max_minutes: assistMinutes, step_up: { password: stepPw } }),
    onSuccess: () => { refresh(); reset() },
  })
  const rdp = useMutation({
    // Unattended RDP: no password step-up (by design). The endpoint always shows a visible banner for the session.
    mutationFn: async () => api.post<RemoteSession>(`/devices/${device.id}/rdp`, { reason, max_minutes: assistMinutes }),
    onSuccess: () => { refresh(); reset() },
  })
  const shell = useMutation({
    // Live-response shell: break-glass arbitrary execution. Banner + full command audit; RBAC-gated server-side.
    mutationFn: async () => api.post<RemoteSession>(`/devices/${device.id}/shell`, { reason, max_minutes: assistMinutes, elevated: shellElevated }),
    onSuccess: () => { refresh(); reset() },
  })
  const screen = useMutation({
    // Remote screen: agent captures the screen + injects input over the relay. Works on any Windows edition; banner shown.
    mutationFn: async () => api.post<RemoteSession>(`/devices/${device.id}/screen`, { reason, max_minutes: assistMinutes }),
    onSuccess: () => { refresh(); reset() },
  })
  const rdpConnect = useMutation({
    mutationFn: async (sessionId: string) => {
      const bridge = (window as unknown as { cageRdp?: { connect: (i: unknown) => Promise<unknown> } }).cageRdp
      if (!bridge?.connect) throw new Error('Remote Desktop connect runs in the installed desktop app. Open this console in the Antiquarian’s Cage desktop app.')
      const t = await api.post<{ operator_token: string; tunnel_path: string; endpoint_public_key: string | null }>(`/remote-sessions/${sessionId}/rdp-connect`)
      // endpointPublicKey enables the end-to-end encrypted (zero-knowledge) relay in the desktop helper.
      await bridge.connect({ sessionId, token: t.operator_token, tunnelPath: t.tunnel_path, endpointPublicKey: t.endpoint_public_key })
    },
    onSuccess: () => setRdpConnectMsg({ tone: 'success', text: 'Opening Remote Desktop… the connection is tunnelled through the server.' }),
    onError: (e) => setRdpConnectMsg({ tone: 'danger', text: describeError(e) }),
  })

  const latestInspect = actions.data?.find((a) => a.command === 'device.inspect' && a.status === 'succeeded')
  const st = (latestInspect?.result.current_state ?? {}) as InspectState
  const admins = new Set((st.administrators ?? []).map((a) => a.name.split('\\').pop()!.toLowerCase()))
  const open = sessions.data?.find((x) => !['ended', 'denied', 'expired', 'cancelled', 'failed'].includes(x.status))
  const active = device.status === 'active'
  // Isolation state derived from history (newest-first): isolated if the latest isolate is newer than any release.
  const lastIso = actions.data?.find((a) => a.command === 'device.isolate' && a.status === 'succeeded')
  const lastRel = actions.data?.find((a) => a.command === 'device.release' && a.status === 'succeeded')
  const isolated = !!lastIso && (!lastRel || new Date(lastIso.issued_at) > new Date(lastRel.issued_at))

  function ask(command: RemoteCommand, parameters: Record<string, unknown>, title: string, description: string, danger = false) {
    act.reset()
    setPending({ command, parameters, title, description, danger })
  }

  return (
    <div className="space-y-4">
      {open && (
        <Alert tone={open.status === 'active' ? 'warning' : 'info'}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>{open.mode === 'rdp' ? <Monitor className="mr-1.5 inline size-4" /> : open.mode === 'shell' ? <Terminal className="mr-1.5 inline size-4" /> : open.mode === 'screen' ? <MonitorSmartphone className="mr-1.5 inline size-4" /> : <Headset className="mr-1.5 inline size-4" />}
              {open.mode === 'rdp' ? 'Remote desktop' : open.mode === 'shell' ? 'Live-response shell' : open.mode === 'screen' ? 'Remote screen' : 'Remote assistance'} <b>{open.status.replace('_', ' ')}</b> — {open.requested_by_label}
              {open.expires_at && ` · ends ${formatDateTime(open.expires_at)}`}{open.status === 'requested' && ' · waiting for the endpoint'}</span>
            <div className="flex items-center gap-2">
              {open.mode === 'rdp' && open.status === 'active' && remote && (
                <Button size="sm" variant="primary" loading={rdpConnect.isPending} onClick={() => { setRdpConnectMsg(null); rdpConnect.mutate(open.id) }}><Monitor />Connect</Button>
              )}
              {open.mode === 'shell' && open.status === 'active' && canShell && (
                <Button size="sm" variant="primary" onClick={() => setTermSession(open.id)}><Terminal />Open terminal</Button>
              )}
              {open.mode === 'screen' && open.status === 'active' && remote && (
                <Button size="sm" variant="primary" onClick={() => setScreenSession(open.id)}><MonitorSmartphone />Open screen</Button>
              )}
              {remote && <TerminateButton session={open} onDone={refresh} />}
            </div>
          </div>
        </Alert>
      )}
      {rdpConnectMsg && <Alert tone={rdpConnectMsg.tone}>{rdpConnectMsg.text}</Alert>}
      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Remote administration" description="Allowlisted, signed, short-lived commands. Every action needs a reason and is audited." />
          {isolated && <div className="mx-4 mt-3"><Alert tone="danger"><ShieldOff className="mr-1.5 inline size-4" /><b>Network isolated</b> — this endpoint is contained; only the management channel is allowed.</Alert></div>}
          {!remote ? <p className="px-4 py-3 text-sm text-silver-500">Your role cannot perform remote actions.</p> : !active ? <p className="px-4 py-3 text-sm text-silver-500">Endpoint is {device.status}; remote actions are disabled.</p> : (
            <div className="flex flex-wrap gap-2 p-4">
              <Button size="sm" variant="outline" onClick={() => ask('device.inspect', {}, 'Inspect live status', 'Collects uptime, load, signed-in users and local accounts (read-only).')}><Activity />Inspect status</Button>
              <Button size="sm" variant="outline" onClick={() => ask('device.lock', {}, 'Lock the endpoint', 'Locks the screen immediately; the user signs in again to continue. Unsaved work is kept.')}><Lock />Lock</Button>
              <Button size="sm" variant="outline" onClick={() => ask('device.restart', { message: 'Your IT administrator scheduled a restart. Save your work.' }, 'Restart the endpoint', 'Schedules a restart with an on-screen warning. Unsaved work in open applications may be lost.', true)}><Power />Restart</Button>
              <Button size="sm" variant="ghost" onClick={() => ask('device.restart_cancel', {}, 'Cancel scheduled restart/shutdown', 'Aborts a pending restart or power-off if one is scheduled.')}><PowerOff />Cancel restart</Button>
              <Button size="sm" variant="outline" onClick={() => ask('device.shutdown', { message: 'Your IT administrator scheduled a shutdown. Save your work.' }, 'Power off the endpoint', 'Schedules a power-off with an on-screen warning. Unsaved work in open applications may be lost; the device goes offline.', true)}><PowerOff />Power off</Button>
              <Button size="sm" variant="outline" onClick={() => ask('device.logoff', {}, 'Log off the user', 'Ends the active interactive session, returning to the sign-in screen. Unsaved work in open applications may be lost.', true)}><UserX />Log off user</Button>
              <Button size="sm" onClick={() => { assist.reset(); setAssistOpen(true) }} disabled={!!open || !device.online} title={!device.online ? 'Endpoint offline' : undefined}><Headset />Remote assistance</Button>
              <Button size="sm" onClick={() => { rdp.reset(); setRdpOpen(true) }} disabled={!!open || !device.online} title={!device.online ? 'Endpoint offline' : undefined}><Monitor />Remote desktop</Button>
              <Button size="sm" onClick={() => { screen.reset(); setScreenOpen(true) }} disabled={!!open || !device.online} title={!device.online ? 'Endpoint offline' : 'Works on any Windows edition (incl. Home)'}><MonitorSmartphone />Remote screen</Button>
              {canShell && <Button size="sm" variant="outline" onClick={() => { shell.reset(); setShellOpen(true) }} disabled={!!open || !device.online} title={!device.online ? 'Endpoint offline' : undefined}><Terminal />Live-response shell</Button>}
              {canIsolate && (isolated
                ? <Button size="sm" variant="primary" onClick={() => ask('device.release', {}, 'Release from isolation', 'Restores normal network access on the endpoint and removes the containment firewall rules.')}><ShieldOff />Release isolation</Button>
                : <Button size="sm" variant="danger" onClick={() => ask('device.isolate', {}, 'Network-isolate the endpoint', 'Contains the endpoint: blocks all traffic except the management channel so you can still release it. Use for a suspected compromise.', true)} disabled={!device.online} title={!device.online ? 'Endpoint offline' : undefined}><ShieldOff />Isolate</Button>)}
            </div>
          )}
          <div className="border-t border-ink-700 px-4 py-3">
            <div className="mb-2 text-xs font-medium text-silver-500">Live status {latestInspect && <span className="font-normal">· {relativeTime(latestInspect.completed_at ?? latestInspect.issued_at)}</span>}</div>
            {!latestInspect ? <p className="text-xs text-silver-600">Run “Inspect status” to collect a live snapshot.</p> : (
              <>
                <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 text-sm">
                  <dt className="text-silver-500">Uptime</dt><dd>{fmtUptime(st.uptime_seconds)}</dd>
                  <dt className="text-silver-500">CPU / memory</dt><dd>{st.cpu_percent ?? '—'}% / {st.memory_percent ?? '—'}%</dd>
                  <dt className="text-silver-500">Signed-in users</dt><dd>{st.logged_on_users?.join(', ') || 'none'}</dd>
                  <dt className="text-silver-500">Processes</dt><dd>{st.process_count ?? '—'}</dd>
                </dl>
                {!!st.top_processes?.length && (
                  <div className="mt-3">
                    <div className="mb-1 text-xs font-medium text-silver-500">Top processes · by memory</div>
                    <ul className="space-y-0.5 text-xs">
                      {st.top_processes.slice(0, 8).map((p) => (
                        <li key={p.pid} className="flex items-center justify-between gap-2">
                          <span className="truncate text-silver-200">{p.name}</span>
                          <span className="shrink-0 text-silver-500">{p.mem_percent}% · pid {p.pid}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
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
          <CardHeader title="Remote sessions" description="Remote assistance (Quick Assist) and remote desktop (RDP)." />
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
            {WITH_DELAY.has(pending.command) && (
              <Field label="Warning delay before restart (seconds)" htmlFor="rd"><Input id="rd" type="number" min={60} max={3600} value={delay} onChange={(e) => setDelay(Number(e.target.value))} /></Field>
            )}
            <Field label="Reason (shown in the audit log)" htmlFor="rr"><Input id="rr" required minLength={3} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
            {SENSITIVE.has(pending.command) && (
              <Field label="Confirm with your password" htmlFor="rp"><Input id="rp" type="password" required autoComplete="current-password" value={stepPw} onChange={(e) => setStepPw(e.target.value)} /></Field>
            )}
            <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={reset}>Cancel</Button>
              <Button type="submit" variant={pending.danger ? 'danger' : 'primary'} loading={act.isPending}>Confirm &amp; send</Button></div>
          </form>
        )}
      </Dialog>

      <Dialog open={assistOpen} onOpenChange={(o) => !o && reset()} title="Request remote assistance"
        description="The person at the endpoint is asked to allow the session (unless your organisation disabled consent). A red banner stays on their screen for the whole session and they can end it at any time. Screen sharing uses Windows Quick Assist, opened only after consent.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); assist.mutate() }} className="space-y-3">
          {assist.error && <Alert>{describeError(assist.error)}</Alert>}
          <Field label="Reason (shown to the user)" htmlFor="ar"><Input id="ar" required minLength={5} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <Field label="Maximum duration (minutes)" htmlFor="am"><Input id="am" type="number" min={5} max={120} value={assistMinutes} onChange={(e) => setAssistMinutes(Number(e.target.value))} /></Field>
          <Field label="Confirm with your password" htmlFor="ap"><Input id="ap" type="password" required autoComplete="current-password" value={stepPw} onChange={(e) => setStepPw(e.target.value)} /></Field>
          <div className="flex justify-end"><Button type="submit" loading={assist.isPending}><Headset />Confirm &amp; send request</Button></div>
        </form>
      </Dialog>

      <Dialog open={rdpOpen} onOpenChange={(o) => !o && reset()} title="Start remote desktop (RDP)"
        description="Starts an unattended Remote Desktop session: no password and no consent prompt on the endpoint. A visible 'Remote desktop active' banner is shown on the endpoint for the whole session, which the person there can end at any time. Once active, connect with your own RDP client to the address shown above.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); rdp.mutate() }} className="space-y-3">
          {rdp.error && <Alert>{describeError(rdp.error)}</Alert>}
          <Field label="Reason (audited)" htmlFor="rr2"><Input id="rr2" required minLength={5} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <Field label="Maximum duration (minutes)" htmlFor="rm"><Input id="rm" type="number" min={5} max={120} value={assistMinutes} onChange={(e) => setAssistMinutes(Number(e.target.value))} /></Field>
          <div className="flex justify-end"><Button type="submit" loading={rdp.isPending}><Monitor />Start remote desktop</Button></div>
        </form>
      </Dialog>

      <Dialog open={shellOpen} onOpenChange={(o) => !o && reset()} title="Open a live-response shell"
        description="Opens an interactive shell on the endpoint (arbitrary commands — break-glass). A visible banner is shown on the endpoint for the whole session and EVERY command is written to the audit trail. Runs as the logged-in user unless elevated.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); shell.mutate() }} className="space-y-3">
          {shell.error && <Alert>{describeError(shell.error)}</Alert>}
          <Field label="Reason (audited)" htmlFor="sr"><Input id="sr" required minLength={5} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <Field label="Maximum duration (minutes)" htmlFor="sm2"><Input id="sm2" type="number" min={5} max={120} value={assistMinutes} onChange={(e) => setAssistMinutes(Number(e.target.value))} /></Field>
          {canShellElevated && (
            <label className="flex items-center gap-2 text-sm text-silver-300">
              <input type="checkbox" checked={shellElevated} onChange={(e) => setShellElevated(e.target.checked)} />
              Run elevated (SYSTEM/root) — more dangerous, extra audit
            </label>
          )}
          <div className="flex justify-end"><Button type="submit" variant="danger" loading={shell.isPending}><Terminal />Open shell</Button></div>
        </form>
      </Dialog>

      <Dialog open={screenOpen} onOpenChange={(o) => !o && reset()} title="Start remote screen"
        description="Shares the endpoint's screen and lets you control it — the agent captures the screen and injects your mouse/keyboard, so it works on ANY Windows edition (including Home) and across any network, with no RDP host. No consent prompt, but a visible 'Remote screen active' banner is shown on the endpoint for the whole session, which the person there can end at any time.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); screen.mutate() }} className="space-y-3">
          {screen.error && <Alert>{describeError(screen.error)}</Alert>}
          <Field label="Reason (audited)" htmlFor="scr"><Input id="scr" required minLength={5} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <Field label="Maximum duration (minutes)" htmlFor="scm"><Input id="scm" type="number" min={5} max={120} value={assistMinutes} onChange={(e) => setAssistMinutes(Number(e.target.value))} /></Field>
          <div className="flex justify-end"><Button type="submit" loading={screen.isPending}><MonitorSmartphone />Start remote screen</Button></div>
        </form>
      </Dialog>

      {termSession && <ShellTerminal sessionId={termSession} hostname={device.hostname} onClose={() => setTermSession(null)} />}
      {screenSession && <ScreenViewer sessionId={screenSession} hostname={device.hostname} onClose={() => setScreenSession(null)} />}
    </div>
  )
}
