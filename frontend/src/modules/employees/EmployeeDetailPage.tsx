import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Ban, KeyRound, Pencil, RotateCcw, UserX } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Field, Input, Spinner, statusTone } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { Device, Employee, EmployeeEvent, Page } from '@/types/api'
import { ConnectivityBadge, DeviceStatusBadge } from '@/modules/devices/shared'
import { formatDate, formatDateTime } from '@/utils/format'
import { EmployeeForm } from './EmployeesPage'

type Action = 'suspend' | 'reactivate' | 'offboard'
const ACTION_COPY: Record<Action, { title: string; description: string; button: string; danger?: boolean }> = {
  suspend: { title: 'Suspend employee', description: 'Blocks the employee and revokes their active sessions. Reversible.', button: 'Suspend', danger: true },
  reactivate: { title: 'Reactivate employee', description: 'Restores the employee to active status.', button: 'Reactivate' },
  offboard: { title: 'Offboard employee (leaver)', description: 'Permanently ends this identity: status becomes offboarded, sessions are revoked and administrators are notified. This cannot be undone.', button: 'Offboard', danger: true },
}

const EVENT_LABEL: Record<string, string> = { joiner: 'Joiner', mover: 'Mover', leaver: 'Leaver', suspend: 'Suspended', reactivate: 'Reactivated', update: 'Details updated' }

export function EmployeeDetailPage() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [action, setAction] = useState<Action | null>(null)
  const [reason, setReason] = useState('')

  const emp = useQuery({ queryKey: ['employee', id], queryFn: () => api.get<Employee>(`/employees/${id}`) })
  const devices = useQuery({ queryKey: ['devices', { employee_id: id }], queryFn: () => api.get<Page<Device>>(`/devices?employee_id=${id}&page_size=50`), enabled: can('devices:read') })
  const appsQ = useQuery({ queryKey: ['employee', id, 'apps'], queryFn: () => api.get<{ assignment_id: string; application_id: string; name: string; granted_at: string; revoked_at: string | null; revoke_reason: string | null }[]>(`/employees/${id}/applications`), enabled: can('employees:read') })
  const portalGrant = useMutation({ mutationFn: () => api.post(`/employees/${id}/portal-access`), onSuccess: () => { qc.invalidateQueries({ queryKey: ['employee', id] }) } })
  const portalRevoke = useMutation({ mutationFn: () => api.del(`/employees/${id}/portal-access`), onSuccess: () => { qc.invalidateQueries({ queryKey: ['employee', id] }) } })
  const events = useQuery({ queryKey: ['employee', id, 'events'], queryFn: () => api.get<EmployeeEvent[]>(`/employees/${id}/events`) })
  const refresh = () => { qc.invalidateQueries({ queryKey: ['employee', id] }); qc.invalidateQueries({ queryKey: ['employees'] }) }

  const update = useMutation({ mutationFn: (b: Record<string, unknown>) => api.patch<Employee>(`/employees/${id}`, b), onSuccess: () => { refresh(); setEditing(false) } })
  const lifecycle = useMutation({
    mutationFn: ({ a, r }: { a: Action; r: string }) => api.post<Employee>(`/employees/${id}/${a}`, { reason: r }),
    onSuccess: () => { refresh(); setAction(null); setReason('') },
  })

  if (emp.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (emp.error) return <Alert>{describeError(emp.error)}</Alert>
  const e = emp.data!
  const canLifecycle = can('employees:lifecycle')
  const portal = { grant: () => portalGrant.mutate(), revoke: () => portalRevoke.mutate() }

  function submitAction(ev: FormEvent) {
    ev.preventDefault()
    if (action) lifecycle.mutate({ a: action, r: reason })
  }

  return (
    <div className="animate-fade-in space-y-4">
      <Link to="/employees" className="inline-flex items-center gap-1 text-xs text-silver-500 hover:text-silver-200"><ArrowLeft className="size-3.5" />Employees</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold text-silver-50">{e.full_name}</h1>
            <Badge tone={statusTone(e.status)}>{e.status}</Badge>
          </div>
          <p className="mt-0.5 text-sm text-silver-500">{e.job_title} · {e.department} · <span className="font-mono">{e.employee_number}</span></p>
        </div>
        <div className="flex flex-wrap gap-2">
          {can('employees:write') && e.status !== 'offboarded' && <Button variant="outline" size="sm" onClick={() => { update.reset(); setEditing(true) }}><Pencil />Edit / move</Button>}
          {canLifecycle && (e.status === 'active' || e.status === 'invited') && <Button variant="outline" size="sm" onClick={() => setAction('suspend')}><Ban />Suspend</Button>}
          {canLifecycle && e.status === 'suspended' && <Button variant="outline" size="sm" onClick={() => setAction('reactivate')}><RotateCcw />Reactivate</Button>}
          {canLifecycle && e.status === 'active' && !e.user_id && <Button variant="outline" size="sm" onClick={portal.grant} loading={portalGrant.isPending}><KeyRound />Invite to workspace</Button>}
          {canLifecycle && e.status !== 'offboarded' && <Button variant="danger" size="sm" onClick={() => setAction('offboard')}><UserX />Offboard</Button>}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Identity" />
          <dl className="grid grid-cols-[120px_1fr] gap-y-2.5 px-4 py-3 text-sm">
            <dt className="text-silver-500">Email</dt><dd className="break-all text-silver-100">{e.email}</dd>
            <dt className="text-silver-500">Employee ID</dt><dd className="font-mono text-silver-100">{e.employee_number}</dd>
            <dt className="text-silver-500">Department</dt><dd>{e.department}</dd>
            <dt className="text-silver-500">Job title</dt><dd>{e.job_title}</dd>
            <dt className="text-silver-500">Start date</dt><dd>{formatDate(e.start_date)}</dd>
            <dt className="text-silver-500">End date</dt><dd>{formatDate(e.end_date)}</dd>
            <dt className="text-silver-500">Created</dt><dd>{formatDateTime(e.created_at)}</dd>
          </dl>
        </Card>
        <Card>
          <CardHeader title="Assigned endpoints" description={`Enrolment: ${e.enrollment_status.replace('_', ' ')}`} />
          {!can('devices:read') ? <p className="px-4 py-3 text-xs text-silver-500">Your role cannot view endpoint inventory.</p>
            : devices.isLoading ? <div className="p-4"><Spinner /></div>
            : !devices.data?.items.length ? <p className="px-4 py-3 text-sm text-silver-500">No endpoints assigned. Generate an enrollment token for this employee from the Endpoints page.</p> : (
              <ul className="divide-y divide-ink-800">{devices.data.items.map((d) => (
                <li key={d.id} className="flex items-center justify-between gap-2 px-4 py-2.5">
                  <div className="min-w-0"><Link to={`/endpoints/${d.id}`} className="text-sm text-silver-100 hover:text-emerald-300">{d.display_name}</Link>
                    <div className="truncate text-xs text-silver-500">{d.os_name ?? 'OS not reported'}</div></div>
                  <div className="flex shrink-0 items-center gap-2"><ConnectivityBadge c={d.connectivity} last={d.last_heartbeat_at} /><DeviceStatusBadge status={d.status} /></div>
                </li>))}</ul>
            )}
          <div className="border-t border-ink-700 px-4 py-3">
            <div className="mb-1.5 flex items-center justify-between text-xs"><span className="font-medium text-silver-500">Workspace account</span>
              {e.user_id ? <span className="flex items-center gap-2"><Badge tone="success">invited / active</Badge>{canLifecycle && e.status !== 'offboarded' && <button className="text-silver-500 hover:text-red-300" onClick={portal.revoke}>Revoke</button>}</span> : <Badge>none</Badge>}</div>
            {(portalGrant.error || portalRevoke.error) && <Alert>{describeError(portalGrant.error ?? portalRevoke.error)}</Alert>}
            <div className="mb-1 mt-3 text-xs font-medium text-silver-500">Application access</div>
            {!appsQ.data?.length ? <p className="text-xs text-silver-600">No applications assigned.</p> : (
              <ul className="space-y-1">{appsQ.data.map((a) => (
                <li key={a.assignment_id} className="flex items-center justify-between text-sm"><Link to={`/applications/${a.application_id}`} className={a.revoked_at ? 'text-silver-600 line-through' : 'text-silver-100 hover:text-emerald-300'}>{a.name}</Link>
                  <span className="text-xs text-silver-500">{a.revoked_at ? `revoked${a.revoke_reason ? ` (${a.revoke_reason})` : ''}` : `since ${formatDate(a.granted_at)}`}</span></li>
              ))}</ul>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Lifecycle history" description="Joiner · mover · leaver" />
          {events.isLoading ? <div className="p-4"><Spinner /></div> : (
            <ol className="max-h-80 overflow-y-auto px-4 py-2">
              {events.data?.map((ev) => (
                <li key={ev.id} className="relative border-l border-ink-700 py-2 pl-4">
                  <span className="absolute -left-[3.5px] top-3.5 size-1.5 rounded-full bg-emerald-500/70" />
                  <div className="text-[13px] text-silver-100">{EVENT_LABEL[ev.kind] ?? ev.kind}</div>
                  <div className="text-[11px] text-silver-500">{formatDateTime(ev.created_at)}</div>
                  {'reason' in ev.details && <div className="mt-0.5 text-xs text-silver-400">Reason: {String(ev.details.reason)}</div>}
                  {ev.kind === 'mover' || ev.kind === 'update' ? (
                    <ul className="mt-0.5 text-xs text-silver-400">
                      {Object.entries(ev.details as Record<string, { from: string | null; to: string | null }>).map(([k, v]) => (
                        <li key={k}>{k.replace('_', ' ')}: <span className="text-silver-500 line-through">{v.from ?? '—'}</span> → {v.to ?? '—'}</li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <Dialog open={editing} onOpenChange={setEditing} title="Edit employee" description="Department, title or manager changes are recorded as a mover event.">
        <EmployeeForm initial={e} includeIdentity={false} submitLabel="Save changes" submitting={update.isPending} error={update.error ? describeError(update.error) : null}
          onSubmit={(b) => {
            const changed = Object.fromEntries(Object.entries(b).filter(([k, v]) => (e as unknown as Record<string, unknown>)[k] !== v))
            if (Object.keys(changed).length === 0) setEditing(false)
            else update.mutate(changed)
          }} />
      </Dialog>

      <Dialog open={!!action} onOpenChange={(o) => { if (!o) { setAction(null); lifecycle.reset() } }} title={action ? ACTION_COPY[action].title : ''} description={action ? ACTION_COPY[action].description : ''}>
        <form onSubmit={submitAction} className="space-y-3">
          {lifecycle.error && <Alert>{describeError(lifecycle.error)}</Alert>}
          <Field label="Reason (recorded in the audit log)" htmlFor="reason"><Input id="reason" required minLength={3} maxLength={500} value={reason} onChange={(ev) => setReason(ev.target.value)} autoFocus /></Field>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setAction(null)}>Cancel</Button>
            <Button type="submit" variant={action && ACTION_COPY[action].danger ? 'danger' : 'primary'} loading={lifecycle.isPending}>{action ? ACTION_COPY[action].button : ''}</Button>
          </div>
        </form>
      </Dialog>
    </div>
  )
}
