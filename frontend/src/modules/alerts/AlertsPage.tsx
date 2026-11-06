import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, ShieldAlert } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Pagination, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError, qs } from '@/services/api'
import { formatDateTime, relativeTime } from '@/utils/format'

export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export interface SecAlert {
  id: string; rule_key: string; rule_name: string | null; kind: 'configuration' | 'operational' | 'suspicious_activity'
  title: string; description: string; severity: Sev; status: 'new' | 'triaging' | 'investigating' | 'resolved' | 'false_positive'
  device_id: string | null; device_name: string | null; employee_id: string | null; subject_label: string | null
  detected_at: string; last_seen_at: string; occurrences: number; assigned_to: string | null; assigned_to_label: string | null
  resolution_notes: string | null; resolved_at: string | null; evidence: Record<string, unknown>; auto_resolvable: boolean
  history?: { kind: string; actor: string; details: Record<string, unknown>; created_at: string }[]
}

const SEV_TONE: Record<Sev, 'danger' | 'warning' | 'info' | 'neutral'> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: 'neutral' }
export function SevBadge({ s }: { s: Sev }) {
  return <Badge tone={SEV_TONE[s]} className={s === 'critical' ? 'uppercase' : ''}>{s}</Badge>
}
const KIND_LABEL = { configuration: 'Configuration finding', operational: 'Operational', suspicious_activity: 'Suspicious activity' }
const STATUS_TONE = { new: 'warning', triaging: 'info', investigating: 'info', resolved: 'success', false_positive: 'neutral' } as const
export function StatusBadge({ s }: { s: SecAlert['status'] }) { return <Badge tone={STATUS_TONE[s]}>{s.replace('_', ' ')}</Badge> }

export function AlertsPage() {
  const nav = useNavigate()
  const [f, setF] = useState({ status: 'open', severity: '', kind: '', assigned: '', q: '' })
  const [page, setPage] = useState(1)
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => { setF({ ...f, [k]: e.target.value }); setPage(1) }
  const list = useQuery({ queryKey: ['alerts', f, page], queryFn: () => api.get<{ items: SecAlert[]; total: number }>(`/alerts${qs({ ...f, page, page_size: 50 })}`),
    placeholderData: keepPreviousData, refetchInterval: 30_000 })
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Security alerts" description="Leads for investigation. Configuration findings and operational issues are not evidence of an attack; suspicious-activity alerts need an analyst's judgement." />
      <Card>
        <div className="flex flex-wrap gap-2 border-b border-ink-700 p-3">
          <Input placeholder="Search titles…" className="max-w-xs" value={f.q} onChange={set('q')} aria-label="Search alerts" />
          <Select value={f.status} onChange={set('status')} aria-label="Status"><option value="open">Open</option><option value="closed">Closed</option><option value="">All</option>
            <option value="new">New</option><option value="triaging">Triaging</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></Select>
          <Select value={f.severity} onChange={set('severity')} aria-label="Severity"><option value="">Any severity</option>{['critical', 'high', 'medium', 'low', 'informational'].map((s) => <option key={s}>{s}</option>)}</Select>
          <Select value={f.kind} onChange={set('kind')} aria-label="Kind"><option value="">Any kind</option><option value="suspicious_activity">Suspicious activity</option><option value="configuration">Configuration</option><option value="operational">Operational</option></Select>
          <Select value={f.assigned} onChange={set('assigned')} aria-label="Assignee"><option value="">Anyone</option><option value="me">Assigned to me</option><option value="unassigned">Unassigned</option></Select>
        </div>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : list.error ? <div className="p-4"><Alert>{describeError(list.error)}</Alert></div>
          : !list.data?.items.length ? <EmptyState icon={ShieldAlert} title="No alerts match" description="Detection runs continuously on sign-ins, endpoint reports, deployments and administrative activity." /> : (
            <>
              <Table>
                <thead><tr><Th>Severity</Th><Th>Alert</Th><Th>Kind</Th><Th>Status</Th><Th>Assignee</Th><Th>Seen</Th></tr></thead>
                <tbody>{list.data.items.map((a) => (
                  <tr key={a.id} className="cursor-pointer hover:bg-ink-850" onClick={() => nav(`/alerts/${a.id}`)}>
                    <Td><SevBadge s={a.severity} /></Td>
                    <Td><Link to={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()} className="text-silver-50 hover:text-emerald-300">{a.title}</Link>
                      <div className="text-xs text-silver-500">{a.rule_name}{a.occurrences > 1 ? ` · ${a.occurrences} occurrences` : ''}</div></Td>
                    <Td className="text-xs text-silver-400">{KIND_LABEL[a.kind]}</Td>
                    <Td><StatusBadge s={a.status} /></Td>
                    <Td className="text-xs text-silver-400">{a.assigned_to_label ?? '—'}</Td>
                    <Td className="text-silver-400">{relativeTime(a.last_seen_at)}</Td>
                  </tr>
                ))}</tbody>
              </Table>
              <Pagination page={page} pageSize={50} total={list.data.total} onPage={setPage} />
            </>
          )}
      </Card>
    </div>
  )
}

const NEXT: Record<SecAlert['status'], SecAlert['status'][]> = {
  new: ['triaging', 'investigating', 'resolved', 'false_positive'], triaging: ['investigating', 'resolved', 'false_positive'],
  investigating: ['resolved', 'false_positive'], resolved: ['investigating'], false_positive: ['investigating'],
}

export function AlertDetailPage() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const manage = can('alerts:manage')
  const q = useQuery({ queryKey: ['alert', id], queryFn: () => api.get<SecAlert>(`/alerts/${id}`), refetchInterval: 30_000 })
  const analysts = useQuery({ queryKey: ['analysts'], queryFn: () => api.get<{ id: string; email: string; full_name: string }[]>('/alerts/analysts'), enabled: manage })
  const [note, setNote] = useState('')
  const [target, setTarget] = useState('')
  const upd = useMutation({ mutationFn: (body: Record<string, unknown>) => api.patch<SecAlert>(`/alerts/${id}`, body),
    onSuccess: () => { setNote(''); setTarget(''); qc.invalidateQueries({ queryKey: ['alert', id] }); qc.invalidateQueries({ queryKey: ['alerts'] }) } })
  if (q.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (q.error) return <Alert>{describeError(q.error)}</Alert>
  const a = q.data!
  const closing = target === 'resolved' || target === 'false_positive'

  return (
    <div className="animate-fade-in space-y-4">
      <Link to="/alerts" className="inline-flex items-center gap-1 text-xs text-silver-500 hover:text-silver-200"><ArrowLeft className="size-3.5" />Alerts</Link>
      <div>
        <div className="flex flex-wrap items-center gap-2"><SevBadge s={a.severity} /><StatusBadge s={a.status} /><Badge>{KIND_LABEL[a.kind]}</Badge></div>
        <h1 className="mt-2 text-lg font-semibold text-silver-50">{a.title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-silver-400">{a.description}</p>
      </div>
      <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Details" />
          <dl className="grid grid-cols-[120px_1fr] gap-y-2 px-4 py-3 text-sm">
            <dt className="text-silver-500">Rule</dt><dd>{a.rule_name}</dd>
            <dt className="text-silver-500">Detected</dt><dd>{formatDateTime(a.detected_at)}</dd>
            <dt className="text-silver-500">Last seen</dt><dd>{formatDateTime(a.last_seen_at)} · {a.occurrences}×</dd>
            {a.device_id && <><dt className="text-silver-500">Endpoint</dt><dd><Link className="text-emerald-400 hover:text-emerald-300" to={`/endpoints/${a.device_id}`}>{a.device_name}</Link></dd></>}
            {a.employee_id && <><dt className="text-silver-500">Employee</dt><dd><Link className="text-emerald-400 hover:text-emerald-300" to={`/employees/${a.employee_id}`}>View employee</Link></dd></>}
            {a.subject_label && !a.device_id && <><dt className="text-silver-500">Subject</dt><dd className="break-all">{a.subject_label}</dd></>}
            <dt className="text-silver-500">Assignee</dt><dd>{a.assigned_to_label ?? 'Unassigned'}</dd>
            {a.resolution_notes && <><dt className="text-silver-500">Resolution</dt><dd>{a.resolution_notes}</dd></>}
            {a.auto_resolvable && <><dt className="text-silver-500">Auto-resolve</dt><dd className="text-xs text-silver-500">Closes automatically when the condition clears.</dd></>}
          </dl>
        </Card>
        <Card>
          <CardHeader title="Evidence" description="As recorded by detection (endpoint-reported data is unverified)." />
          <pre className="max-h-80 overflow-auto px-4 py-3 font-mono text-[11px] text-silver-300">{JSON.stringify(a.evidence, null, 2)}</pre>
        </Card>
        <Card>
          <CardHeader title="Investigation" />
          {!manage ? <p className="px-4 py-3 text-sm text-silver-500">Your role can view alerts but not handle them.</p> : (
            <div className="space-y-3 p-4">
              {upd.error && <Alert>{describeError(upd.error)}</Alert>}
              <Field label="Assign to" htmlFor="as">
                <Select id="as" className="w-full" value={a.assigned_to ?? ''} onChange={(e) => upd.mutate(e.target.value ? { assigned_to: e.target.value } : { unassign: true })}>
                  <option value="">Unassigned</option>{analysts.data?.map((u) => <option key={u.id} value={u.id}>{u.full_name} ({u.email})</option>)}
                </Select>
              </Field>
              <form className="space-y-2" onSubmit={(e: FormEvent) => { e.preventDefault(); upd.mutate({ ...(target ? { status: target } : {}), ...(note.trim() ? { note } : {}) }) }}>
                <Field label="Change status" htmlFor="st">
                  <Select id="st" className="w-full" value={target} onChange={(e) => setTarget(e.target.value)}>
                    <option value="">Keep “{a.status.replace('_', ' ')}”</option>{NEXT[a.status].map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                  </Select>
                </Field>
                <Field label={closing ? 'Resolution notes (required)' : 'Investigation note'} htmlFor="nt">
                  <textarea id="nt" rows={3} required={closing} minLength={closing ? 5 : undefined} value={note} onChange={(e) => setNote(e.target.value)}
                    className="w-full rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-sm text-silver-100 focus:border-emerald-600/70 focus:outline-none" />
                </Field>
                <Button type="submit" size="sm" loading={upd.isPending} disabled={!target && !note.trim()}>Save</Button>
              </form>
            </div>
          )}
        </Card>
      </div>
      <Card>
        <CardHeader title="History" />
        <ol className="px-4 py-2">{a.history?.map((h, i) => (
          <li key={i} className="relative border-l border-ink-700 py-2 pl-4">
            <span className="absolute -left-[3.5px] top-3.5 size-1.5 rounded-full bg-emerald-500/70" />
            <div className="text-[13px] text-silver-100">{h.kind === 'status' ? `Status ${String(h.details.from).replace('_', ' ')} → ${String(h.details.to).replace('_', ' ')}` : h.kind.replace('_', ' ')}
              <span className="ml-2 text-xs text-silver-500">{h.actor} · {formatDateTime(h.created_at)}</span></div>
            {typeof h.details.note === 'string' && <div className="text-xs text-silver-400">{h.details.note}</div>}
            {typeof h.details.reason === 'string' && <div className="text-xs text-silver-400">{h.details.reason}</div>}
            {typeof h.details.occurrences === 'number' && <div className="text-xs text-silver-500">occurrence #{h.details.occurrences}</div>}
          </li>
        ))}</ol>
      </Card>
    </div>
  )
}

