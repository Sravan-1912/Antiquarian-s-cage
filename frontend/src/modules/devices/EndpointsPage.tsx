import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, Download, KeyRound, Laptop, Plus } from 'lucide-react'
import {
  Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Pagination, Select, Spinner, Table, Td, Th,
} from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError, download, qs } from '@/services/api'
import type { Device, Employee, EnrollmentToken, Page } from '@/types/api'
import { formatDateTime, relativeTime } from '@/utils/format'
import { ConnectivityBadge, DeviceStatusBadge } from './shared'

function EnrollDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [employeeId, setEmployeeId] = useState('')
  const [minutes, setMinutes] = useState(60)
  const [copied, setCopied] = useState(false)
  const employees = useQuery({ queryKey: ['employees', 'active-all'], queryFn: () => api.get<Page<Employee>>('/employees?status=active&page_size=100'), enabled: open })
  const create = useMutation({
    mutationFn: () => api.post<EnrollmentToken>('/enrollment-tokens', { label, employee_id: employeeId || null, expires_in_minutes: minutes }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['enrollment-tokens'] }),
  })
  const server = window.location.origin.replace(':5173', ':8000')
  const token = create.data?.token
  // Plain-HTTP servers are only accepted by the agent for localhost development, and need explicit flags.
  const devFlags = server.startsWith('http://') ? ' --allow-insecure-localhost --key-scope user' : ''
  const command = token ? `cage-agent enroll --server ${server} --token ${token}${devFlags}` : ''

  function close(o: boolean) {
    if (!o) { create.reset(); setLabel(''); setEmployeeId(''); setCopied(false) }
    onOpenChange(o)
  }

  return (
    <Dialog open={open} onOpenChange={close} title="Enrol an endpoint" description="Creates a single-use, short-lived enrollment token. The device generates its own key; the token is only used once to obtain a device certificate.">
      {token ? (
        <div className="space-y-3">
          <Alert tone="warning">Copy this token now — it is shown only once and is stored server-side as a hash.</Alert>
          <div className="rounded-md border border-ink-600 bg-ink-950 p-3 font-mono text-lg tracking-wider text-silver-50">{token}</div>
          <div>
            <div className="mb-1 text-xs text-silver-500">On the Windows endpoint (elevated prompt):</div>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-ink-950 p-2 font-mono text-xs text-silver-200">{command}</pre>
          </div>
          <div className="flex justify-between">
            <span className="text-xs text-silver-500">Expires {formatDateTime(create.data!.expires_at)}</span>
            <Button size="sm" variant="secondary" onClick={() => { void navigator.clipboard.writeText(command); setCopied(true) }}>{copied ? <Check /> : <Copy />}{copied ? 'Copied' : 'Copy command'}</Button>
          </div>
        </div>
      ) : (
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }} className="space-y-3">
          {create.error && <Alert>{describeError(create.error)}</Alert>}
          <Field label="Label (who/what is this for?)" htmlFor="tl"><Input id="tl" required minLength={2} maxLength={128} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Grace's replacement laptop" /></Field>
          <Field label="Assign to employee (optional)" htmlFor="te">
            <Select id="te" className="w-full" value={employeeId} onChange={(e) => setEmployeeId(e.target.value)}>
              <option value="">Unassigned</option>
              {employees.data?.items.map((e) => <option key={e.id} value={e.id}>{e.full_name} · {e.employee_number}</option>)}
            </Select>
          </Field>
          <Field label="Valid for" htmlFor="tm">
            <Select id="tm" className="w-full" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
              <option value={15}>15 minutes</option><option value={60}>1 hour</option><option value={240}>4 hours</option><option value={1440}>24 hours</option>
            </Select>
          </Field>
          <div className="flex justify-end"><Button type="submit" loading={create.isPending}><KeyRound />Generate token</Button></div>
        </form>
      )}
    </Dialog>
  )
}

function TokensCard() {
  const qc = useQueryClient()
  const tokens = useQuery({ queryKey: ['enrollment-tokens'], queryFn: () => api.get<EnrollmentToken[]>('/enrollment-tokens') })
  const revoke = useMutation({ mutationFn: (id: string) => api.post(`/enrollment-tokens/${id}/revoke`), onSuccess: () => qc.invalidateQueries({ queryKey: ['enrollment-tokens'] }) })
  if (!tokens.data?.length) return null
  const tone = { active: 'success', used: 'neutral', expired: 'neutral', revoked: 'danger' } as const
  return (
    <Card>
      <CardHeader title="Enrollment tokens" description="Single-use. Revoke any token that may have been exposed." />
      <Table>
        <thead><tr><Th>Label</Th><Th>State</Th><Th>Created</Th><Th>Expires</Th><Th>Used by</Th><Th className="w-20" /></tr></thead>
        <tbody>{tokens.data.slice(0, 10).map((t) => (
          <tr key={t.id}>
            <Td>{t.label}</Td>
            <Td><Badge tone={tone[t.state]}>{t.state}</Badge></Td>
            <Td className="text-silver-400">{relativeTime(t.created_at)}</Td>
            <Td className="text-silver-400">{formatDateTime(t.expires_at)}</Td>
            <Td>{t.used_by_device_id ? <Link className="text-emerald-400 hover:text-emerald-300" to={`/endpoints/${t.used_by_device_id}`}>View endpoint</Link> : '—'}</Td>
            <Td>{t.state === 'active' && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(t.id)} loading={revoke.isPending && revoke.variables === t.id}>Revoke</Button>}</Td>
          </tr>
        ))}</tbody>
      </Table>
    </Card>
  )
}

export function EndpointsPage() {
  const { can } = useAuth()
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [connectivity, setConnectivity] = useState('')
  const [page, setPage] = useState(1)
  const [enrolling, setEnrolling] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const params = { q, status, connectivity }
  const list = useQuery({
    queryKey: ['devices', params, page],
    queryFn: () => api.get<Page<Device>>(`/devices${qs({ ...params, page, page_size: 25 })}`),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })
  const filtered = !!(q || status || connectivity)

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Endpoints" description="Enrolled Windows devices. Online status is derived only from authenticated heartbeats."
        actions={<>
          {can('reports:export') && can('devices:read') && <Button size="sm" variant="outline" onClick={() => download(`/devices/export.csv${qs(params)}`, 'endpoints.csv').catch((e) => setExportError(describeError(e)))}><Download />Export CSV</Button>}
          {can('devices:manage') && <Button size="sm" onClick={() => setEnrolling(true)}><Plus />Enrol endpoint</Button>}
        </>} />
      {exportError && <Alert>{exportError}</Alert>}
      <Card>
        <div className="flex flex-wrap gap-2 border-b border-ink-700 p-3">
          <Input placeholder="Hostname, serial or model…" className="max-w-xs" value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} aria-label="Search endpoints" />
          <Select value={connectivity} onChange={(e) => { setConnectivity(e.target.value); setPage(1) }} aria-label="Connectivity">
            <option value="">Any connectivity</option><option value="online">Online</option><option value="offline">Offline</option><option value="never">Never reported</option>
          </Select>
          <Select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }} aria-label="Status">
            <option value="">All statuses</option><option value="active">Active</option><option value="suspended">Suspended</option>
            <option value="revoked">Credentials revoked</option><option value="unenrolled">Unenrolled</option>
          </Select>
        </div>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : list.error ? <div className="p-4"><Alert>{describeError(list.error)}</Alert></div>
          : !list.data?.items.length ? (
            <EmptyState icon={Laptop} title={filtered ? 'No endpoints match these filters' : can('devices:read') ? 'No endpoints enrolled yet' : 'No endpoints assigned to you'}
              description="Generate an enrollment token, then run the agent's enroll command on the Windows device."
              action={can('devices:manage') && !filtered ? <Button size="sm" onClick={() => setEnrolling(true)}><Plus />Enrol the first endpoint</Button> : undefined} />
          ) : (
            <>
              <Table>
                <thead><tr><Th>Endpoint</Th><Th>Connectivity</Th><Th>Status</Th><Th>Assigned to</Th><Th>Operating system</Th><Th>Agent</Th><Th>Last heartbeat</Th></tr></thead>
                <tbody>{list.data.items.map((d) => (
                  <tr key={d.id} className="cursor-pointer hover:bg-ink-850" onClick={() => nav(`/endpoints/${d.id}`)}>
                    <Td><Link to={`/endpoints/${d.id}`} onClick={(e) => e.stopPropagation()} className="block text-silver-50 hover:text-emerald-300">{d.display_name}</Link>
                      <span className="text-xs text-silver-500">{[d.manufacturer, d.model].filter(Boolean).join(' ') || d.hostname}</span></Td>
                    <Td><ConnectivityBadge c={d.connectivity} last={d.last_heartbeat_at} /></Td>
                    <Td><DeviceStatusBadge status={d.status} /></Td>
                    <Td>{d.employee_name ?? <span className="text-silver-600">Unassigned</span>}</Td>
                    <Td className="text-silver-400">{d.os_name ?? '—'}{d.os_build && <span className="block text-xs text-silver-600">Build {d.os_build}</span>}</Td>
                    <Td className="font-mono text-xs">{d.agent_version ?? '—'}</Td>
                    <Td className="text-silver-400">{d.last_heartbeat_at ? relativeTime(d.last_heartbeat_at) : '—'}</Td>
                  </tr>
                ))}</tbody>
              </Table>
              <Pagination page={page} pageSize={25} total={list.data.total} onPage={setPage} />
            </>
          )}
      </Card>
      {can('devices:manage') && <TokensCard />}
      <EnrollDialog open={enrolling} onOpenChange={setEnrolling} />
    </div>
  )
}
