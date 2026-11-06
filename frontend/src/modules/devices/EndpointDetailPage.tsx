import { Fragment, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Ban, KeyRound, Pencil, RotateCcw, Trash2 } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { AdminUser, Device, DeviceCertificate, DeviceEvent, Employee, Heartbeat, Inventory, Page } from '@/types/api'
import { formatDateTime, relativeTime } from '@/utils/format'
import { ConnectivityBadge, DeviceStatusBadge, SECURITY_LABELS, SecurityStateBadge, formatBytes } from './shared'
import { DeviceComplianceCard, DevicePoliciesCard } from '@/modules/compliance/DeviceComplianceCard'
import { RemotePanel } from '@/modules/remote/RemotePanel'

type Op = 'suspend' | 'reactivate' | 'revoke' | 'unenroll'
const OPS: Record<Op, { title: string; description: string; button: string; danger: boolean }> = {
  suspend: { title: 'Suspend endpoint', description: 'The agent keeps sending heartbeats so the device stays visible, but it is marked suspended and stops uploading inventory. Reversible.', button: 'Suspend', danger: true },
  reactivate: { title: 'Reactivate endpoint', description: 'Returns the endpoint to active management.', button: 'Reactivate', danger: false },
  revoke: { title: 'Revoke endpoint credentials', description: 'Immediately revokes the device certificate. The agent can no longer authenticate; the device must be re-enrolled with a new token.', button: 'Revoke credentials', danger: true },
  unenroll: { title: 'Unenrol endpoint', description: 'Removes the endpoint from management and revokes any remaining credentials. History is retained for audit.', button: 'Unenrol', danger: true },
}

function Dl({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[130px_1fr] gap-y-2 px-4 py-3 text-sm">
      {rows.map(([k, v]) => <Fragment key={k}><dt className="text-silver-500">{k}</dt><dd className="min-w-0 break-words text-silver-100">{v ?? '—'}</dd></Fragment>)}
    </dl>
  )
}

export function EndpointDetailPage() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const [op, setOp] = useState<Op | null>(null)
  const [reason, setReason] = useState('')
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState({ display_name: '', employee_id: '', support_owner_id: '' })

  const device = useQuery({ queryKey: ['device', id], queryFn: () => api.get<Device>(`/devices/${id}`), refetchInterval: 30_000 })
  const inv = useQuery({ queryKey: ['device', id, 'inventory'], queryFn: () => api.get<Inventory | null>(`/devices/${id}/inventory`) })
  const events = useQuery({ queryKey: ['device', id, 'events'], queryFn: () => api.get<DeviceEvent[]>(`/devices/${id}/events`) })
  const certs = useQuery({ queryKey: ['device', id, 'certs'], queryFn: () => api.get<DeviceCertificate[]>(`/devices/${id}/certificates`) })
  const beats = useQuery({ queryKey: ['device', id, 'heartbeats'], queryFn: () => api.get<Heartbeat[]>(`/devices/${id}/heartbeats`), refetchInterval: 30_000 })
  const employees = useQuery({ queryKey: ['employees', 'active-all'], queryFn: () => api.get<Page<Employee>>('/employees?status=active&page_size=100'), enabled: editing })
  const admins = useQuery({ queryKey: ['admins'], queryFn: () => api.get<AdminUser[]>('/users'), enabled: editing && can('users:read') })
  const refresh = () => { qc.invalidateQueries({ queryKey: ['device', id] }); qc.invalidateQueries({ queryKey: ['devices'] }) }

  const action = useMutation({ mutationFn: () => api.post<Device>(`/devices/${id}/${op}`, { reason }), onSuccess: () => { refresh(); setOp(null); setReason('') } })
  const update = useMutation({
    mutationFn: () => api.patch<Device>(`/devices/${id}`, {
      display_name: form.display_name, employee_id: form.employee_id || null, ...(can('users:read') ? { support_owner_id: form.support_owner_id || null } : {}),
    }),
    onSuccess: () => { refresh(); qc.invalidateQueries({ queryKey: ['employees'] }); setEditing(false) },
  })

  if (device.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (device.error) return <Alert>{describeError(device.error)}</Alert>
  const d = device.data!
  const i = inv.data
  const manage = can('devices:manage')
  const managed = d.status === 'active' || d.status === 'suspended'

  return (
    <div className="animate-fade-in space-y-4">
      <Link to="/endpoints" className="inline-flex items-center gap-1 text-xs text-silver-500 hover:text-silver-200"><ArrowLeft className="size-3.5" />Endpoints</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold text-silver-50">{d.display_name}</h1>
            <DeviceStatusBadge status={d.status} />
            <ConnectivityBadge c={d.connectivity} last={d.last_heartbeat_at} />
          </div>
          <p className="mt-0.5 text-sm text-silver-500">{[d.manufacturer, d.model].filter(Boolean).join(' ') || 'Hardware not yet reported'} · <span className="font-mono text-xs">{d.id}</span></p>
        </div>
        {manage && (
          <div className="flex flex-wrap gap-2">
            {managed && <Button size="sm" variant="outline" onClick={() => { update.reset(); setForm({ display_name: d.display_name, employee_id: d.employee_id ?? '', support_owner_id: d.support_owner_id ?? '' }); setEditing(true) }}><Pencil />Edit / assign</Button>}
            {d.status === 'active' && <Button size="sm" variant="outline" onClick={() => setOp('suspend')}><Ban />Suspend</Button>}
            {d.status === 'suspended' && <Button size="sm" variant="outline" onClick={() => setOp('reactivate')}><RotateCcw />Reactivate</Button>}
            {managed && <Button size="sm" variant="outline" onClick={() => setOp('revoke')}><KeyRound />Revoke credentials</Button>}
            {d.status !== 'unenrolled' && <Button size="sm" variant="danger" onClick={() => setOp('unenroll')}><Trash2 />Unenrol</Button>}
          </div>
        )}
      </div>

      {d.status === 'revoked' && <Alert tone="warning">Credentials revoked — this agent can no longer authenticate. Re-enrol the device with a new token to manage it again.</Alert>}

      {(can('devices:remote') || can('devices:read')) && <RemotePanel device={d} />}

      <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Overview" description="Values reported by the agent unless noted" />
          <Dl rows={[
            ['Hostname', d.hostname],
            ['Assigned to', d.employee_id ? <Link className="text-emerald-400 hover:text-emerald-300" to={`/employees/${d.employee_id}`}>{d.employee_name}</Link> : 'Unassigned'],
            ['Operating system', d.os_name],
            ['OS version', [d.os_version, d.os_build && `build ${d.os_build}`].filter(Boolean).join(' · ') || null],
            ['Serial number', d.serial_number],
            ['Agent version', d.agent_version],
            ['Enrolled', formatDateTime(d.enrolled_at)],
            ['Last heartbeat', d.last_heartbeat_at ? `${formatDateTime(d.last_heartbeat_at)} (${relativeTime(d.last_heartbeat_at)})` : 'Never'],
            ['Last inventory', formatDateTime(d.last_inventory_at)],
            ['Source IP', <span className="font-mono text-xs">{d.last_seen_ip ?? '—'} <span className="font-sans text-silver-600">(observed by server)</span></span>],
            ['Reported IPs', <span className="font-mono text-xs">{d.reported_ip_addresses.addresses?.join(', ') || '—'}</span>],
            ['MAC addresses', <span className="font-mono text-xs">{d.reported_mac_addresses.addresses?.join(', ') || '—'}</span>],
          ]} />
        </Card>
        <Card>
          <CardHeader title="Hardware" description={i ? `Inventory received ${relativeTime(i.collected_at)}` : undefined} />
          {!i ? <EmptyState icon={Pencil} title="No inventory received yet" description="The agent uploads inventory after its first successful heartbeat." /> : (
            <>
              <Dl rows={[
                ['Processor', i.cpu.name],
                ['Cores / threads', i.cpu.physical_cores != null ? `${i.cpu.physical_cores} / ${i.cpu.logical_processors}` : null],
                ['Memory', formatBytes(i.memory_bytes)],
                ['OS edition', i.os.edition],
                ['Architecture', i.os.architecture],
                ['Last boot', i.os.last_boot ? formatDateTime(i.os.last_boot) : null],
              ]} />
              <div className="border-t border-ink-700 px-4 py-3">
                <div className="mb-2 text-xs font-medium text-silver-500">Disks</div>
                <ul className="space-y-2.5">{i.disks.items.map((k) => {
                  const pct = k.total_bytes ? Math.round((k.used_bytes / k.total_bytes) * 100) : 0
                  return (
                    <li key={k.mountpoint}>
                      <div className="flex justify-between text-xs"><span className="text-silver-200">{k.mountpoint} <span className="text-silver-600">{k.filesystem}</span></span><span className="text-silver-400">{formatBytes(k.free_bytes)} free of {formatBytes(k.total_bytes)}</span></div>
                      <div className="mt-1 h-1.5 overflow-hidden rounded bg-ink-700"><div className={pct > 90 ? 'h-full bg-red-500' : pct > 75 ? 'h-full bg-amber-500' : 'h-full bg-emerald-500'} style={{ width: `${pct}%` }} /></div>
                    </li>
                  )
                })}</ul>
              </div>
            </>
          )}
        </Card>
        <Card>
          <CardHeader title="Reported security configuration" description="Raw evidence reported by the agent. Interpreted by the compliance engine below." />
          {!i ? <EmptyState icon={KeyRound} title="Not yet reported" /> : (
            <ul className="divide-y divide-ink-800">{Object.entries(i.security).map(([k, c]) => (
              <li key={k} className="flex items-start justify-between gap-3 px-4 py-2">
                <div className="min-w-0 flex-1 overflow-hidden">
                  <div className="text-sm text-silver-100">{SECURITY_LABELS[k] ?? k}</div>
                  {c.detail && <div className="text-xs text-silver-500">{c.detail}</div>}
                  {Object.keys(c.data).length > 0 && <div className="mt-0.5 truncate font-mono text-[11px] text-silver-600">{Object.entries(c.data).map(([dk, dv]) => `${dk}=${String(dv)}`).join(' ')}</div>}
                </div>
                <SecurityStateBadge name={k} check={c} />
              </li>
            ))}</ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        {can('compliance:read') && <DeviceComplianceCard deviceId={d.id} />}
        {can('policies:read') && <DevicePoliciesCard deviceId={d.id} />}
      </div>

      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Network interfaces" />
          {!i?.network_interfaces.items.length ? <p className="px-4 py-3 text-sm text-silver-500">None reported.</p> : (
            <Table>
              <thead><tr><Th>Interface</Th><Th>MAC</Th><Th>IPv4</Th><Th>State</Th></tr></thead>
              <tbody>{i.network_interfaces.items.map((n) => (
                <tr key={n.name}><Td>{n.name}</Td><Td className="font-mono text-xs">{n.mac_address ?? '—'}</Td><Td className="font-mono text-xs">{n.ipv4.join(', ') || '—'}</Td>
                  <Td>{n.is_up ? <Badge tone="success">up{n.speed_mbps ? ` · ${n.speed_mbps} Mb/s` : ''}</Badge> : <Badge>down</Badge>}</Td></tr>
              ))}</tbody>
            </Table>
          )}
        </Card>
        <Card>
          <CardHeader title="Device history" />
          <ol className="max-h-72 overflow-y-auto px-4 py-2">{events.data?.map((e) => (
            <li key={e.id} className="relative border-l border-ink-700 py-2 pl-4">
              <span className="absolute -left-[3.5px] top-3.5 size-1.5 rounded-full bg-emerald-500/70" />
              <div className="text-[13px] text-silver-100">{e.kind.replace(/_/g, ' ')}</div>
              <div className="text-[11px] text-silver-500">{formatDateTime(e.created_at)}</div>
              {'reason' in e.details && <div className="text-xs text-silver-400">Reason: {String(e.details.reason)}</div>}
            </li>
          ))}</ol>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Device certificates" description="Issued by the internal device CA; private keys never leave the endpoint." />
          <Table>
            <thead><tr><Th>Serial</Th><Th>Status</Th><Th>Valid until</Th><Th>Fingerprint (SHA-256)</Th></tr></thead>
            <tbody>{certs.data?.map((c) => (
              <tr key={c.id}><Td className="font-mono text-xs">{c.serial.slice(0, 12)}…</Td>
                <Td><Badge tone={c.status === 'active' ? 'success' : c.status === 'revoked' ? 'danger' : 'neutral'}>{c.status}</Badge></Td>
                <Td className="text-silver-400">{formatDateTime(c.not_after)}</Td>
                <Td className="font-mono text-[11px] text-silver-500">{c.fingerprint_sha256.slice(0, 24)}…</Td></tr>
            ))}</tbody>
          </Table>
        </Card>
        <Card>
          <CardHeader title="Recent heartbeats" description="Authenticated heartbeats received by the server" />
          {!beats.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No heartbeats received.</p> : (
            <div className="max-h-72 overflow-y-auto"><Table>
              <thead><tr><Th>Received</Th><Th>Source IP</Th><Th>Agent</Th><Th>Uptime</Th></tr></thead>
              <tbody>{beats.data.slice(0, 30).map((b) => (
                <tr key={b.received_at}><Td className="text-silver-400">{formatDateTime(b.received_at)}</Td><Td className="font-mono text-xs">{b.source_ip ?? '—'}</Td>
                  <Td className="font-mono text-xs">{b.agent_version}</Td><Td className="text-silver-400">{b.uptime_seconds != null ? `${Math.floor(b.uptime_seconds / 3600)} h` : '—'}</Td></tr>
              ))}</tbody>
            </Table></div>
          )}
        </Card>
      </div>

      <Dialog open={!!op} onOpenChange={(o) => { if (!o) { setOp(null); action.reset() } }} title={op ? OPS[op].title : ''} description={op ? OPS[op].description : ''}>
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); action.mutate() }} className="space-y-3">
          {action.error && <Alert>{describeError(action.error)}</Alert>}
          <Field label="Reason (recorded in the audit log)" htmlFor="dr"><Input id="dr" required minLength={3} maxLength={500} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setOp(null)}>Cancel</Button>
            <Button type="submit" variant={op && OPS[op].danger ? 'danger' : 'primary'} loading={action.isPending}>{op ? OPS[op].button : ''}</Button></div>
        </form>
      </Dialog>

      <Dialog open={editing} onOpenChange={setEditing} title="Edit endpoint" description="Assignment changes are recorded in the device history and audit log.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); update.mutate() }} className="space-y-3">
          {update.error && <Alert>{describeError(update.error)}</Alert>}
          <Field label="Display name" htmlFor="dn"><Input id="dn" required maxLength={128} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="Assigned employee" htmlFor="de">
            <Select id="de" className="w-full" value={form.employee_id} onChange={(e) => setForm({ ...form, employee_id: e.target.value })}>
              <option value="">Unassigned</option>
              {d.employee_id && !employees.data?.items.some((x) => x.id === d.employee_id) && <option value={d.employee_id}>{d.employee_name}</option>}
              {employees.data?.items.map((x) => <option key={x.id} value={x.id}>{x.full_name} · {x.employee_number}</option>)}
            </Select>
          </Field>
          {can('users:read') && (
            <Field label="IT support owner" htmlFor="ds">
              <Select id="ds" className="w-full" value={form.support_owner_id} onChange={(e) => setForm({ ...form, support_owner_id: e.target.value })}>
                <option value="">None</option>
                {admins.data?.filter((u) => u.status === 'active').map((u) => <option key={u.id} value={u.id}>{u.full_name} · {u.roles.map((r) => r.name).join(', ')}</option>)}
              </Select>
            </Field>
          )}
          <div className="flex justify-end"><Button type="submit" loading={update.isPending}>Save</Button></div>
        </form>
      </Dialog>
    </div>
  )
}
