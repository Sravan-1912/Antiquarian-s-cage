import { Fragment, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Archive, ChevronDown, ChevronRight, Pencil, Plus, RotateCcw, Undo2, XCircle } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { Assignment, Deployment, Device, Page, Policy, PolicyRevision } from '@/types/api'
import { formatDateTime, relativeTime } from '@/utils/format'
import { ConnectivityBadge } from '@/modules/devices/shared'
import { CATEGORY_LABEL, CATEGORY_NOTE, ConfigEditor, DeploymentBadge, summarizeConfig } from './config'

function AssignDialog({ policy, assigned, open, onOpenChange }: { policy: Policy; assigned: Set<string>; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const devices = useQuery({ queryKey: ['devices', 'active-all'], queryFn: () => api.get<Page<Device>>('/devices?status=active&page_size=100'), enabled: open })
  const assign = useMutation({
    mutationFn: () => api.post<Deployment[]>(`/policies/${policy.id}/assign`, { device_ids: [...selected] }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policy', policy.id] }); qc.invalidateQueries({ queryKey: ['policies'] }); setSelected(new Set()); onOpenChange(false) },
  })
  const candidates = devices.data?.items.filter((d) => !assigned.has(d.id)) ?? []
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) assign.reset(); onOpenChange(o) }} title="Assign endpoints" description="Each endpoint receives a signed, expiring job. Offline endpoints pick it up when they reconnect.">
      {assign.error && <div className="mb-3"><Alert>{describeError(assign.error)}</Alert></div>}
      {devices.isLoading ? <Spinner /> : !candidates.length ? <p className="text-sm text-silver-500">No other active endpoints available.</p> : (
        <ul className="max-h-72 divide-y divide-ink-800 overflow-y-auto rounded-md border border-ink-700">
          {candidates.map((d) => (
            <li key={d.id}>
              <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-ink-850">
                <input type="checkbox" className="size-4 accent-emerald-500" checked={selected.has(d.id)}
                  onChange={(e) => { const s = new Set(selected); if (e.target.checked) s.add(d.id); else s.delete(d.id); setSelected(s) }} />
                <span className="flex-1 text-sm text-silver-100">{d.display_name}<span className="block text-xs text-silver-500">{d.os_name ?? '—'}</span></span>
                <ConnectivityBadge c={d.connectivity} last={d.last_heartbeat_at} />
              </label>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-4 flex justify-end"><Button onClick={() => assign.mutate()} disabled={!selected.size} loading={assign.isPending}>Assign {selected.size || ''} endpoint{selected.size === 1 ? '' : 's'}</Button></div>
    </Dialog>
  )
}

export function PolicyDetailPage() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const write = can('policies:write')
  const [assigning, setAssigning] = useState(false)
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<{ name: string; description: string; configuration: Record<string, unknown> } | null>(null)
  const [unassign, setUnassign] = useState<Assignment | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [flash, setFlash] = useState<{ tone: 'success' | 'danger'; msg: string } | null>(null)

  const policy = useQuery({ queryKey: ['policy', id], queryFn: () => api.get<Policy>(`/policies/${id}`), refetchInterval: 15_000 })
  const assignments = useQuery({ queryKey: ['policy', id, 'assignments'], queryFn: () => api.get<Assignment[]>(`/policies/${id}/assignments`), refetchInterval: 15_000 })
  const deployments = useQuery({ queryKey: ['policy', id, 'deployments'], queryFn: () => api.get<Deployment[]>(`/deployments?policy_id=${id}`), refetchInterval: 15_000 })
  const revisions = useQuery({ queryKey: ['policy', id, 'revisions'], queryFn: () => api.get<PolicyRevision[]>(`/policies/${id}/revisions`) })
  const refresh = () => { qc.invalidateQueries({ queryKey: ['policy', id] }); qc.invalidateQueries({ queryKey: ['policies'] }) }
  const onErr = (e: unknown) => setFlash({ tone: 'danger', msg: describeError(e) })

  const update = useMutation({ mutationFn: () => api.patch<Policy>(`/policies/${id}`, form), onSuccess: (p) => { refresh(); setEditing(false); setFlash({ tone: 'success', msg: `Saved as version ${p.version}. Changed configurations are redeployed to all assigned endpoints.` }) } })
  const doUnassign = useMutation({
    mutationFn: (rollback: boolean) => api.post(`/policies/${id}/unassign`, { device_ids: [unassign!.device_id], rollback }),
    onSuccess: (_d, rollback) => { refresh(); setUnassign(null); setFlash({ tone: 'success', msg: rollback ? 'Unassigned. A signed rollback job restores the recorded previous configuration.' : 'Unassigned without rollback; current settings remain on the endpoint.' }) },
    onError: onErr,
  })
  const retry = useMutation({ mutationFn: (did: string) => api.post(`/deployments/${did}/retry`), onSuccess: () => { refresh(); setFlash({ tone: 'success', msg: 'New signed job created.' }) }, onError: onErr })
  const revoke = useMutation({ mutationFn: (jid: string) => api.post(`/command-jobs/${jid}/revoke`), onSuccess: () => { refresh(); setFlash({ tone: 'success', msg: 'Command revoked. The agent will drop it if not yet executed.' }) }, onError: onErr })
  const retire = useMutation({ mutationFn: () => api.post(`/policies/${id}/retire`), onSuccess: refresh, onError: onErr })

  if (policy.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (policy.error) return <Alert>{describeError(policy.error)}</Alert>
  const p = policy.data!
  const active = p.status === 'active'

  return (
    <div className="animate-fade-in space-y-4">
      <Link to="/policies" className="inline-flex items-center gap-1 text-xs text-silver-500 hover:text-silver-200"><ArrowLeft className="size-3.5" />Policies</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2"><h1 className="text-lg font-semibold text-silver-50">{p.name}</h1><Badge>v{p.version}</Badge>{!active && <Badge tone="danger">retired</Badge>}</div>
          <p className="mt-0.5 text-sm text-silver-500">{CATEGORY_LABEL[p.category]} · {summarizeConfig(p.category, p.configuration)}</p>
        </div>
        {write && active && (
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={() => { update.reset(); setForm({ name: p.name, description: p.description, configuration: p.configuration }); setEditing(true) }}><Pencil />Edit</Button>
            <Button size="sm" onClick={() => setAssigning(true)}><Plus />Assign endpoints</Button>
            <Button size="sm" variant="ghost" onClick={() => retire.mutate()} loading={retire.isPending} title="Retire (requires no assignments)"><Archive /></Button>
          </div>
        )}
      </div>
      {flash && <Alert tone={flash.tone}>{flash.msg}</Alert>}
      <p className="text-xs text-silver-500">{CATEGORY_NOTE[p.category]}</p>

      <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
        <Card className="xl:col-span-2">
          <CardHeader title="Assigned endpoints" description="Latest deployment status per endpoint" />
          {!assignments.data?.length ? <EmptyState icon={Plus} title="Not assigned" description="Assign endpoints to deploy this policy." /> : (
            <Table>
              <thead><tr><Th>Endpoint</Th><Th>Status</Th><Th>Assigned</Th>{write && <Th className="w-24" />}</tr></thead>
              <tbody>{assignments.data.map((a) => (
                <tr key={a.id}>
                  <Td><Link className="text-silver-100 hover:text-emerald-300" to={`/endpoints/${a.device_id}`}>{a.device_name}</Link></Td>
                  <Td>{a.latest_status ? <DeploymentBadge status={a.latest_status} /> : '—'}</Td>
                  <Td className="text-silver-400">{relativeTime(a.assigned_at)}</Td>
                  {write && <Td><Button size="sm" variant="ghost" onClick={() => setUnassign(a)}><Undo2 />Unassign</Button></Td>}
                </tr>
              ))}</tbody>
            </Table>
          )}
        </Card>
        <Card>
          <CardHeader title="Version history" />
          <ol className="max-h-72 overflow-y-auto px-4 py-2">{revisions.data?.map((r) => (
            <li key={r.version} className="border-l border-ink-700 py-1.5 pl-3">
              <div className="text-[13px] text-silver-100">v{r.version} <span className="text-xs text-silver-500">· {formatDateTime(r.created_at)}</span></div>
              <div className="text-xs text-silver-500">{summarizeConfig(p.category, r.configuration)}</div>
            </li>
          ))}</ol>
        </Card>
      </div>

      <Card>
        <CardHeader title="Deployments" description="Every signed job and its outcome. Expand a row for the reported previous and current state." />
        {!deployments.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No deployments yet.</p> : (
          <Table>
            <thead><tr><Th className="w-6" /><Th>Endpoint</Th><Th>Action</Th><Th>Version</Th><Th>Status</Th><Th>Detail</Th><Th>Updated</Th>{write && <Th className="w-28" />}</tr></thead>
            <tbody>{deployments.data.map((d) => (
              <Fragment key={d.id}>
                <tr className="cursor-pointer hover:bg-ink-850" onClick={() => setOpen(open === d.id ? null : d.id)}>
                  <Td>{open === d.id ? <ChevronDown className="size-3.5 text-silver-500" /> : <ChevronRight className="size-3.5 text-silver-500" />}</Td>
                  <Td>{d.device_name}</Td>
                  <Td>{d.action === 'remove' ? <Badge tone="info">rollback</Badge> : <Badge>apply</Badge>}</Td>
                  <Td className="font-mono text-xs">v{d.policy_version}</Td>
                  <Td><DeploymentBadge status={d.status} /></Td>
                  <Td className="max-w-md truncate text-xs text-silver-400" title={d.detail ?? ''}>{d.detail ?? '—'}</Td>
                  <Td className="text-silver-400">{relativeTime(d.updated_at)}</Td>
                  {write && (
                    <Td onClick={(e) => e.stopPropagation()}>
                      {['failed', 'needs_attention', 'offline', 'revoked'].includes(d.status) && <Button size="sm" variant="ghost" onClick={() => retry.mutate(d.id)}><RotateCcw />Retry</Button>}
                      {['pending', 'in_progress', 'offline'].includes(d.status) && d.command_job_id && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(d.command_job_id!)}><XCircle />Revoke</Button>}
                    </Td>
                  )}
                </tr>
                {open === d.id && (
                  <tr className="bg-ink-950/60"><Td colSpan={8}>
                    <div className="grid gap-3 py-1 text-xs md:grid-cols-2">
                      <div><div className="mb-1 text-silver-500">Previous state (recorded before change)</div><pre className="overflow-x-auto rounded bg-ink-900 p-2 font-mono text-[11px] text-silver-300">{JSON.stringify(d.previous_state, null, 2)}</pre></div>
                      <div><div className="mb-1 text-silver-500">Reported current state</div><pre className="overflow-x-auto rounded bg-ink-900 p-2 font-mono text-[11px] text-silver-300">{JSON.stringify(d.result, null, 2)}</pre></div>
                      <div className="text-silver-600">Job {d.command_job_id} · created {formatDateTime(d.created_at)}</div>
                    </div>
                  </Td></tr>
                )}
              </Fragment>
            ))}</tbody>
          </Table>
        )}
      </Card>

      <AssignDialog policy={p} assigned={new Set(assignments.data?.map((a) => a.device_id))} open={assigning} onOpenChange={setAssigning} />

      <Dialog open={editing} onOpenChange={setEditing} title="Edit policy" description="Configuration changes create a new version and redeploy to every assigned endpoint." className="max-w-xl">
        {form && (
          <form onSubmit={(e: FormEvent) => { e.preventDefault(); update.mutate() }} className="space-y-3">
            {update.error && <Alert>{describeError(update.error)}</Alert>}
            <Field label="Name" htmlFor="en"><Input id="en" required minLength={3} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Description" htmlFor="ed"><Input id="ed" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
            <div className="rounded-md border border-ink-700 bg-ink-950/50 p-3"><ConfigEditor category={p.category} value={form.configuration} onChange={(c) => setForm({ ...form, configuration: c })} /></div>
            <div className="flex justify-end"><Button type="submit" loading={update.isPending}>Save new version</Button></div>
          </form>
        )}
      </Dialog>

      <Dialog open={!!unassign} onOpenChange={(o) => !o && setUnassign(null)} title={`Unassign ${unassign?.device_name ?? ''}`}
        description="Rollback sends a signed job that restores exactly the configuration the broker recorded before this policy changed it.">
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => doUnassign.mutate(false)} loading={doUnassign.isPending && doUnassign.variables === false}>Unassign, keep settings</Button>
          <Button onClick={() => doUnassign.mutate(true)} loading={doUnassign.isPending && doUnassign.variables === true}><Undo2 />Unassign and roll back</Button>
        </div>
      </Dialog>
    </div>
  )
}
