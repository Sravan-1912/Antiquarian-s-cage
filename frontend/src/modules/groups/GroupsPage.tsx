import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Plus, Rocket, Trash2, Users } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'

interface Criteria { q?: string; status?: string; connectivity?: string; os?: string; compliance_state?: string }
interface Group { id: string; name: string; description: string; criteria: Criteria; member_count: number; created_at: string; updated_at: string }
interface Member { id: string; display_name: string; hostname: string; status: string; os_name: string | null; compliance_state: string; connectivity: string; online: boolean }
interface ScriptSummary { id: string; name: string; interpreter: string }
interface BulkResult { kind: string; total: number; dispatched: number; skipped: number; results: { device_id: string; hostname: string; ok: boolean; detail: string | null }[] }

const clean = (c: Criteria): Criteria => Object.fromEntries(Object.entries(c).filter(([, v]) => v)) as Criteria
const CRIT_LABEL: Record<string, (v: string) => string> = {
  q: (v) => `matches “${v}”`, status: (v) => `status: ${v}`, connectivity: (v) => v, os: (v) => `OS ~ ${v}`,
  compliance_state: (v) => v.replace('_', '-'),
}
function criteriaChips(c: Criteria) {
  const e = Object.entries(clean(c))
  return e.length ? e.map(([k, v]) => <Badge key={k} tone="neutral">{(CRIT_LABEL[k] ?? ((x: string) => x))(String(v))}</Badge>) : <span className="text-xs text-silver-500">All endpoints</span>
}

type Draft = { name: string; description: string; criteria: Criteria }
const empty: Draft = { name: '', description: '', criteria: {} }

function GroupDialog({ open, onClose, editing }: { open: boolean; onClose: () => void; editing: Group | null }) {
  const qc = useQueryClient()
  const [d, setD] = useState<Draft>(editing ? { name: editing.name, description: editing.description, criteria: { ...editing.criteria } } : empty)
  const setC = (k: keyof Criteria, v: string) => setD((p) => ({ ...p, criteria: { ...p.criteria, [k]: v || undefined } }))
  const preview = useQuery({
    queryKey: ['group-preview', d.criteria],
    queryFn: () => api.post<Member[]>('/device-groups/preview', { criteria: clean(d.criteria) }),
  })
  const save = useMutation({
    mutationFn: () => editing ? api.put(`/device-groups/${editing.id}`, { ...d, criteria: clean(d.criteria) }) : api.post('/device-groups', { ...d, criteria: clean(d.criteria) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['device-groups'] }); onClose() },
  })
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} title={editing ? 'Edit group' : 'New dynamic group'}
      description="Membership is live: endpoints are matched by these criteria every time, so a group always reflects the current fleet.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} className="space-y-3">
        {save.error && <Alert>{describeError(save.error)}</Alert>}
        <Field label="Name" htmlFor="gn"><Input id="gn" required maxLength={128} value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder="e.g. Non-compliant Windows laptops" /></Field>
        <Field label="Description" htmlFor="gd"><Input id="gd" maxLength={500} value={d.description} onChange={(e) => setD({ ...d, description: e.target.value })} /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name / serial contains" htmlFor="gq"><Input id="gq" value={d.criteria.q ?? ''} onChange={(e) => setC('q', e.target.value)} placeholder="any text" /></Field>
          <Field label="Operating system contains" htmlFor="go"><Input id="go" value={d.criteria.os ?? ''} onChange={(e) => setC('os', e.target.value)} placeholder="e.g. Windows" /></Field>
          <Field label="Status" htmlFor="gs"><Select id="gs" className="w-full" value={d.criteria.status ?? ''} onChange={(e) => setC('status', e.target.value)}>
            <option value="">Any</option><option value="active">Active</option><option value="suspended">Suspended</option><option value="revoked">Revoked</option><option value="unenrolled">Unenrolled</option></Select></Field>
          <Field label="Connectivity" htmlFor="gc"><Select id="gc" className="w-full" value={d.criteria.connectivity ?? ''} onChange={(e) => setC('connectivity', e.target.value)}>
            <option value="">Any</option><option value="online">Online</option><option value="offline">Offline</option><option value="never">Never reported</option></Select></Field>
          <Field label="Compliance" htmlFor="gm"><Select id="gm" className="w-full" value={d.criteria.compliance_state ?? ''} onChange={(e) => setC('compliance_state', e.target.value)}>
            <option value="">Any</option><option value="compliant">Compliant</option><option value="non_compliant">Non-compliant</option><option value="unknown">Unknown</option></Select></Field>
        </div>
        <div className="rounded-md border border-ink-700 bg-ink-850 px-3 py-2 text-sm text-silver-300">
          {preview.isFetching ? 'Matching…' : <><span className="font-semibold text-silver-100">{preview.data?.length ?? 0}</span> endpoint{(preview.data?.length ?? 0) === 1 ? '' : 's'} currently match{(preview.data?.length ?? 0) === 1 ? 'es' : ''}.</>}
        </div>
        <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={save.isPending} disabled={!d.name.trim()}>{editing ? 'Save' : 'Create'}</Button></div>
      </form>
    </Dialog>
  )
}

function BulkDialog({ group, onClose }: { group: Group; onClose: () => void }) {
  const { can } = useAuth()
  const [kind, setKind] = useState<'script' | 'action' | 'status'>(can('devices:shell') ? 'script' : 'action')
  const [scriptId, setScriptId] = useState('')
  const [command, setCommand] = useState('device.inspect')
  const [op, setOp] = useState<'suspend' | 'reactivate'>('suspend')
  const [reason, setReason] = useState('')
  const [password, setPassword] = useState('')
  const [result, setResult] = useState<BulkResult | null>(null)
  const scripts = useQuery({ queryKey: ['scripts'], queryFn: () => api.get<ScriptSummary[]>('/scripts'), enabled: can('devices:shell') })
  const SENSITIVE = command === 'device.restart' || command === 'device.isolate' || command === 'device.release'

  const run = useMutation({
    mutationFn: () => {
      const body = kind === 'script' ? { kind, script_id: scriptId, reason }
        : kind === 'action' ? { kind, command, parameters: command === 'device.restart' ? { delay_seconds: 300 } : {}, reason, ...(SENSITIVE ? { step_up: { password } } : {}) }
          : { kind, op, reason }
      return api.post<BulkResult>(`/device-groups/${group.id}/bulk`, body)
    },
    onSuccess: (r) => setResult(r),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Bulk action — ${group.name}`}
      description={`Applies to the ${group.member_count} endpoint${group.member_count === 1 ? '' : 's'} that currently match. Each endpoint is actioned individually, signed and audited.`}>
      {result ? (
        <div className="space-y-3">
          <Alert tone={result.skipped ? 'warning' : 'success'}>{result.dispatched} of {result.total} dispatched{result.skipped ? ` · ${result.skipped} skipped` : ''}.</Alert>
          <div className="max-h-60 space-y-1 overflow-y-auto">
            {result.results.map((r) => (
              <div key={r.device_id} className="flex items-center gap-2 rounded px-2 py-1 text-sm">
                <Badge tone={r.ok ? 'success' : 'danger'}>{r.ok ? 'ok' : 'skipped'}</Badge>
                <span className="truncate text-silver-200">{r.hostname}</span>
                {r.detail && <span className="ml-auto truncate text-xs text-silver-500">{r.detail}</span>}
              </div>
            ))}
          </div>
          <div className="flex justify-end"><Button onClick={onClose}>Done</Button></div>
        </div>
      ) : (
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); run.mutate() }} className="space-y-3">
          {run.error && <Alert>{describeError(run.error)}</Alert>}
          <Field label="Action type" htmlFor="bk">
            <Select id="bk" className="w-full" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
              {can('devices:shell') && <option value="script">Deploy a script</option>}
              {can('devices:remote') && <option value="action">Remote action</option>}
              <option value="status">Change status</option>
            </Select>
          </Field>
          {kind === 'script' && (
            <Field label="Script" htmlFor="bs"><Select id="bs" className="w-full" value={scriptId} onChange={(e) => setScriptId(e.target.value)}>
              <option value="">Select a script…</option>{scripts.data?.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.interpreter})</option>)}</Select></Field>
          )}
          {kind === 'action' && (
            <Field label="Command" htmlFor="ba"><Select id="ba" className="w-full" value={command} onChange={(e) => setCommand(e.target.value)}>
              <option value="device.inspect">Inspect (read-only)</option><option value="device.lock">Lock</option>
              <option value="device.restart">Restart (warns users)</option><option value="device.restart_cancel">Cancel restart</option>
              {can('devices:isolate') && <><option value="device.isolate">Network-isolate</option><option value="device.release">Release isolation</option></>}
            </Select></Field>
          )}
          {kind === 'status' && (
            <Field label="Status" htmlFor="bo"><Select id="bo" className="w-full" value={op} onChange={(e) => setOp(e.target.value as typeof op)}>
              <option value="suspend">Suspend</option><option value="reactivate">Reactivate</option></Select></Field>
          )}
          <Field label="Reason" htmlFor="br"><Input id="br" required minLength={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why?" /></Field>
          {kind === 'action' && SENSITIVE && <Field label="Confirm your password" htmlFor="bp" hint="This action is sensitive and requires re-entering your password."><Input id="bp" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} /></Field>}
          <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" loading={run.isPending} disabled={reason.trim().length < 3 || (kind === 'script' && !scriptId)}><Rocket />Run on {group.member_count}</Button></div>
        </form>
      )}
    </Dialog>
  )
}

function MembersDialog({ group, onClose }: { group: Group; onClose: () => void }) {
  const q = useQuery({ queryKey: ['group-members', group.id], queryFn: () => api.get<Member[]>(`/device-groups/${group.id}/members`) })
  const rows = q.data ?? []
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Members — ${group.name}`} description="The endpoints that currently match this group's criteria.">
      {q.isLoading ? <div className="grid h-32 place-items-center"><Spinner /></div>
        : rows.length === 0 ? <EmptyState icon={Users} title="No members" description="No endpoints currently match." />
          : (
            <div className="max-h-[60vh] overflow-y-auto">
              <Table>
                <thead><tr><Th>Endpoint</Th><Th>OS</Th><Th>Status</Th><Th>Connectivity</Th></tr></thead>
                <tbody>{rows.map((m) => (
                  <tr key={m.id} className="border-t border-ink-800">
                    <Td><span className="text-silver-100">{m.display_name}</span><span className="block text-xs text-silver-500">{m.hostname}</span></Td>
                    <Td className="text-xs text-silver-400">{m.os_name ?? '—'}</Td>
                    <Td><Badge tone={m.status === 'active' ? 'success' : 'neutral'}>{m.status}</Badge></Td>
                    <Td><Badge tone={m.online ? 'success' : 'neutral'}>{m.online ? 'online' : m.connectivity}</Badge></Td>
                  </tr>
                ))}</tbody>
              </Table>
            </div>
          )}
    </Dialog>
  )
}

export function GroupsPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['device-groups'], queryFn: () => api.get<Group[]>('/device-groups') })
  const [dialog, setDialog] = useState(false)
  const [editing, setEditing] = useState<Group | null>(null)
  const [bulk, setBulk] = useState<Group | null>(null)
  const [members, setMembers] = useState<Group | null>(null)
  const del = useMutation({ mutationFn: (id: string) => api.del(`/device-groups/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['device-groups'] }) })
  const groups = q.data ?? []
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Endpoint groups" description="Dynamic groups match endpoints by live criteria (status, OS, connectivity, compliance). Run bulk actions — deploy a script, a remote action, or a status change — across every current member."
        actions={<Button onClick={() => { setEditing(null); setDialog(true) }}><Plus />New group</Button>} />
      <Card>
        <CardHeader title="Groups" />
        {q.isLoading ? <div className="grid h-40 place-items-center"><Spinner /></div>
          : groups.length === 0 ? <EmptyState icon={Boxes} title="No groups yet" description="Create a dynamic group to target bulk actions." action={<Button size="sm" onClick={() => { setEditing(null); setDialog(true) }}><Plus />New group</Button>} />
            : (
              <Table>
                <thead><tr><Th>Name</Th><Th>Criteria</Th><Th>Members</Th><Th className="text-right">Actions</Th></tr></thead>
                <tbody>{groups.map((g) => (
                  <tr key={g.id} className="border-t border-ink-800">
                    <Td><span className="text-silver-50">{g.name}</span>{g.description && <span className="block max-w-xs truncate text-xs text-silver-500">{g.description}</span>}</Td>
                    <Td><div className="flex flex-wrap gap-1">{criteriaChips(g.criteria)}</div></Td>
                    <Td><button className="text-silver-100 hover:text-emerald-300" onClick={() => setMembers(g)}>{g.member_count}</button></Td>
                    <Td className="text-right">
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" variant="outline" onClick={() => setBulk(g)} disabled={g.member_count === 0}><Rocket />Bulk action</Button>
                        <Button size="sm" variant="ghost" onClick={() => setMembers(g)}><Users />Members</Button>
                        <Button size="sm" variant="ghost" onClick={() => { setEditing(g); setDialog(true) }}>Edit</Button>
                        <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Delete group “${g.name}”?`)) del.mutate(g.id) }} aria-label="Delete"><Trash2 /></Button>
                      </div>
                    </Td>
                  </tr>
                ))}</tbody>
              </Table>
            )}
      </Card>
      {dialog && <GroupDialog open={dialog} editing={editing} onClose={() => setDialog(false)} />}
      {bulk && <BulkDialog group={bulk} onClose={() => setBulk(null)} />}
      {members && <MembersDialog group={members} onClose={() => setMembers(null)} />}
    </div>
  )
}
