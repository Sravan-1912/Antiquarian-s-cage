import { useMemo, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileCode2, Play, Plus, Rocket, Trash2 } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { api, describeError } from '@/services/api'
import { relativeTime } from '@/utils/format'

interface ScriptSummary { id: string; name: string; description: string; interpreter: string; timeout_seconds: number; created_at: string; updated_at: string }
interface Script extends ScriptSummary { content: string; created_by: string | null }
interface ScriptRun {
  id: string; script_id: string; device_id: string; script_name: string; status: string
  exit_code: number | null; stdout: string; stderr: string; requested_by_label: string | null
  created_at: string; finished_at: string | null
}
interface DeviceLite { id: string; display_name: string; hostname: string; connectivity: string; online: boolean }
interface Page<T> { items: T[]; total: number }

const INTERPRETERS = [
  { value: 'powershell', label: 'PowerShell (.ps1)' },
  { value: 'cmd', label: 'Windows cmd (.bat)' },
  { value: 'bash', label: 'Bash (.sh)' },
]

const RUN_TONE: Record<string, 'success' | 'danger' | 'warning' | 'neutral'> = {
  succeeded: 'success', failed: 'danger', needs_attention: 'warning', rejected: 'danger', queued: 'neutral',
}

type Draft = { name: string; description: string; interpreter: string; content: string; timeout_seconds: number }
const empty: Draft = { name: '', description: '', interpreter: 'powershell', content: '', timeout_seconds: 300 }

function ScriptDialog({ open, onClose, editing }: { open: boolean; onClose: () => void; editing: Script | null }) {
  const qc = useQueryClient()
  const [d, setD] = useState<Draft>(editing
    ? { name: editing.name, description: editing.description, interpreter: editing.interpreter, content: editing.content, timeout_seconds: editing.timeout_seconds }
    : empty)
  const save = useMutation({
    mutationFn: () => editing ? api.put(`/scripts/${editing.id}`, d) : api.post('/scripts', d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scripts'] }); onClose() },
  })
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} title={editing ? 'Edit script' : 'New script'}
      description="Scripts run on endpoints in the agent's service context. Each deployment is signed, audited, and captured with its output — treat this like the live-response shell.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} className="space-y-3">
        {save.error && <Alert>{describeError(save.error)}</Alert>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" htmlFor="scn"><Input id="scn" required maxLength={128} value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder="e.g. Clear temp files" /></Field>
          <Field label="Interpreter" htmlFor="sci">
            <Select id="sci" className="w-full" value={d.interpreter} onChange={(e) => setD({ ...d, interpreter: e.target.value })}>
              {INTERPRETERS.map((i) => <option key={i.value} value={i.value}>{i.label}</option>)}
            </Select>
          </Field>
        </div>
        <Field label="Description" htmlFor="scd"><Input id="scd" maxLength={500} value={d.description} onChange={(e) => setD({ ...d, description: e.target.value })} placeholder="What does this script do?" /></Field>
        <Field label="Script" htmlFor="scc">
          <textarea id="scc" required rows={12} spellCheck={false}
            className="cage-input w-full rounded-md px-3 py-2 font-mono text-xs leading-relaxed placeholder:text-silver-600"
            value={d.content} onChange={(e) => setD({ ...d, content: e.target.value })}
            placeholder={d.interpreter === 'bash' ? '#!/bin/bash\necho hello' : 'Write-Output "hello"'} />
        </Field>
        <Field label="Timeout (seconds)" htmlFor="sct" hint="5–3600. The run is killed and marked failed if it exceeds this.">
          <Input id="sct" type="number" min={5} max={3600} value={d.timeout_seconds} onChange={(e) => setD({ ...d, timeout_seconds: Number(e.target.value) || 0 })} className="w-40" />
        </Field>
        <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={save.isPending} disabled={!d.name.trim() || !d.content.trim()}>{editing ? 'Save' : 'Create'}</Button></div>
      </form>
    </Dialog>
  )
}

function DeployDialog({ script, onClose }: { script: ScriptSummary; onClose: () => void }) {
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<Record<string, boolean>>({})
  const [reason, setReason] = useState('')
  const devices = useQuery({ queryKey: ['devices', 'for-deploy'], queryFn: () => api.get<Page<DeviceLite>>('/devices?page_size=100') })
  const items = devices.data?.items ?? []
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase()
    return t ? items.filter((d) => d.display_name.toLowerCase().includes(t) || d.hostname.toLowerCase().includes(t)) : items
  }, [items, q])
  const chosen = Object.keys(sel).filter((k) => sel[k])
  const deploy = useMutation({
    mutationFn: () => api.post<ScriptRun[]>(`/scripts/${script.id}/deploy`, { device_ids: chosen, reason: reason.trim() }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['script-runs', script.id] }); onClose() },
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Deploy “${script.name}”`}
      description="Run this script on the selected endpoints. Offline endpoints run it when they next check in. Every run is audited and its output captured.">
      <div className="space-y-3">
        {deploy.error && <Alert>{describeError(deploy.error)}</Alert>}
        <Input placeholder="Filter endpoints…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="max-h-60 space-y-1 overflow-y-auto rounded-md border border-ink-700 bg-ink-850 p-2">
          {devices.isLoading ? <div className="grid h-24 place-items-center"><Spinner /></div>
            : shown.length === 0 ? <p className="p-2 text-sm text-silver-500">No endpoints.</p>
              : shown.map((d) => (
                <label key={d.id} className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-sm text-silver-200 hover:bg-ink-800">
                  <input type="checkbox" className="size-3.5 accent-[color:var(--cage-accent)]" checked={!!sel[d.id]}
                    onChange={() => setSel((s) => ({ ...s, [d.id]: !s[d.id] }))} />
                  <span className="truncate">{d.display_name}</span>
                  <span className="ml-auto shrink-0"><Badge tone={d.online ? 'success' : 'neutral'}>{d.online ? 'online' : d.connectivity}</Badge></span>
                </label>
              ))}
        </div>
        <Field label="Reason" htmlFor="dpr"><Input id="dpr" required minLength={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why are you running this?" /></Field>
        <div className="flex items-center justify-between">
          <span className="text-xs text-silver-500">{chosen.length} endpoint{chosen.length === 1 ? '' : 's'} selected</span>
          <div className="flex gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button onClick={() => deploy.mutate()} loading={deploy.isPending} disabled={chosen.length === 0 || reason.trim().length < 3}><Rocket />Deploy</Button></div>
        </div>
      </div>
    </Dialog>
  )
}

function RunsDialog({ script, onClose }: { script: ScriptSummary; onClose: () => void }) {
  const q = useQuery({ queryKey: ['script-runs', script.id], queryFn: () => api.get<ScriptRun[]>(`/scripts/${script.id}/runs`), refetchInterval: 5000 })
  const runs = q.data ?? []
  const [openRun, setOpenRun] = useState<string | null>(null)
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Runs — ${script.name}`}
      description="Per-endpoint execution history. Status and output update automatically as endpoints report back.">
      {q.isLoading ? <div className="grid h-32 place-items-center"><Spinner /></div>
        : runs.length === 0 ? <EmptyState icon={Play} title="No runs yet" description="Deploy this script to an endpoint to see results here." />
          : (
            <div className="max-h-[60vh] space-y-2 overflow-y-auto">
              {runs.map((r) => (
                <div key={r.id} className="rounded-md border border-ink-700 bg-ink-850">
                  <button className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm" onClick={() => setOpenRun(openRun === r.id ? null : r.id)}>
                    <Badge tone={RUN_TONE[r.status] ?? 'neutral'}>{r.status}</Badge>
                    <span className="truncate text-silver-200">{r.device_id.slice(0, 8)}…</span>
                    {r.exit_code != null && <span className="text-xs text-silver-500">exit {r.exit_code}</span>}
                    <span className="ml-auto shrink-0 text-xs text-silver-600">{relativeTime(r.finished_at ?? r.created_at)}</span>
                  </button>
                  {openRun === r.id && (
                    <div className="space-y-2 border-t border-ink-700 p-3">
                      {r.stdout && <div><div className="mb-1 text-[11px] uppercase tracking-wide text-silver-600">stdout</div><pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-ink-900 p-2 font-mono text-xs text-silver-200">{r.stdout}</pre></div>}
                      {r.stderr && <div><div className="mb-1 text-[11px] uppercase tracking-wide text-silver-600">stderr</div><pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-ink-900 p-2 font-mono text-xs text-red-300">{r.stderr}</pre></div>}
                      {!r.stdout && !r.stderr && <p className="text-xs text-silver-500">No output{r.status === 'queued' ? ' yet — waiting for the endpoint.' : '.'}</p>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
    </Dialog>
  )
}

export function ScriptsPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['scripts'], queryFn: () => api.get<ScriptSummary[]>('/scripts') })
  const [editing, setEditing] = useState<Script | null>(null)
  const [dialog, setDialog] = useState(false)
  const [deploy, setDeploy] = useState<ScriptSummary | null>(null)
  const [runs, setRuns] = useState<ScriptSummary | null>(null)
  const del = useMutation({
    mutationFn: (id: string) => api.del(`/scripts/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scripts'] }),
  })
  const openEdit = async (s: ScriptSummary) => { setEditing(await api.get<Script>(`/scripts/${s.id}`)); setDialog(true) }
  const scripts = q.data ?? []
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Scripts" description="A library of reusable scripts you can deploy to endpoints. Each run is signed, audited, and its output captured — gated on the live-response (devices:shell) permission."
        actions={<Button onClick={() => { setEditing(null); setDialog(true) }}><Plus />New script</Button>} />
      <Card>
        <CardHeader title="Library" description="PowerShell, cmd or bash scripts available to deploy." />
        {q.isLoading ? <div className="grid h-40 place-items-center"><Spinner /></div>
          : scripts.length === 0 ? <EmptyState icon={FileCode2} title="No scripts yet" description="Create a script to deploy it across your fleet." action={<Button size="sm" onClick={() => { setEditing(null); setDialog(true) }}><Plus />New script</Button>} />
            : (
              <Table>
                <thead><tr><Th>Name</Th><Th>Interpreter</Th><Th>Updated</Th><Th className="text-right">Actions</Th></tr></thead>
                <tbody>{scripts.map((s) => (
                  <tr key={s.id} className="border-t border-ink-800">
                    <Td><span className="text-silver-50">{s.name}</span>{s.description && <span className="block max-w-md truncate text-xs text-silver-500">{s.description}</span>}</Td>
                    <Td><Badge tone="neutral">{s.interpreter}</Badge></Td>
                    <Td className="text-xs text-silver-500">{relativeTime(s.updated_at)}</Td>
                    <Td className="text-right">
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" variant="outline" onClick={() => setDeploy(s)}><Rocket />Deploy</Button>
                        <Button size="sm" variant="ghost" onClick={() => setRuns(s)}><Play />Runs</Button>
                        <Button size="sm" variant="ghost" onClick={() => openEdit(s)}>Edit</Button>
                        <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Delete script “${s.name}”?`)) del.mutate(s.id) }} aria-label="Delete"><Trash2 /></Button>
                      </div>
                    </Td>
                  </tr>
                ))}</tbody>
              </Table>
            )}
      </Card>
      {dialog && <ScriptDialog open={dialog} editing={editing} onClose={() => setDialog(false)} />}
      {deploy && <DeployDialog script={deploy} onClose={() => setDeploy(null)} />}
      {runs && <RunsDialog script={runs} onClose={() => setRuns(null)} />}
    </div>
  )
}
