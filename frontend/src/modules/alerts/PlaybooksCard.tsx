import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Plus, ShieldAlert, Trash2, Zap } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, Select, Spinner } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { api, describeError } from '@/services/api'

interface Playbook { id: string; name: string; enabled: boolean; match_rule_keys: string[]; match_min_severity: string; match_kinds: string[]; actions: string[] }
interface RuleKey { key: string; name: string; kind: string }
type Draft = Omit<Playbook, 'id'>

const ACTION_LABELS: Record<string, string> = { isolate: 'Network-isolate the endpoint', escalate: 'Escalate to critical & notify', comment: 'Add a note to the alert' }
const empty: Draft = { name: '', enabled: true, match_rule_keys: [], match_min_severity: 'high', match_kinds: [], actions: ['escalate'] }

function PlaybookDialog({ open, onClose, editing }: { open: boolean; onClose: () => void; editing: Playbook | null }) {
  const qc = useQueryClient()
  // The dialog mounts fresh each time it opens, so the editing row (or a blank draft) seeds the initial state.
  const [d, setD] = useState<Draft>(editing ? { ...editing } : empty)
  const rules = useQuery({ queryKey: ['playbook-rule-keys'], queryFn: () => api.get<RuleKey[]>('/playbooks/rule-keys'), enabled: open })
  const toggle = (arr: string[], v: string) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v])

  const save = useMutation({
    mutationFn: () => editing ? api.put(`/playbooks/${editing.id}`, d) : api.post('/playbooks', d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); onClose() },
  })

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} title={editing ? 'Edit playbook' : 'New response playbook'}
      description="When a new alert matches the trigger, the actions run automatically. Isolate is powerful — use it only for high-confidence rules.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} className="space-y-3">
        {save.error && <Alert>{describeError(save.error)}</Alert>}
        <Field label="Name" htmlFor="pbn"><Input id="pbn" required maxLength={128} value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder="e.g. Isolate on EDR detection" /></Field>
        <Field label="Trigger when severity is at least" htmlFor="pbs">
          <Select id="pbs" className="w-full" value={d.match_min_severity} onChange={(e) => setD({ ...d, match_min_severity: e.target.value })}>
            <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
          </Select>
        </Field>
        <div>
          <div className="mb-1.5 text-xs font-medium text-silver-400">Only these rules (none = any rule)</div>
          <div className="max-h-36 space-y-1 overflow-y-auto rounded-md border border-ink-700 bg-ink-850 p-2">
            {rules.data?.map((r) => (
              <label key={r.key} className="flex cursor-pointer items-center gap-2 text-sm text-silver-200">
                <input type="checkbox" className="size-3.5 accent-[color:var(--cage-accent)]" checked={d.match_rule_keys.includes(r.key)}
                  onChange={() => setD({ ...d, match_rule_keys: toggle(d.match_rule_keys, r.key) })} />
                {r.name} <span className="text-[11px] text-silver-600">{r.kind}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <div className="mb-1.5 text-xs font-medium text-silver-400">Actions</div>
          <div className="space-y-1">
            {(['isolate', 'escalate', 'comment'] as const).map((a) => (
              <label key={a} className="flex cursor-pointer items-center gap-2 text-sm text-silver-200">
                <input type="checkbox" className="size-3.5 accent-[color:var(--cage-accent)]" checked={d.actions.includes(a)}
                  onChange={() => setD({ ...d, actions: toggle(d.actions, a) })} />
                {ACTION_LABELS[a]}{a === 'isolate' && <ShieldAlert className="size-3.5 text-amber-400" />}
              </label>
            ))}
          </div>
        </div>
        <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={save.isPending} disabled={!d.actions.length}>{editing ? 'Save' : 'Create'}</Button></div>
      </form>
    </Dialog>
  )
}

export function PlaybooksCard() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['playbooks'], queryFn: () => api.get<Playbook[]>('/playbooks') })
  const [editing, setEditing] = useState<Playbook | null>(null)
  const [open, setOpen] = useState(false)
  const del = useMutation({ mutationFn: (id: string) => api.del(`/playbooks/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }) })
  const toggleEnabled = useMutation({
    mutationFn: (p: Playbook) => api.put(`/playbooks/${p.id}`, { ...p, enabled: !p.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  })
  const start = (p: Playbook | null) => { setEditing(p); setOpen(true) }

  return (
    <Card>
      <CardHeader title="Automated response playbooks" description="Run actions automatically when an alert matches — isolate the endpoint, escalate to critical, or annotate."
        action={<Button size="sm" onClick={() => start(null)}><Plus />New</Button>} />
      {q.isLoading ? <div className="grid h-24 place-items-center"><Spinner /></div>
        : !q.data?.length ? <EmptyState icon={Zap} title="No playbooks yet" description="Create one to respond to alerts automatically." />
          : (
            <ul className="divide-y divide-ink-800">
              {q.data.map((p) => (
                <li key={p.id} className="flex flex-wrap items-center gap-2 px-4 py-3">
                  <button type="button" className="text-left" onClick={() => start(p)}>
                    <div className="text-sm font-medium text-silver-100">{p.name}</div>
                    <div className="text-xs text-silver-500">≥ {p.match_min_severity} · {p.match_rule_keys.length ? `${p.match_rule_keys.length} rule(s)` : 'any rule'} → {p.actions.join(', ') || 'no action'}</div>
                  </button>
                  <div className="ml-auto flex items-center gap-2">
                    {!p.enabled && <Badge tone="neutral"><Ban className="size-3" />off</Badge>}
                    <button type="button" role="switch" aria-checked={p.enabled} aria-label="Enabled" onClick={() => toggleEnabled.mutate(p)}
                      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${p.enabled ? 'bg-[color:var(--cage-accent)]' : 'bg-ink-600'}`}>
                      <span className={`inline-block size-4 rounded-full bg-white transition ${p.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                    </button>
                    <Button size="sm" variant="ghost" onClick={() => del.mutate(p.id)}><Trash2 /></Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
      {open && <PlaybookDialog open={open} editing={editing} onClose={() => setOpen(false)} />}
    </Card>
  )
}
