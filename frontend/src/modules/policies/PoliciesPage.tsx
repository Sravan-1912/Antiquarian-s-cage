import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, ShieldCheck } from 'lucide-react'
import { Alert, Badge, Button, Card, EmptyState, Field, Input, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { Policy, PolicyCategory } from '@/types/api'
import { relativeTime } from '@/utils/format'
import { CATEGORY_LABEL, CATEGORY_NOTE, ConfigEditor, DEFAULTS, summarizeConfig } from './config'

function CreatePolicyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const nav = useNavigate()
  const [category, setCategory] = useState<PolicyCategory>('firewall')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [config, setConfig] = useState<Record<string, unknown>>(DEFAULTS.firewall)
  const create = useMutation({
    mutationFn: () => api.post<Policy>('/policies', { name, description, category, configuration: config }),
    onSuccess: (p) => { qc.invalidateQueries({ queryKey: ['policies'] }); onOpenChange(false); nav(`/policies/${p.id}`) },
  })
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) create.reset(); onOpenChange(o) }} title="Create security policy" description="Configuration is validated by the server before it can be saved or deployed." className="max-w-xl">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }} className="space-y-3">
        {create.error && <Alert>{describeError(create.error)}</Alert>}
        <Field label="Category" htmlFor="pc">
          <Select id="pc" className="w-full" value={category} onChange={(e) => { const c = e.target.value as PolicyCategory; setCategory(c); setConfig(DEFAULTS[c]) }}>
            {(Object.keys(CATEGORY_LABEL) as PolicyCategory[]).map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>)}
          </Select>
        </Field>
        <p className="text-xs text-silver-500">{CATEGORY_NOTE[category]}</p>
        <Field label="Name" htmlFor="pn"><Input id="pn" required minLength={3} maxLength={128} value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Description" htmlFor="pd"><Input id="pd" maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        <div className="rounded-md border border-ink-700 bg-ink-950/50 p-3"><ConfigEditor key={category} category={category} value={config} onChange={setConfig} /></div>
        <div className="flex justify-end"><Button type="submit" loading={create.isPending}>Create policy</Button></div>
      </form>
    </Dialog>
  )
}

export function PoliciesPage() {
  const { can } = useAuth()
  const nav = useNavigate()
  const [category, setCategory] = useState('')
  const [creating, setCreating] = useState(false)
  const list = useQuery({ queryKey: ['policies', category], queryFn: () => api.get<Policy[]>(`/policies${category ? `?category=${category}` : ''}`), refetchInterval: 30_000 })

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Security policies" description="Versioned endpoint configuration, deployed as signed, expiring commands and applied by the privileged broker."
        actions={can('policies:write') && <Button size="sm" onClick={() => setCreating(true)}><Plus />New policy</Button>} />
      <Card>
        <div className="border-b border-ink-700 p-3">
          <Select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
            <option value="">All categories</option>
            {(Object.keys(CATEGORY_LABEL) as PolicyCategory[]).map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>)}
          </Select>
        </div>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : list.error ? <div className="p-4"><Alert>{describeError(list.error)}</Alert></div>
          : !list.data?.length ? (
            <EmptyState icon={ShieldCheck} title="No policies yet" description="Create a policy, then assign it to endpoints."
              action={can('policies:write') ? <Button size="sm" onClick={() => setCreating(true)}><Plus />Create the first policy</Button> : undefined} />
          ) : (
            <Table>
              <thead><tr><Th>Policy</Th><Th>Category</Th><Th>Configuration</Th><Th>Version</Th><Th>Endpoints</Th><Th>Deployment status</Th><Th>Updated</Th></tr></thead>
              <tbody>{list.data.map((p) => {
                const s = p.deployment_summary
                return (
                  <tr key={p.id} className="cursor-pointer hover:bg-ink-850" onClick={() => nav(`/policies/${p.id}`)}>
                    <Td><Link to={`/policies/${p.id}`} onClick={(e) => e.stopPropagation()} className="text-silver-50 hover:text-emerald-300">{p.name}</Link>
                      {p.description && <div className="max-w-xs truncate text-xs text-silver-500">{p.description}</div>}</Td>
                    <Td className="text-silver-400">{CATEGORY_LABEL[p.category]}</Td>
                    <Td className="text-xs text-silver-400">{summarizeConfig(p.category, p.configuration)}</Td>
                    <Td className="font-mono text-xs">v{p.version}</Td>
                    <Td>{p.assigned_devices}</Td>
                    <Td><div className="flex flex-wrap gap-1">
                      {!!s.applied && <Badge tone="success">{s.applied} applied</Badge>}
                      {!!s.failed && <Badge tone="danger">{s.failed} failed</Badge>}
                      {!!s.needs_attention && <Badge tone="warning">{s.needs_attention} attention</Badge>}
                      {!!((s.pending ?? 0) + (s.in_progress ?? 0)) && <Badge tone="info">{(s.pending ?? 0) + (s.in_progress ?? 0)} pending</Badge>}
                      {!!s.offline && <Badge>{s.offline} offline</Badge>}
                      {!Object.keys(s).length && <span className="text-xs text-silver-600">Not deployed</span>}
                    </div></Td>
                    <Td className="text-silver-400">{relativeTime(p.updated_at)}</Td>
                  </tr>
                )
              })}</tbody>
            </Table>
          )}
      </Card>
      <CreatePolicyDialog open={creating} onOpenChange={setCreating} />
    </div>
  )
}
