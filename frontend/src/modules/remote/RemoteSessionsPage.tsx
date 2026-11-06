import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Headset } from 'lucide-react'
import { Alert, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { AssistSettings, RemoteSession } from '@/types/api'
import { formatDateTime } from '@/utils/format'
import { SessionStatusBadge, TerminateButton } from './shared'

function SettingsCard() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['assist-settings'], queryFn: () => api.get<AssistSettings>('/settings/remote-assistance') })
  const [draft, setDraft] = useState<AssistSettings | null>(null)
  const save = useMutation({ mutationFn: (s: AssistSettings) => api.put<AssistSettings>('/settings/remote-assistance', s),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['assist-settings'] }); setDraft(null) } })
  const v = draft ?? q.data
  const editable = can('org:settings')
  if (!v) return null
  return (
    <Card>
      <CardHeader title="Remote assistance policy" description="Organisation-wide. Consent is required by default; changes are audited." />
      <div className="space-y-3 p-4">
        {save.error && <Alert>{describeError(save.error)}</Alert>}
        <label className="flex items-center gap-2 text-sm text-silver-200">
          <input type="checkbox" className="size-4 accent-emerald-500" disabled={!editable} checked={v.require_consent} onChange={(e) => setDraft({ ...v, require_consent: e.target.checked })} />
          Require explicit consent from the person at the endpoint
        </label>
        {!v.require_consent && <Alert tone="warning">Without consent, sessions start immediately. The on-screen indicator is still always shown and the user can still end the session.</Alert>}
        <label className="flex items-center gap-2 text-sm text-silver-200">
          <input type="checkbox" className="size-4 accent-emerald-500" disabled={!editable} checked={v.allow_it_support} onChange={(e) => setDraft({ ...v, allow_it_support: e.target.checked })} />
          Allow IT Support to start sessions on endpoints assigned to them
        </label>
        <div className="max-w-xs"><Field label="Maximum session length (minutes)" htmlFor="ms">
          <Input id="ms" type="number" min={5} max={120} disabled={!editable} value={v.max_session_minutes} onChange={(e) => setDraft({ ...v, max_session_minutes: Number(e.target.value) })} />
        </Field></div>
        {editable && draft && <Button size="sm" onClick={() => save.mutate(draft)} loading={save.isPending}>Save policy</Button>}
      </div>
    </Card>
  )
}

export function RemoteSessionsPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [status, setStatus] = useState<'' | 'open' | 'closed'>('')
  const q = useQuery({ queryKey: ['remote-sessions', status], queryFn: () => api.get<RemoteSession[]>(`/remote-sessions${status ? `?status=${status}` : ''}`), refetchInterval: 10_000 })
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Remote sessions" description="Consented remote assistance across all endpoints you can access." />
      <Card>
        <div className="border-b border-ink-700 p-3">
          <Select value={status} onChange={(e) => setStatus(e.target.value as typeof status)} aria-label="Status">
            <option value="">All sessions</option><option value="open">Open</option><option value="closed">Closed</option>
          </Select>
        </div>
        {q.isLoading ? <div className="p-6"><Spinner /></div> : q.error ? <div className="p-4"><Alert>{describeError(q.error)}</Alert></div>
          : !q.data?.length ? <EmptyState icon={Headset} title="No remote sessions" description="Start one from an endpoint's page." /> : (
            <Table>
              <thead><tr><Th>Endpoint</Th><Th>Requested by</Th><Th>Reason</Th><Th>Status</Th><Th>Consent</Th><Th>Started</Th><Th>Ended</Th><Th /></tr></thead>
              <tbody>{q.data.map((x) => (
                <tr key={x.id}>
                  <Td><Link className="text-silver-100 hover:text-emerald-300" to={`/endpoints/${x.device_id}`}>{x.device_name}</Link></Td>
                  <Td className="text-silver-400">{x.requested_by_label}</Td>
                  <Td className="max-w-xs truncate text-silver-400" title={x.reason}>{x.reason}</Td>
                  <Td><SessionStatusBadge s={x.status} /></Td>
                  <Td className="text-xs text-silver-400">{x.require_consent ? (x.consent_decision ?? 'pending') : 'not required'}{x.consent_user ? ` · ${x.consent_user}` : ''}</Td>
                  <Td className="text-silver-400">{formatDateTime(x.started_at)}</Td>
                  <Td className="text-xs text-silver-400">{x.ended_at ? `${formatDateTime(x.ended_at)} · ${x.ended_by?.replace('_', ' ')}` : '—'}</Td>
                  <Td>{can('devices:remote') && !['ended', 'denied', 'expired', 'cancelled', 'failed'].includes(x.status) &&
                    <TerminateButton session={x} onDone={() => qc.invalidateQueries({ queryKey: ['remote-sessions'] })} />}</Td>
                </tr>
              ))}</tbody>
            </Table>
          )}
      </Card>
      <SettingsCard />
    </div>
  )
}
