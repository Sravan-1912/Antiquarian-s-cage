import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ClipboardCheck } from 'lucide-react'
import { Alert, Card, CardHeader, EmptyState, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { ComplianceCheckDef, ComplianceDeviceRow, ComplianceSummary, Severity } from '@/types/api'
import { relativeTime } from '@/utils/format'
import { SeverityBadge, StateBadge } from './shared'

const AXIS = { stroke: '#5f646b', fontSize: 11, tickLine: false, axisLine: false } as const
const TOOLTIP = { contentStyle: { background: '#0d0e10', border: '1px solid #2b2f34', borderRadius: 6, fontSize: 12, color: '#d8dbde' }, labelStyle: { color: '#9a9ea4' } }

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return <Card className="px-4 py-3.5"><div className="text-xs text-silver-500">{label}</div><div className={`mt-2 text-2xl font-semibold tabular-nums ${tone ?? 'text-silver-50'}`}>{value}</div></Card>
}

function ChecksSettings() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const checks = useQuery({ queryKey: ['compliance', 'checks'], queryFn: () => api.get<ComplianceCheckDef[]>('/compliance/checks') })
  const save = useMutation({
    mutationFn: ({ key, enabled, severity }: { key: string; enabled: boolean; severity: Severity }) => api.put(`/compliance/checks/${key}`, { enabled, severity }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance'] }),
  })
  const editable = can('policies:write')
  return (
    <Card>
      <CardHeader title="Compliance checks" description="Disable checks that do not apply to your fleet (e.g. third-party antivirus) and set severities. Changes apply at the next evaluation." />
      {save.error && <div className="px-4 pt-3"><Alert>{describeError(save.error)}</Alert></div>}
      <Table>
        <thead><tr><Th>Check</Th><Th>Severity</Th><Th>Enabled</Th></tr></thead>
        <tbody>{checks.data?.map((c) => (
          <tr key={c.key}>
            <Td><div className="text-silver-100">{c.name}</div><div className="text-xs text-silver-500">{c.description}</div></Td>
            <Td>{editable ? (
              <Select value={c.severity} aria-label={`Severity for ${c.name}`} onChange={(e) => save.mutate({ key: c.key, enabled: c.enabled, severity: e.target.value as Severity })}>
                {['critical', 'high', 'medium', 'low', 'informational'].map((s) => <option key={s}>{s}</option>)}
              </Select>
            ) : <SeverityBadge s={c.severity} />}</Td>
            <Td><input type="checkbox" aria-label={`Enable ${c.name}`} className="size-4 accent-emerald-500" disabled={!editable} checked={c.enabled}
              onChange={(e) => save.mutate({ key: c.key, enabled: e.target.checked, severity: c.severity })} /></Td>
          </tr>
        ))}</tbody>
      </Table>
    </Card>
  )
}

export function CompliancePage() {
  const nav = useNavigate()
  const summary = useQuery({ queryKey: ['compliance', 'summary'], queryFn: () => api.get<ComplianceSummary>('/compliance/summary'), refetchInterval: 60_000 })
  const devices = useQuery({ queryKey: ['compliance', 'devices'], queryFn: () => api.get<ComplianceDeviceRow[]>('/compliance/devices'), refetchInterval: 60_000 })
  if (summary.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (summary.error) return <Alert>{describeError(summary.error)}</Alert>
  const s = summary.data!
  const short = (iso: string) => new Date(iso + 'T00:00:00').toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  const hasHistory = s.history.some((h) => h.devices > 0)

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Compliance" description="Evaluated from agent-reported evidence after every inventory. Unknown results are never counted as compliant." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Average score" value={s.average_score != null ? `${s.average_score}%` : '—'} />
        <Stat label="Compliant" value={s.states.compliant} tone="text-emerald-300" />
        <Stat label="Non-compliant" value={s.states.non_compliant} tone={s.states.non_compliant ? 'text-red-300' : undefined} />
        <Stat label="Unknown (not compliant)" value={s.states.unknown} tone={s.states.unknown ? 'text-amber-300' : undefined} />
        <Stat label="Evaluated endpoints" value={`${s.evaluated}/${s.devices}`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
        <Card className="xl:col-span-2">
          <CardHeader title="Compliance history" description="Average score of endpoints evaluated each day, last 30 days" />
          <div className="h-60 px-2 py-3">
            {!hasHistory ? <EmptyState icon={ClipboardCheck} title="No evaluations yet" description="Evaluations run when agents upload inventory." /> : (
              <ResponsiveContainer>
                <LineChart data={s.history}>
                  <CartesianGrid stroke="#202327" vertical={false} />
                  <XAxis dataKey="date" tickFormatter={short} {...AXIS} />
                  <YAxis domain={[0, 100]} width={32} {...AXIS} />
                  <Tooltip {...TOOLTIP} labelFormatter={(v) => short(String(v))} />
                  <Line type="monotone" dataKey="average_score" name="Avg score %" stroke="#10b981" strokeWidth={1.75} dot={{ r: 2.5 }} connectNulls />
                  <Line type="monotone" dataKey="non_compliant" name="Non-compliant" stroke="#ef4444" strokeWidth={1.25} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Top failing checks" />
          {!s.failing_checks.length && !s.unknown_checks.length ? <p className="px-4 py-3 text-sm text-silver-500">No failing or unknown checks.</p> : (
            <ul className="divide-y divide-ink-800">
              {s.failing_checks.map((c) => <li key={c.key} className="flex justify-between px-4 py-2 text-sm"><span className="text-silver-100">{c.name}</span><span className="text-red-300">{c.devices} failing</span></li>)}
              {s.unknown_checks.map((c) => <li key={`u-${c.key}`} className="flex justify-between px-4 py-2 text-sm"><span className="text-silver-300">{c.name}</span><span className="text-amber-300">{c.devices} unknown</span></li>)}
            </ul>
          )}
        </Card>
      </div>

      <Card>
        <CardHeader title="Endpoints" />
        {!devices.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No managed endpoints.</p> : (
          <Table>
            <thead><tr><Th>Endpoint</Th><Th>State</Th><Th>Score</Th><Th>Failing</Th><Th>Unknown</Th><Th>Evaluated</Th></tr></thead>
            <tbody>{devices.data.map((d) => (
              <tr key={d.device_id} className="cursor-pointer hover:bg-ink-850" onClick={() => nav(`/endpoints/${d.device_id}#compliance`)}>
                <Td className="text-silver-100">{d.name}</Td><Td><StateBadge state={d.state} /></Td>
                <Td className="tabular-nums">{d.score != null ? `${d.score}%` : '—'}</Td>
                <Td className={d.failed ? 'text-red-300' : ''}>{d.failed ?? '—'}</Td>
                <Td className={d.unknown ? 'text-amber-300' : ''}>{d.unknown ?? '—'}</Td>
                <Td className="text-silver-400">{d.evaluated_at ? relativeTime(d.evaluated_at) : 'never'}</Td>
              </tr>
            ))}</tbody>
          </Table>
        )}
      </Card>
      <ChecksSettings />
    </div>
  )
}
