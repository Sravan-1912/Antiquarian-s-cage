import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ClipboardCheck } from 'lucide-react'
import { Card, CardHeader, EmptyState, Spinner } from '@/components/ui/primitives'
import { api } from '@/services/api'
import type { Deployment, DeviceCompliance } from '@/types/api'
import { relativeTime } from '@/utils/format'
import { DeploymentBadge } from '@/modules/policies/config'
import { ResultBadge, SeverityBadge, StateBadge } from './shared'

export function DeviceComplianceCard({ deviceId }: { deviceId: string }) {
  const q = useQuery({ queryKey: ['device', deviceId, 'compliance'], queryFn: () => api.get<DeviceCompliance>(`/compliance/devices/${deviceId}`), refetchInterval: 30_000 })
  const [open, setOpen] = useState<string | null>(null)
  if (q.isLoading) return <Card><div className="p-4"><Spinner /></div></Card>
  const c = q.data
  if (!c?.evaluation) return <Card><CardHeader title="Compliance" /><EmptyState icon={ClipboardCheck} title="Not evaluated yet" description="Evaluation runs when the agent uploads inventory." /></Card>
  const e = c.evaluation
  return (
    <Card id="compliance">
      <CardHeader title="Compliance" description={`Evaluated ${relativeTime(e.evaluated_at)} · ${e.passed} pass · ${e.failed} fail · ${e.unknown} unknown · ${e.not_applicable} n/a`}
        action={<div className="flex items-center gap-2"><span className="text-lg font-semibold tabular-nums text-silver-50">{e.score}%</span><StateBadge state={c.state} /></div>} />
      <ul className="divide-y divide-ink-800">{c.results.map((r) => (
        <li key={r.key} className="px-4 py-2">
          <button className="flex w-full items-center justify-between gap-3 text-left" onClick={() => setOpen(open === r.key ? null : r.key)}>
            <span className="min-w-0 flex-1 truncate text-sm text-silver-100">{r.name}</span>
            <SeverityBadge s={r.severity} /><ResultBadge r={r.result} />
          </button>
          {open === r.key && (
            <div className="mt-2 space-y-1.5 text-xs">
              {r.remediation && <p className="text-amber-200/90"><span className="text-silver-500">Remediation: </span>{r.remediation}</p>}
              <pre className="overflow-x-auto rounded bg-ink-950 p-2 font-mono text-[11px] text-silver-400">{JSON.stringify(r.evidence, null, 2)}</pre>
            </div>
          )}
        </li>
      ))}</ul>
    </Card>
  )
}

export function DevicePoliciesCard({ deviceId }: { deviceId: string }) {
  const q = useQuery({ queryKey: ['device', deviceId, 'deployments'], queryFn: () => api.get<Deployment[]>(`/deployments?device_id=${deviceId}&limit=20`), refetchInterval: 30_000 })
  return (
    <Card>
      <CardHeader title="Policy deployments" />
      {!q.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No policies deployed to this endpoint.</p> : (
        <ul className="divide-y divide-ink-800">{q.data.map((d) => (
          <li key={d.id} className="flex items-center justify-between gap-3 px-4 py-2">
            <div className="min-w-0"><Link to={`/policies/${d.policy_id}`} className="text-sm text-silver-100 hover:text-emerald-300">{d.policy_name}</Link>
              <span className="ml-1.5 text-xs text-silver-500">v{d.policy_version}{d.action === 'remove' ? ' · rollback' : ''}</span>
              {d.detail && <div className="truncate text-xs text-silver-500" title={d.detail}>{d.detail}</div>}</div>
            <DeploymentBadge status={d.status} />
          </li>
        ))}</ul>
      )}
    </Card>
  )
}
