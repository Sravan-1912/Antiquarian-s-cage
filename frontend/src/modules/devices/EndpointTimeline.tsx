import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, FileCode2, Headset, History, Terminal, Usb } from 'lucide-react'
import { Badge, Card, CardHeader, EmptyState, Spinner } from '@/components/ui/primitives'
import { api } from '@/services/api'
import { formatDateTime, relativeTime } from '@/utils/format'

interface TimelineEntry {
  at: string; category: string; severity: string | null; title: string; detail: string; ref_id: string | null
}

const CAT: Record<string, { label: string; icon: typeof Activity; dot: string }> = {
  lifecycle: { label: 'Lifecycle', icon: History, dot: 'bg-emerald-500/70' },
  alert: { label: 'Alerts', icon: AlertTriangle, dot: 'bg-red-500/80' },
  action: { label: 'Actions', icon: Terminal, dot: 'bg-sky-500/70' },
  remote: { label: 'Sessions', icon: Headset, dot: 'bg-violet-500/70' },
  script: { label: 'Scripts', icon: FileCode2, dot: 'bg-amber-500/70' },
  removable: { label: 'USB', icon: Usb, dot: 'bg-fuchsia-500/70' },
}
const SEV_TONE: Record<string, 'danger' | 'warning' | 'info' | 'neutral'> = {
  critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: 'neutral',
}

export function EndpointTimelineCard({ deviceId }: { deviceId: string }) {
  const q = useQuery({ queryKey: ['device', deviceId, 'timeline'], queryFn: () => api.get<TimelineEntry[]>(`/devices/${deviceId}/timeline`), refetchInterval: 60_000 })
  const all = q.data ?? []
  const [filter, setFilter] = useState<string | null>(null)
  const present = useMemo(() => Array.from(new Set(all.map((e) => e.category))), [all])
  const rows = filter ? all.filter((e) => e.category === filter) : all
  return (
    <Card>
      <CardHeader title="Activity timeline" description="Lifecycle, alerts, remote actions, sessions and script runs — newest first."
        action={present.length > 1 ? (
          <div className="flex flex-wrap gap-1">
            <button onClick={() => setFilter(null)} className={`rounded px-2 py-0.5 text-xs ${filter === null ? 'bg-ink-700 text-silver-100' : 'text-silver-500 hover:text-silver-200'}`}>All</button>
            {present.map((c) => (
              <button key={c} onClick={() => setFilter(c === filter ? null : c)}
                className={`rounded px-2 py-0.5 text-xs ${filter === c ? 'bg-ink-700 text-silver-100' : 'text-silver-500 hover:text-silver-200'}`}>{CAT[c]?.label ?? c}</button>
            ))}
          </div>
        ) : undefined} />
      {q.isLoading ? <div className="grid h-40 place-items-center"><Spinner /></div>
        : rows.length === 0 ? <EmptyState icon={Activity} title="No activity yet" description="Events appear here as the endpoint reports in and operators act on it." />
          : (
            <ol className="max-h-[28rem] overflow-y-auto px-4 py-2">
              {rows.map((e, i) => {
                const meta = CAT[e.category] ?? CAT.lifecycle
                const Icon = meta.icon
                return (
                  <li key={`${e.ref_id ?? e.title}-${i}`} className="relative border-l border-ink-700 py-2 pl-5">
                    <span className={`absolute -left-[4px] top-3.5 size-2 rounded-full ${meta.dot}`} />
                    <div className="flex items-center gap-2">
                      <Icon className="size-3.5 shrink-0 text-silver-500" />
                      <span className="text-[13px] text-silver-100">{e.title}</span>
                      {e.severity && <Badge tone={SEV_TONE[e.severity] ?? 'neutral'}>{e.severity}</Badge>}
                    </div>
                    {e.detail && <div className="mt-0.5 pl-5 text-xs text-silver-400">{e.detail}</div>}
                    <div className="pl-5 text-[11px] text-silver-600" title={formatDateTime(e.at)}>{relativeTime(e.at)}</div>
                  </li>
                )
              })}
            </ol>
          )}
    </Card>
  )
}
