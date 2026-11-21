import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Globe2, MapPin } from 'lucide-react'
import { Badge, Card, CardHeader, EmptyState, PageHeader, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { api } from '@/services/api'
import { relativeTime } from '@/utils/format'
import { OsmMap, accuracyText, sourceLabel } from '@/modules/devices/EndpointGeoCards'

interface TopSite { domain: string; visits: number; endpoints: number }
interface FleetLocation {
  device_id: string; display_name: string; hostname: string; source: 'wifi' | 'ip' | 'none'
  latitude: number | null; longitude: number | null; accuracy_m: number | null
  city: string | null; country: string | null; resolved_at: string
}

function TopWebsites() {
  const q = useQuery({ queryKey: ['web-activity', 'top-sites'], queryFn: () => api.get<TopSite[]>('/web-activity/top-sites'), refetchInterval: 120_000 })
  const sites = q.data ?? []
  const max = sites.reduce((m, s) => Math.max(m, s.visits), 0) || 1
  return (
    <Card>
      <CardHeader title="Top 10 websites" description="Most-visited domains across all visible endpoints (aggregated visit counts, no full URLs)." />
      {q.isLoading ? <div className="grid h-40 place-items-center"><Spinner /></div>
        : sites.length === 0 ? <EmptyState icon={Globe2} title="No browsing data yet" description="Endpoints report aggregated domain counts on the agent's inventory cycle." />
          : (
            <ol className="space-y-2.5 p-4">
              {sites.map((s, i) => (
                <li key={s.domain}>
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate text-silver-100"><span className="mr-2 tabular-nums text-silver-600">{i + 1}.</span>{s.domain}</span>
                    <span className="flex shrink-0 items-center gap-2 text-silver-400">
                      <Badge tone="neutral">{s.endpoints} endpoint{s.endpoints === 1 ? '' : 's'}</Badge>
                      <span className="tabular-nums">{s.visits.toLocaleString()} visits</span>
                    </span>
                  </div>
                  <div className="mt-1 h-2 overflow-hidden rounded bg-ink-700"><div className="h-full rounded bg-[color:var(--cage-accent)]" style={{ width: `${Math.round((s.visits / max) * 100)}%` }} /></div>
                </li>
              ))}
            </ol>
          )}
    </Card>
  )
}

function FleetLocations() {
  const q = useQuery({ queryKey: ['geo', 'locations'], queryFn: () => api.get<FleetLocation[]>('/geo/locations'), refetchInterval: 60_000 })
  const rows = q.data ?? []
  const [sel, setSel] = useState(0)
  const active = rows[sel]
  return (
    <Card>
      <CardHeader title="Endpoint locations" description="Approximate positions (Wi-Fi or IP). Select a row to focus the map; accuracy radius is shown per endpoint." />
      {q.isLoading ? <div className="grid h-40 place-items-center"><Spinner /></div>
        : rows.length === 0 ? <EmptyState icon={MapPin} title="No located endpoints yet" description="Positions appear once agents report on their inventory cycle." />
          : (
            <div className="space-y-3 p-4">
              {active && active.latitude != null && active.longitude != null && (
                <OsmMap lat={active.latitude} lon={active.longitude} accuracyM={active.accuracy_m} className="h-64" />
              )}
              <div className="max-h-72 overflow-y-auto">
                <Table>
                  <thead><tr><Th>Endpoint</Th><Th>Place</Th><Th>Source</Th><Th>Accuracy</Th><Th>Updated</Th></tr></thead>
                  <tbody>
                    {rows.map((r, i) => (
                      <tr key={r.device_id} onClick={() => setSel(i)}
                        className={`cursor-pointer ${i === sel ? 'bg-ink-800' : 'hover:bg-ink-850'}`}>
                        <Td><Link to={`/endpoints/${r.device_id}`} className="text-[color:var(--cage-accent)] hover:underline" onClick={(e) => e.stopPropagation()}>{r.display_name}</Link>
                          <div className="font-mono text-[11px] text-silver-600">{r.hostname}</div></Td>
                        <Td className="text-silver-200">{[r.city, r.country].filter(Boolean).join(', ') || '—'}</Td>
                        <Td><Badge tone={r.source === 'wifi' ? 'success' : 'info'}>{sourceLabel(r.source)}</Badge></Td>
                        <Td className="text-silver-400">{accuracyText(r.accuracy_m)}</Td>
                        <Td className="text-silver-500">{relativeTime(r.resolved_at)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </div>
          )}
    </Card>
  )
}

export function InsightsPage() {
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Web & locations" description="Fleet-wide browsing and geolocation insights. Locations are approximate and labelled with their source and accuracy — never presented as exact." />
      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <TopWebsites />
        <FleetLocations />
      </div>
    </div>
  )
}
