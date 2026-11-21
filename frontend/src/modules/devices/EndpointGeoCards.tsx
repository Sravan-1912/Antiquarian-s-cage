import { useQuery } from '@tanstack/react-query'
import { Globe2, MapPin } from 'lucide-react'
import { Badge, Card, CardHeader, EmptyState } from '@/components/ui/primitives'
import { api } from '@/services/api'
import { relativeTime } from '@/utils/format'

export interface DeviceLocation {
  source: 'wifi' | 'ip' | 'none'
  latitude: number | null
  longitude: number | null
  accuracy_m: number | null
  city: string | null
  region: string | null
  country: string | null
  ip: string | null
  ap_count: number
  resolved_at: string
}
export interface TopSite { domain: string; visits: number }

export function sourceLabel(s: string): string {
  return s === 'wifi' ? 'Wi-Fi positioning' : s === 'ip' ? 'IP-based (approximate)' : 'Unknown'
}
export function accuracyText(m: number | null): string {
  if (m == null) return 'accuracy unknown'
  return m >= 1000 ? `±${(m / 1000).toFixed(m >= 10000 ? 0 : 1)} km` : `±${m} m`
}

/** Keyless OpenStreetMap embed centred on a coordinate, with a marker. */
export function OsmMap({ lat, lon, accuracyM, className = 'h-56' }: { lat: number; lon: number; accuracyM: number | null; className?: string }) {
  // Widen the viewport with the accuracy radius so the marker isn't shown more precise than it is.
  const d = Math.max(0.004, Math.min(0.5, (accuracyM ?? 500) / 111_000))
  const bbox = `${lon - d},${lat - d},${lon + d},${lat + d}`
  const src = `https://www.openstreetmap.org/export/embed.html?bbox=${encodeURIComponent(bbox)}&layer=mapnik&marker=${lat},${lon}`
  return <iframe title="Endpoint location map" src={src} className={`w-full rounded-md border border-ink-700 ${className}`} loading="lazy" referrerPolicy="no-referrer" />
}

export function EndpointLocationCard({ deviceId }: { deviceId: string }) {
  const q = useQuery({ queryKey: ['device', deviceId, 'location'], queryFn: () => api.get<DeviceLocation | null>(`/devices/${deviceId}/location`), refetchInterval: 60_000 })
  const loc = q.data
  const hasCoords = loc && loc.latitude != null && loc.longitude != null
  const place = loc ? [loc.city, loc.region, loc.country].filter(Boolean).join(', ') : ''
  return (
    <Card>
      <CardHeader title="Location" description="Approximate — resolved from Wi-Fi or IP. Never exact; the accuracy radius is shown." />
      {!hasCoords ? (
        <EmptyState icon={MapPin} title="No location yet" description="The agent reports a location on its inventory cycle. Desktops on Ethernet with no API key fall back to IP-based city location." />
      ) : (
        <div className="space-y-3 p-4">
          <OsmMap lat={loc!.latitude!} lon={loc!.longitude!} accuracyM={loc!.accuracy_m} />
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge tone={loc!.source === 'wifi' ? 'success' : 'info'}>{sourceLabel(loc!.source)}</Badge>
            <Badge tone="neutral">{accuracyText(loc!.accuracy_m)}</Badge>
            {loc!.source === 'wifi' && loc!.ap_count > 0 && <span className="text-silver-500">{loc!.ap_count} Wi-Fi APs</span>}
            <span className="ml-auto text-silver-600">updated {relativeTime(loc!.resolved_at)}</span>
          </div>
          <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 text-sm">
            <dt className="text-silver-500">Place</dt><dd className="text-silver-100">{place || '—'}</dd>
            <dt className="text-silver-500">Coordinates</dt><dd className="font-mono text-xs text-silver-200">{loc!.latitude!.toFixed(5)}, {loc!.longitude!.toFixed(5)}</dd>
            <dt className="text-silver-500">Public IP</dt><dd className="font-mono text-xs text-silver-200">{loc!.ip ?? '—'}</dd>
          </dl>
        </div>
      )}
    </Card>
  )
}

export function EndpointTopSitesCard({ deviceId }: { deviceId: string }) {
  const q = useQuery({ queryKey: ['device', deviceId, 'top-sites'], queryFn: () => api.get<TopSite[]>(`/devices/${deviceId}/top-sites`), refetchInterval: 120_000 })
  const sites = q.data ?? []
  const max = sites.reduce((m, s) => Math.max(m, s.visits), 0) || 1
  return (
    <Card>
      <CardHeader title="Top websites" description="Most-visited domains from this endpoint's browsers (aggregated counts, no full URLs)." />
      {sites.length === 0 ? (
        <EmptyState icon={Globe2} title="No browsing data yet" description="Reported on the agent's inventory cycle from Chrome, Edge, Brave and Firefox history." />
      ) : (
        <ul className="space-y-2 p-4">
          {sites.map((s, idx) => (
            <li key={s.domain}>
              <div className="flex items-center justify-between gap-3 text-sm">
                <span className="truncate text-silver-100"><span className="mr-2 tabular-nums text-silver-600">{idx + 1}.</span>{s.domain}</span>
                <span className="shrink-0 tabular-nums text-silver-400">{s.visits.toLocaleString()}</span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded bg-ink-700"><div className="h-full rounded bg-[color:var(--cage-accent)]" style={{ width: `${Math.round((s.visits / max) * 100)}%` }} /></div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
