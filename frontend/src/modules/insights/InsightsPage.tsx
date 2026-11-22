import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Globe2, MapPin, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import { relativeTime } from '@/utils/format'
import { OsmMap, accuracyText, sourceLabel } from '@/modules/devices/EndpointGeoCards'

interface TopSite { domain: string; visits: number; endpoints: number }
interface FleetLocation {
  device_id: string; display_name: string; hostname: string; source: 'wifi' | 'ip' | 'none'
  latitude: number | null; longitude: number | null; accuracy_m: number | null
  city: string | null; country: string | null; resolved_at: string
}

interface PatchSummary {
  devices: number; reporting: number; up_to_date: number; with_critical: number
  reboot_pending: number; pending_total: number; pending_critical: number; pending_important: number
}

function PatchScorecard() {
  const q = useQuery({ queryKey: ['patch', 'summary'], queryFn: () => api.get<PatchSummary>('/patch/summary'), refetchInterval: 300_000 })
  const d = q.data
  const stats = [
    { label: 'Up to date', value: d?.up_to_date ?? 0, tone: 'text-emerald-300' },
    { label: 'With critical', value: d?.with_critical ?? 0, tone: 'text-red-300' },
    { label: 'Reboot pending', value: d?.reboot_pending ?? 0, tone: 'text-amber-300' },
    { label: 'Not reporting', value: Math.max(0, (d?.devices ?? 0) - (d?.reporting ?? 0)), tone: 'text-silver-300' },
  ]
  return (
    <Card>
      <CardHeader title="Patch scorecard" description="OS update posture across all visible endpoints. Reported on the agent's inventory cycle — endpoints that haven't reported are counted as not reporting." />
      {q.isLoading ? <div className="grid h-40 place-items-center"><Spinner /></div>
        : (d?.devices ?? 0) === 0 ? <EmptyState icon={ShieldCheck} title="No endpoints yet" description="Enrol endpoints to see their patch posture here." />
          : (
            <div className="space-y-4 p-4">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                {stats.map((s) => (
                  <div key={s.label} className="rounded-lg border border-ink-700 bg-ink-800/40 p-3">
                    <div className={`text-2xl font-semibold tabular-nums ${s.tone}`}>{s.value}</div>
                    <div className="mt-0.5 text-xs text-silver-500">{s.label}</div>
                  </div>
                ))}
              </div>
              <dl className="grid grid-cols-[1fr_auto] gap-y-1.5 text-sm">
                <dt className="text-silver-500">Reporting endpoints</dt><dd className="tabular-nums text-silver-200">{d!.reporting} / {d!.devices}</dd>
                <dt className="text-silver-500">Pending updates (total)</dt><dd className="tabular-nums text-silver-200">{d!.pending_total.toLocaleString()}</dd>
                <dt className="text-silver-500">Critical / important</dt><dd className="tabular-nums text-silver-200">{d!.pending_critical.toLocaleString()} / {d!.pending_important.toLocaleString()}</dd>
              </dl>
            </div>
          )}
    </Card>
  )
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

interface GeoPolicy { geofence_enabled: boolean; allowed_countries: string[]; on_violation: 'alert' | 'isolate'; impossible_travel: boolean }

function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} disabled={disabled} onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition disabled:opacity-50 ${checked ? 'bg-[color:var(--cage-accent)]' : 'bg-ink-600'}`}>
      <span className={`inline-block size-4 rounded-full bg-white transition ${checked ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
  )
}

function GeoSecurityCard() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const editable = can('devices:manage')
  const q = useQuery({ queryKey: ['geo', 'policy'], queryFn: () => api.get<GeoPolicy>('/geo/policy') })
  const [form, setForm] = useState<GeoPolicy>({ geofence_enabled: false, allowed_countries: [], on_violation: 'alert', impossible_travel: false })
  const [countries, setCountries] = useState('')
  useEffect(() => { if (q.data) { setForm(q.data); setCountries(q.data.allowed_countries.join(', ')) } }, [q.data])

  const save = useMutation({
    mutationFn: () => api.put<GeoPolicy>('/geo/policy', { ...form, allowed_countries: countries.split(',').map((c) => c.trim()).filter(Boolean) }),
    onSuccess: (d) => { qc.setQueryData(['geo', 'policy'], d); setCountries(d.allowed_countries.join(', ')) },
  })

  return (
    <Card>
      <CardHeader title="Location security" description="Geo-fencing and impossible-travel detection. Locations are approximate (Wi-Fi/IP), so keep thresholds conservative — isolate only when you're sure." />
      {q.isLoading ? <div className="grid h-32 place-items-center"><Spinner /></div> : (
        <div className="space-y-4 p-4">
          {save.error && <Alert>{describeError(save.error)}</Alert>}
          <div className="flex items-center justify-between gap-3">
            <div><div className="text-sm font-medium text-silver-100">Impossible-travel detection</div>
              <div className="text-xs text-silver-500">Raise a high-severity alert when an endpoint's location jumps faster than any aircraft (&gt;500 km and &gt;900 km/h between reports).</div></div>
            <Toggle checked={form.impossible_travel} disabled={!editable} onChange={(v) => setForm({ ...form, impossible_travel: v })} />
          </div>
          <div className="flex items-center justify-between gap-3 border-t border-ink-800 pt-4">
            <div><div className="text-sm font-medium text-silver-100">Geo-fencing</div>
              <div className="text-xs text-silver-500">Alert when an endpoint is located outside the allowed countries.</div></div>
            <Toggle checked={form.geofence_enabled} disabled={!editable} onChange={(v) => setForm({ ...form, geofence_enabled: v })} />
          </div>
          {form.geofence_enabled && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Allowed countries (comma-separated)" htmlFor="gc">
                <Input id="gc" disabled={!editable} value={countries} placeholder="India, United States"
                  onChange={(e) => setCountries(e.target.value)} />
              </Field>
              <Field label="On violation" htmlFor="gv">
                <Select id="gv" className="w-full" disabled={!editable} value={form.on_violation}
                  onChange={(e) => setForm({ ...form, on_violation: e.target.value as 'alert' | 'isolate' })}>
                  <option value="alert">Alert only</option>
                  <option value="isolate">Alert + network-isolate the endpoint</option>
                </Select>
              </Field>
              {form.on_violation === 'isolate' && (
                <div className="sm:col-span-2 flex items-start gap-2 rounded-md border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
                  <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />Auto-isolation cuts the endpoint off the network. IP/Wi-Fi location is approximate (VPNs, mobile data), so use country names exactly as resolved and expect occasional false positives.
                </div>
              )}
            </div>
          )}
          {editable && (
            <div className="flex justify-end border-t border-ink-800 pt-3">
              <Button size="sm" loading={save.isPending} onClick={() => save.mutate()}>Save</Button>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

export function InsightsPage() {
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Web & locations" description="Fleet-wide browsing and geolocation insights. Locations are approximate and labelled with their source and accuracy — never presented as exact." />
      <GeoSecurityCard />
      <PatchScorecard />
      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <TopWebsites />
        <FleetLocations />
      </div>
    </div>
  )
}
