import { Link } from 'react-router-dom'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { Laptop, ScrollText, ShieldAlert, ShieldCheck, Users } from 'lucide-react'
import type { AlertDash, DashboardSummary, EndpointSummary, ModuleStatus, PolicyDash } from '@/types/api'

const available = <T extends { available: true }>(m: ModuleStatus | T): m is T => (m as T).available === true

function bytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`
}
const pct = (a: number, b: number) => (b ? Math.round((100 * a) / b) : 0)

/** Health chip: green only when there are no open critical/high alerts and no non-compliant managed endpoints. */
export function HealthChip({ d }: { d: DashboardSummary }) {
  const al = available<AlertDash>(d.alerts) ? d.alerts : null
  const comp = available(d.compliance) ? d.compliance : null
  const urgent = al ? al.open_by_severity.critical + al.open_by_severity.high : 0
  const noncompliant = comp ? comp.non_compliant : 0
  const ok = al != null && urgent === 0 && noncompliant === 0
  const text = !al ? 'Alert status restricted' : ok ? 'All checks passing'
    : urgent ? `${urgent} urgent alert${urgent === 1 ? '' : 's'}` : `${noncompliant} endpoint${noncompliant === 1 ? '' : 's'} non-compliant`
  return (
    <Link to={ok ? '/compliance' : urgent ? '/alerts' : '/compliance'}
      className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] transition-colors ${ok
        ? 'border-emerald-600/50 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/40'
        : 'border-amber-600/50 bg-amber-950/30 text-amber-300 hover:bg-amber-900/30'}`}>
      {ok ? <ShieldCheck className="size-4" /> : <ShieldAlert className="size-4" />}{text}
    </Link>
  )
}

function StatCard({ icon: Icon, value, label, ratio, ratioLabel, foot, to, accent = 'emerald' }: {
  icon: React.ComponentType<{ className?: string }>; value: number; label: string; ratio: number; ratioLabel: string
  foot: React.ReactNode; to: string; accent?: 'emerald' | 'red'
}) {
  const tile = accent === 'red' ? 'border-red-500/40 bg-red-950/30 text-red-400' : 'border-emerald-600/40 bg-emerald-950/40 text-emerald-400'
  return (
    <Link to={to} className="group rounded-xl border border-ink-700 bg-ink-900/70 p-5 transition-colors hover:border-emerald-700/60">
      <div className="flex items-start justify-between">
        <div className={`grid size-10 place-items-center rounded-lg border ${tile}`}><Icon className="size-5" /></div>
        <span className="text-sm font-semibold text-emerald-400">{ratio}% {ratioLabel}</span>
      </div>
      <div className="mt-3 text-4xl font-bold tabular-nums tracking-tight text-silver-50">{value}</div>
      <div className="mt-1 text-xs font-semibold uppercase tracking-[0.14em] text-silver-300">{label}</div>
      <div className="mt-4 border-t border-ink-700 pt-3 text-sm">{foot}</div>
    </Link>
  )
}

function Ring({ data, center }: { data: { name: string; value: number; color: string }[]; center?: React.ReactNode }) {
  const shown = data.filter((x) => x.value > 0)
  return (
    <div className="relative h-48">
      <ResponsiveContainer>
        <PieChart>
          <Pie data={shown.length ? shown : [{ name: 'none', value: 1, color: '#202327' }]} dataKey="value" nameKey="name"
            innerRadius="72%" outerRadius="92%" paddingAngle={shown.length > 1 ? 2 : 0} stroke="none" startAngle={90} endAngle={-270}>
            {(shown.length ? shown : [{ color: '#202327' }]).map((s, i) => <Cell key={i} fill={s.color} />)}
          </Pie>
          {shown.length > 0 && <Tooltip contentStyle={{ background: '#0d0e10', border: '1px solid #2b2f34', borderRadius: 6, fontSize: 12 }} itemStyle={{ color: '#d8dbde' }} />}
        </PieChart>
      </ResponsiveContainer>
      {center && <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">{center}</div>}
    </div>
  )
}

function Legend({ items }: { items: { name: string; value: number | string; color: string }[] }) {
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
      {items.map((i) => (
        <div key={i.name} className="flex items-center gap-2 text-silver-300">
          <span className="size-2.5 rounded-full" style={{ background: i.color }} />{i.name} <span className="ml-auto font-semibold tabular-nums text-silver-50">{i.value}</span>
        </div>
      ))}
    </div>
  )
}

const PLATFORM_COLORS: Record<string, string> = { Windows: '#38bdf8', macOS: '#a78bfa', Linux: '#f59e0b', Unknown: '#5f646b' }

export function FleetOverview({ d }: { d: DashboardSummary }) {
  const e = available<EndpointSummary>(d.endpoints) ? d.endpoints : null
  const p = available<PolicyDash>(d.policies) ? d.policies : null
  const users = d.administrators.active + d.employees.active
  const adminsOnline = d.administrators.online
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-3">
        <StatCard icon={Users} value={d.administrators.active} label="Console users" to="/administrators"
          ratio={pct(adminsOnline, d.administrators.active)} ratioLabel="online"
          foot={<><span className="text-emerald-400">Online: {adminsOnline}</span> <span className="font-semibold text-silver-200">Offline: {d.administrators.active - adminsOnline}</span>
            <span className="block text-xs text-silver-600">{users} people incl. {d.employees.active} active employee{d.employees.active === 1 ? "" : "s"}</span></>} />
        {e ? (
          <StatCard icon={Laptop} value={e.enrolled} label="Total devices" to="/endpoints" ratio={pct(e.online, e.enrolled)} ratioLabel="online"
            foot={<><span className="text-emerald-400">Online: {e.online}</span> <span className="font-semibold text-silver-200">Offline: {e.offline + e.never_reported}</span></>} />
        ) : <RestrictedCard label="Total devices" />}
        {p ? (
          <StatCard icon={ScrollText} value={p.total_policies} label="Total policies" to="/policies" accent="red"
            ratio={pct(p.active_policies, p.total_policies)} ratioLabel="active"
            foot={<><span className="text-emerald-400">Active: {p.active_policies}</span> <span className="font-semibold text-silver-200">Inactive: {p.inactive_policies}</span></>} />
        ) : <RestrictedCard label="Total policies" />}
      </div>

      {e && (
        <div>
          <h2 className="mb-3 text-lg font-semibold text-silver-50">Fleet analytics</h2>
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="rounded-xl border border-ink-700 bg-ink-900/70 p-5">
              <h3 className="font-semibold text-silver-100">Total devices by platform</h3>
              <Ring data={e.platforms.map((x) => ({ name: x.platform, value: x.count, color: PLATFORM_COLORS[x.platform] ?? '#94a3b8' }))}
                center={<div><div className="text-3xl font-bold text-silver-50">{e.enrolled}</div><div className="text-xs text-silver-500">devices</div></div>} />
              <Legend items={e.platforms.map((x) => ({ name: x.platform, value: x.count, color: PLATFORM_COLORS[x.platform] ?? '#94a3b8' }))} />
            </div>
            <div className="rounded-xl border border-ink-700 bg-ink-900/70 p-5">
              <h3 className="font-semibold text-silver-100">Last contact time</h3>
              {(() => {
                const lc = e.last_contact
                const items = [
                  { name: 'Online now', value: lc.online, color: '#22c55e' }, { name: 'Under 1 hour', value: lc.under_1h, color: '#86efac' },
                  { name: '1 to 24 hours', value: lc['1h_24h'], color: '#38bdf8' }, { name: '1 to 7 days', value: lc['1d_7d'], color: '#f59e0b' },
                  { name: 'Over 7 days', value: lc.over_7d, color: '#ef4444' }, { name: 'Never', value: lc.never, color: '#5f646b' },
                ]
                return <><Ring data={items} center={<div><div className="text-3xl font-bold text-emerald-400">{pct(lc.online, e.enrolled)}%</div><div className="text-xs text-silver-500">online now</div></div>} />
                  <Legend items={items.filter((i) => i.value > 0 || ['Online now', 'Under 1 hour', '1 to 24 hours', '1 to 7 days'].includes(i.name))} /></>
              })()}
            </div>
            <NetworkCard e={e} />
          </div>
        </div>
      )}
    </div>
  )
}

function NetworkCard({ e }: { e: EndpointSummary }) {
  const n = e.network
  const total = n.bytes_received + n.bytes_sent
  const recvShare = total ? (100 * n.bytes_received) / total : 0
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-900/70 p-5">
      <h3 className="font-semibold text-silver-100">Network usage</h3>
      <p className="text-sm text-silver-500">Whole fleet, last {n.window_hours} hours. Per device on each endpoint page.</p>
      {n.devices_reporting === 0 ? (
        <p className="mt-6 text-sm text-silver-400">No traffic data yet. Agents 0.5.0+ report network counters with each heartbeat; usage appears after two heartbeats.</p>
      ) : (
        <>
          <div className="mt-4 text-4xl font-bold tabular-nums text-emerald-400">{bytes(total)}</div>
          <div className="text-sm text-silver-400">across {n.devices_reporting} device{n.devices_reporting === 1 ? '' : 's'}, last {n.window_hours} hours</div>
          <div className="mt-4 flex h-2 overflow-hidden rounded-full bg-ink-700" aria-hidden>
            <div className="bg-emerald-500" style={{ width: `${recvShare}%` }} />
            <div className="bg-sky-500" style={{ width: `${100 - recvShare}%` }} />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
            <div><span className="inline-flex items-center gap-1.5 text-silver-300"><span className="size-2 rounded-full bg-emerald-500" />Received</span><div className="text-lg font-semibold text-silver-50">{bytes(n.bytes_received)}</div></div>
            <div><span className="inline-flex items-center gap-1.5 text-silver-300"><span className="size-2 rounded-full bg-sky-500" />Sent</span><div className="text-lg font-semibold text-silver-50">{bytes(n.bytes_sent)}</div></div>
            <div className="rounded-lg bg-ink-800 px-3 py-2"><div className="text-xs text-silver-500">Avg received</div><div className="font-semibold text-silver-100">{bytes(n.avg_received)}</div></div>
            <div className="rounded-lg bg-ink-800 px-3 py-2"><div className="text-xs text-silver-500">Avg sent</div><div className="font-semibold text-silver-100">{bytes(n.avg_sent)}</div></div>
          </div>
        </>
      )}
    </div>
  )
}

function RestrictedCard({ label }: { label: string }) {
  return (
    <div className="rounded-xl border border-dashed border-ink-700 p-5 text-sm text-silver-500">
      <div className="text-xs font-semibold uppercase tracking-[0.14em] text-silver-400">{label}</div>
      Not visible with your role.
    </div>
  )
}
