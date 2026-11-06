import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { Activity, KeyRound, Laptop, RefreshCw, ShieldAlert, ShieldCheck, UserCheck, UserMinus, Users } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, PageHeader, Spinner, statusTone } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'
import type { ComplianceDash, DashboardSummary, EndpointSummary, ModuleStatus, PolicyDash } from '@/types/api'
import { formatDateTime, humanizeAction, relativeTime } from '@/utils/format'

const GRID = '#202327'
const AXIS = { stroke: '#5f646b', fontSize: 11, tickLine: false, axisLine: false } as const
const TOOLTIP = {
  contentStyle: { background: '#0d0e10', border: '1px solid #2b2f34', borderRadius: 6, fontSize: 12, color: '#d8dbde' },
  labelStyle: { color: '#9a9ea4' },
  cursor: { fill: 'rgba(255,255,255,0.03)' },
}
const STATUS_COLORS = ['#10b981', '#64748b', '#f59e0b', '#ef4444']

function Kpi({ label, value, icon: Icon, hint, tone }: { label: string; value: number | string; icon: React.ComponentType<{ className?: string }>; hint?: string; tone?: 'warn' }) {
  return (
    <Card className="px-4 py-3.5">
      <div className="flex items-center justify-between">
        <span className="text-xs text-silver-500">{label}</span>
        <Icon className={tone === 'warn' ? 'size-4 text-amber-400' : 'size-4 text-silver-600'} />
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums tracking-tight text-silver-50">{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-silver-600">{hint}</div>}
    </Card>
  )
}

function Pending({ m, icon }: { m: ModuleStatus; icon: React.ComponentType<{ className?: string }> }) {
  return (
    <Card className="px-4 py-3.5">
      <EmptyState icon={icon} title={`${m.module} not deployed`} description={`Metrics appear once Phase ${m.phase} is live and reporting real data. No placeholder values are shown.`} />
    </Card>
  )
}

const CONN_COLORS = { Online: '#10b981', Offline: '#ef4444', 'Never reported': '#5f646b' } as const
const OS_COLORS = ['#34d399', '#38bdf8', '#a78bfa', '#f59e0b', '#94a3b8', '#f472b6']

function EndpointsSection({ e, short }: { e: EndpointSummary; short: (iso: string) => string }) {
  const conn = [
    { name: 'Online', value: e.online }, { name: 'Offline', value: e.offline }, { name: 'Never reported', value: e.never_reported },
  ].filter((x) => x.value > 0) as { name: keyof typeof CONN_COLORS; value: number }[]
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="Managed endpoints" value={e.enrolled} icon={Laptop} hint="Active + suspended" />
        <Kpi label="Online" value={e.online} icon={Activity} hint={`Heartbeat within ${Math.round(e.offline_threshold_seconds / 60)} min`} />
        <Kpi label="Offline" value={e.offline + e.never_reported} icon={ShieldAlert} tone={e.offline ? 'warn' : undefined} hint={e.never_reported ? `${e.never_reported} never reported` : undefined} />
        <Kpi label="Suspended" value={e.suspended} icon={UserMinus} tone={e.suspended ? 'warn' : undefined} hint={`${e.revoked} revoked · ${e.unenrolled} unenrolled`} />
      </div>
      <div className="grid gap-3 xl:grid-cols-3">
        <Card>
          <CardHeader title="Enrollment over time" description="Endpoints enrolled per day, last 14 days" />
          <div className="h-56 px-2 py-3">
            <ResponsiveContainer>
              <BarChart data={e.enrollments_by_day}>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="date" tickFormatter={short} {...AXIS} />
                <YAxis allowDecimals={false} width={28} {...AXIS} />
                <Tooltip {...TOOLTIP} labelFormatter={(v) => short(String(v))} />
                <Bar dataKey="count" name="Enrolled" fill="#38bdf8" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card>
          <CardHeader title="Online / offline" description="From authenticated heartbeats only" />
          <div className="h-56 px-2 py-3">
            {conn.length === 0 ? <EmptyState icon={Laptop} title="No managed endpoints" action={<Button asChild size="sm" variant="secondary"><Link to="/endpoints">Enrol endpoints</Link></Button>} /> : (
              <div className="flex h-full items-center">
                <ResponsiveContainer width="55%">
                  <PieChart><Pie data={conn} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="85%" paddingAngle={2} stroke="none">
                    {conn.map((c) => <Cell key={c.name} fill={CONN_COLORS[c.name]} />)}</Pie><Tooltip {...TOOLTIP} /></PieChart>
                </ResponsiveContainer>
                <ul className="space-y-2 text-xs">{conn.map((c) => (
                  <li key={c.name} className="flex items-center gap-2"><span className="size-2 rounded-sm" style={{ background: CONN_COLORS[c.name] }} />
                    <span className="text-silver-400">{c.name}</span><span className="ml-auto pl-3 tabular-nums text-silver-100">{c.value}</span></li>))}</ul>
              </div>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Operating systems" description="As reported by agents" />
          <div className="h-56 px-2 py-3">
            {e.os_distribution.length === 0 ? <EmptyState icon={Laptop} title="No OS data yet" /> : (
              <ResponsiveContainer>
                <BarChart data={e.os_distribution} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid stroke={GRID} horizontal={false} />
                  <XAxis type="number" allowDecimals={false} {...AXIS} />
                  <YAxis type="category" dataKey="os" width={150} {...AXIS} tickFormatter={(v: string) => v.replace('Microsoft ', '')} />
                  <Tooltip {...TOOLTIP} />
                  <Bar dataKey="count" name="Endpoints" barSize={14} radius={[0, 3, 3, 0]}>
                    {e.os_distribution.map((o, i) => <Cell key={o.os} fill={OS_COLORS[i % OS_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

const COMP_COLORS = { Compliant: '#10b981', 'Non-compliant': '#ef4444', 'Unknown (not compliant)': '#f59e0b' } as const
const DEP_COLORS: Record<string, string> = { applied: '#10b981', failed: '#ef4444', needs_attention: '#f59e0b', pending: '#38bdf8', in_progress: '#38bdf8', offline: '#64748b', revoked: '#5f646b' }

function SecuritySection({ c, p, short }: { c: ComplianceDash | ModuleStatus; p: PolicyDash | ModuleStatus; short: (iso: string) => string }) {
  const comp = c.available ? ([
    { name: 'Compliant', value: c.compliant }, { name: 'Non-compliant', value: c.non_compliant }, { name: 'Unknown (not compliant)', value: c.unknown },
  ] as const).filter((x) => x.value > 0) : []
  const deps = p.available ? Object.entries(p.by_status).map(([k, v]) => ({ status: k.replace('_', ' '), key: k, count: v ?? 0 })) : []
  const trend = c.available ? c.trend : []
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {c.available ? <>
          <Kpi label="Compliant endpoints" value={c.compliant} icon={ShieldCheck} />
          <Kpi label="Non-compliant" value={c.non_compliant} icon={ShieldAlert} tone={c.non_compliant ? 'warn' : undefined} />
          <Kpi label="Unknown (not compliant)" value={c.unknown} icon={ShieldAlert} tone={c.unknown ? 'warn' : undefined} hint="Evidence missing or undeterminable" />
        </> : <div className="col-span-3"><Pending m={c} icon={ShieldCheck} /></div>}
        {p.available ? <>
          <Kpi label="Pending deployments" value={p.pending} icon={RefreshCw} hint={`${p.active_policies} active policies`} />
          <Kpi label="Deployment success" value={p.success_rate != null ? `${p.success_rate}%` : '—'} icon={Activity} hint="Last 30 days" />
        </> : <div className="col-span-2"><Pending m={p} icon={ShieldCheck} /></div>}
      </div>
      <div className="grid gap-3 xl:grid-cols-3 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Compliance distribution" />
          <div className="h-56 px-2 py-3">
            {!comp.length ? <EmptyState icon={ShieldCheck} title="No evaluations yet" /> : (
              <div className="flex h-full items-center">
                <ResponsiveContainer width="55%"><PieChart><Pie data={[...comp]} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="85%" paddingAngle={2} stroke="none">
                  {comp.map((x) => <Cell key={x.name} fill={COMP_COLORS[x.name]} />)}</Pie><Tooltip {...TOOLTIP} /></PieChart></ResponsiveContainer>
                <ul className="space-y-2 text-xs">{comp.map((x) => (
                  <li key={x.name} className="flex items-center gap-2"><span className="size-2 rounded-sm" style={{ background: COMP_COLORS[x.name] }} />
                    <span className="text-silver-400">{x.name}</span><span className="ml-auto pl-3 tabular-nums text-silver-100">{x.value}</span></li>))}</ul>
              </div>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Policy deployment outcomes" description="Last 30 days" />
          <div className="h-56 px-2 py-3">
            {!deps.length ? <EmptyState icon={RefreshCw} title="No deployments yet" /> : (
              <ResponsiveContainer>
                <BarChart data={deps}>
                  <CartesianGrid stroke={GRID} vertical={false} />
                  <XAxis dataKey="status" {...AXIS} />
                  <YAxis allowDecimals={false} width={28} {...AXIS} />
                  <Tooltip {...TOOLTIP} />
                  <Bar dataKey="count" name="Deployments" radius={[3, 3, 0, 0]}>{deps.map((x) => <Cell key={x.key} fill={DEP_COLORS[x.key] ?? '#94a3b8'} />)}</Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Security trend" description="Average compliance score per day, last 14 days" />
          <div className="h-56 px-2 py-3">
            {!trend.some((t) => t.average_score != null) ? <EmptyState icon={Activity} title="No trend data yet" /> : (
              <ResponsiveContainer>
                <LineChart data={trend}>
                  <CartesianGrid stroke={GRID} vertical={false} />
                  <XAxis dataKey="date" tickFormatter={short} {...AXIS} />
                  <YAxis domain={[0, 100]} width={30} {...AXIS} />
                  <Tooltip {...TOOLTIP} labelFormatter={(v) => short(String(v))} />
                  <Line type="monotone" dataKey="average_score" name="Avg score %" stroke="#10b981" strokeWidth={1.75} dot={{ r: 2 }} connectNulls />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

interface AlertsDash { available: true; open_total: number; unassigned: number; open_by_severity: Record<string, number>; detected_by_day: { date: string; count: number }[] }
const SEV_COLORS: Record<string, string> = { critical: '#dc2626', high: '#f97316', medium: '#f59e0b', low: '#38bdf8', informational: '#64748b' }

function AlertsSection({ a, short }: { a: AlertsDash; short: (iso: string) => string }) {
  const sev = Object.entries(a.open_by_severity).map(([k, v]) => ({ severity: k, count: v }))
  return (
    <div className="grid gap-3 xl:grid-cols-3 [&>*]:min-w-0">
      <div className="grid grid-cols-2 content-start gap-3">
        <Kpi label="Critical open alerts" value={a.open_by_severity.critical ?? 0} icon={ShieldAlert} tone={a.open_by_severity.critical ? 'warn' : undefined} />
        <Kpi label="Open alerts" value={a.open_total} icon={ShieldAlert} hint={`${a.unassigned} unassigned`} />
        <div className="col-span-2"><Button asChild variant="secondary" size="sm" className="w-full"><Link to="/alerts">Open alert queue</Link></Button></div>
      </div>
      <Card>
        <CardHeader title="Open alerts by severity" />
        <div className="h-48 px-2 py-3">
          {!a.open_total ? <EmptyState icon={ShieldCheck} title="No open alerts" /> : (
            <ResponsiveContainer><BarChart data={sev}><CartesianGrid stroke={GRID} vertical={false} /><XAxis dataKey="severity" {...AXIS} /><YAxis allowDecimals={false} width={28} {...AXIS} /><Tooltip {...TOOLTIP} />
              <Bar dataKey="count" name="Open" radius={[3, 3, 0, 0]}>{sev.map((s) => <Cell key={s.severity} fill={SEV_COLORS[s.severity]} />)}</Bar></BarChart></ResponsiveContainer>
          )}
        </div>
      </Card>
      <Card>
        <CardHeader title="Alerts detected" description="Per day, last 14 days" />
        <div className="h-48 px-2 py-3">
          <ResponsiveContainer><AreaChart data={a.detected_by_day}><CartesianGrid stroke={GRID} vertical={false} /><XAxis dataKey="date" tickFormatter={short} {...AXIS} /><YAxis allowDecimals={false} width={28} {...AXIS} />
            <Tooltip {...TOOLTIP} labelFormatter={(v) => short(String(v))} /><Area type="monotone" dataKey="count" name="Alerts" stroke="#f97316" fill="#f9731622" strokeWidth={1.5} /></AreaChart></ResponsiveContainer>
        </div>
      </Card>
    </div>
  )
}

export function DashboardPage() {
  const q = useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<DashboardSummary>('/dashboard/summary'), refetchInterval: 60_000 })

  if (q.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (q.error) return <Alert>{describeError(q.error)}</Alert>
  const d = q.data!
  const short = (iso: string) => new Date(iso + 'T00:00:00').toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  const statusData = [
    { name: 'Active', value: d.employees.active },
    { name: 'Invited', value: d.employees.invited },
    { name: 'Suspended', value: d.employees.suspended },
    { name: 'Offboarded', value: d.employees.offboarded },
  ].filter((x) => x.value > 0)
  const totalLogins = d.authentication.logins_by_day.reduce((a, b) => a + b.success + b.failure, 0)

  return (
    <div className="animate-fade-in space-y-5">
      <PageHeader title="Operations overview" description={`Live figures computed from the database · updated ${formatDateTime(d.generated_at)}`}
        actions={<Button variant="outline" size="sm" onClick={() => q.refetch()} loading={q.isFetching}><RefreshCw />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Active employees" value={d.employees.active} icon={Users} />
        <Kpi label="Suspended employees" value={d.employees.suspended} icon={UserMinus} tone={d.employees.suspended ? 'warn' : undefined} />
        <Kpi label="Offboarded" value={d.employees.offboarded} icon={UserCheck} />
        <Kpi label="Failed sign-ins (24h)" value={d.authentication.failed_logins_24h} icon={ShieldAlert} tone={d.authentication.failed_logins_24h ? 'warn' : undefined} />
        <Kpi label="Locked accounts" value={d.authentication.locked_accounts} icon={KeyRound} tone={d.authentication.locked_accounts ? 'warn' : undefined} />
        <Kpi label="Admins with MFA" value={`${d.administrators.mfa_enabled}/${d.administrators.active}`} icon={ShieldCheck}
          tone={d.administrators.mfa_enabled < d.administrators.active ? 'warn' : undefined} hint="Active administrator accounts" />
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Administrator sign-ins" description="Successful vs failed password sign-ins, last 14 days" />
          <div className="h-64 px-2 py-3">
            {totalLogins === 0 ? <EmptyState icon={Activity} title="No sign-in activity yet" /> : (
              <ResponsiveContainer>
                <BarChart data={d.authentication.logins_by_day} barGap={2}>
                  <CartesianGrid stroke={GRID} vertical={false} />
                  <XAxis dataKey="date" tickFormatter={short} {...AXIS} />
                  <YAxis allowDecimals={false} width={28} {...AXIS} />
                  <Tooltip {...TOOLTIP} labelFormatter={(v) => short(String(v))} />
                  <Bar dataKey="success" name="Successful" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="failure" name="Failed" stackId="a" fill="#ef4444" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Workforce status" description="Employees by lifecycle state" />
          <div className="h-64 px-2 py-3">
            {statusData.length === 0 ? (
              <EmptyState icon={Users} title="No employees yet" action={<Button asChild size="sm" variant="secondary"><Link to="/employees">Add employees</Link></Button>} />
            ) : (
              <div className="flex h-full items-center">
                <ResponsiveContainer width="55%">
                  <PieChart>
                    <Pie data={statusData} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="85%" paddingAngle={2} stroke="none">
                      {statusData.map((s) => <Cell key={s.name} fill={STATUS_COLORS[['Active', 'Invited', 'Suspended', 'Offboarded'].indexOf(s.name)]} />)}
                    </Pie>
                    <Tooltip {...TOOLTIP} />
                  </PieChart>
                </ResponsiveContainer>
                <ul className="space-y-2 text-xs">
                  {statusData.map((s) => (
                    <li key={s.name} className="flex items-center gap-2">
                      <span className="size-2 rounded-sm" style={{ background: STATUS_COLORS[['Active', 'Invited', 'Suspended', 'Offboarded'].indexOf(s.name)] }} />
                      <span className="text-silver-400">{s.name}</span><span className="ml-auto pl-3 tabular-nums text-silver-100">{s.value}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Card>
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        <Card>
          <CardHeader title="Headcount by department" description="Excludes offboarded employees" />
          <div className="h-60 px-2 py-3">
            {d.employees.by_department.length === 0 ? <EmptyState icon={Users} title="No departments yet" /> : (
              <ResponsiveContainer>
                <BarChart data={d.employees.by_department} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid stroke={GRID} horizontal={false} />
                  <XAxis type="number" allowDecimals={false} {...AXIS} />
                  <YAxis type="category" dataKey="department" width={96} {...AXIS} />
                  <Tooltip {...TOOLTIP} />
                  <Bar dataKey="count" name="Employees" fill="#34d399" radius={[0, 3, 3, 0]} barSize={14} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Joiners" description="Employees created per day, last 14 days" />
          <div className="h-60 px-2 py-3">
            <ResponsiveContainer>
              <AreaChart data={d.employees.joiners_by_day}>
                <defs><linearGradient id="j" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#10b981" stopOpacity={0.25} /><stop offset="100%" stopColor="#10b981" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid stroke={GRID} vertical={false} />
                <XAxis dataKey="date" tickFormatter={short} {...AXIS} />
                <YAxis allowDecimals={false} width={28} {...AXIS} />
                <Tooltip {...TOOLTIP} labelFormatter={(v) => short(String(v))} />
                <Area type="monotone" dataKey="count" name="Joiners" stroke="#10b981" fill="url(#j)" strokeWidth={1.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card>
          <CardHeader title="Recent administrative activity" action={d.recent_activity_visible ? <Link to="/audit" className="text-xs text-emerald-400 hover:text-emerald-300">Audit log</Link> : undefined} />
          {!d.recent_activity_visible ? (
            <EmptyState icon={Activity} title="Restricted" description="Your role does not include audit log access." />
          ) : d.recent_activity.length === 0 ? <EmptyState icon={Activity} title="No activity recorded" /> : (
            <ol className="max-h-60 overflow-y-auto px-4 py-2">
              {d.recent_activity.map((a) => (
                <li key={a.id} className="relative border-l border-ink-700 py-2 pl-4">
                  <span className="absolute -left-[3.5px] top-3.5 size-1.5 rounded-full bg-ink-500" />
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[13px] text-silver-100">{humanizeAction(a.action)}</span>
                    {a.result !== 'success' && <Badge tone={statusTone(a.result)}>{a.result}</Badge>}
                  </div>
                  <div className="truncate text-[11px] text-silver-500">{a.actor}{a.target ? ` → ${a.target}` : ''} · {relativeTime(a.created_at)}</div>
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-silver-600">Endpoints</h2>
        {d.endpoints.available ? <EndpointsSection e={d.endpoints} short={short} /> : <Pending m={d.endpoints} icon={Laptop} />}
      </div>

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-silver-600">Security posture</h2>
        <SecuritySection c={d.compliance} p={d.policies} short={short} />
        <div className="mt-3">{(d.alerts as { available: boolean }).available
          ? <AlertsSection a={d.alerts as unknown as AlertsDash} short={short} />
          : <div className="grid gap-3 md:grid-cols-3"><Pending m={d.alerts as ModuleStatus} icon={ShieldAlert} /></div>}</div>
      </div>
    </div>
  )
}
