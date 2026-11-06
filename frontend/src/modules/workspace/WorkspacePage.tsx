import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AppWindow, ExternalLink, Laptop, ShieldCheck } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, PageHeader, Spinner } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'
import { ConnectivityBadge } from '@/modules/devices/shared'
import type { Connectivity } from '@/types/api'
import { relativeTime } from '@/utils/format'

interface Workspace {
  employee: { full_name: string; email: string; department: string; job_title: string; employee_number: string; status: string } | null
  devices: { id: string; name: string; os: string | null; status: string; connectivity: Connectivity; compliance_state: string; last_heartbeat_at: string | null }[]
  applications: { id: string; name: string; description: string; launch_url: string | null; mfa_required: boolean }[]
}

export function WorkspacePage() {
  const q = useQuery({ queryKey: ['workspace'], queryFn: () => api.get<Workspace>('/me/workspace') })
  if (q.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (q.error) return <Alert>{describeError(q.error)}</Alert>
  const w = q.data!
  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title={w.employee ? `Welcome, ${w.employee.full_name.split(' ')[0]}` : 'My workspace'}
        description={w.employee ? `${w.employee.job_title} · ${w.employee.department} · ${w.employee.employee_number}` : 'Your account is not linked to an employee record.'}
        actions={<Button asChild size="sm" variant="outline"><Link to="/account/security"><ShieldCheck />Passkeys & sign-in security</Link></Button>} />
      <Card>
        <CardHeader title="My applications" description="Single sign-on: you are signed in to these with your workspace account." />
        {!w.applications.length ? <EmptyState icon={AppWindow} title="No applications assigned" description="Ask your administrator if you need access to an application." /> : (
          <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">{w.applications.map((a) => (
            <div key={a.id} className="flex flex-col rounded-lg border border-ink-700 bg-ink-850 p-4">
              <div className="flex items-center gap-2"><AppWindow className="size-4 text-emerald-400" /><span className="text-sm font-medium text-silver-50">{a.name}</span>
                {a.mfa_required && <Badge tone="info">MFA</Badge>}</div>
              {a.description && <p className="mt-1 text-xs text-silver-500">{a.description}</p>}
              <div className="mt-auto pt-3">{a.launch_url
                ? <Button asChild size="sm" variant="secondary"><a href={a.launch_url} target="_blank" rel="noopener noreferrer"><ExternalLink />Open</a></Button>
                : <span className="text-xs text-silver-600">Open it from the application itself.</span>}</div>
            </div>
          ))}</div>
        )}
      </Card>
      <Card>
        <CardHeader title="My devices" />
        {!w.devices.length ? <EmptyState icon={Laptop} title="No devices assigned" /> : (
          <ul className="divide-y divide-ink-800">{w.devices.map((d) => (
            <li key={d.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
              <div><div className="text-sm text-silver-100">{d.name}</div><div className="text-xs text-silver-500">{d.os ?? 'OS not reported'}{d.last_heartbeat_at ? ` · seen ${relativeTime(d.last_heartbeat_at)}` : ''}</div></div>
              <div className="flex items-center gap-2"><ConnectivityBadge c={d.connectivity} last={d.last_heartbeat_at} />
                <Badge tone={d.compliance_state === 'compliant' ? 'success' : d.compliance_state === 'non_compliant' ? 'danger' : 'warning'}>{d.compliance_state.replace('_', '-')}</Badge></div>
            </li>
          ))}</ul>
        )}
      </Card>
    </div>
  )
}
