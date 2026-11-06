import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AppWindow, ArrowLeft, Copy, KeyRound, Plus, UserPlus } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Input, PageHeader, Select, Spinner, Table, Td, Th } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { Employee, Page } from '@/types/api'
import { formatDateTime, relativeTime } from '@/utils/format'

export interface App {
  id: string; name: string; description: string; protocol: string; client_id: string; client_type: 'confidential' | 'public'
  redirect_uris: string[]; launch_url: string | null; mfa_required: boolean; status: 'active' | 'disabled'
  verified_at: string | null; created_at: string; assigned_employees: number; integration: string; client_secret?: string
}

const ISSUER = `${window.location.origin}/api/v1/oidc`

function Copyable({ label, value, secret }: { label: string; value: string; secret?: boolean }) {
  const [copied, setCopied] = useState(false)
  return (
    <div>
      <div className="mb-1 text-xs text-silver-500">{label}</div>
      <div className="flex items-center gap-2">
        <code className={`min-w-0 flex-1 break-all rounded bg-ink-950 px-2 py-1.5 font-mono text-xs ${secret ? 'text-amber-200' : 'text-silver-100'}`}>{value}</code>
        <Button size="sm" variant="ghost" type="button" onClick={() => { void navigator.clipboard.writeText(value); setCopied(true) }}><Copy />{copied ? 'Copied' : 'Copy'}</Button>
      </div>
    </div>
  )
}

function IntegrationBadge({ a }: { a: App }) {
  return a.verified_at ? <Badge tone="success" title={`First successful sign-in ${formatDateTime(a.verified_at)}`}>verified</Badge>
    : <Badge tone="warning" title="No real sign-in has completed yet">not yet verified</Badge>
}

function SecretNotice({ a }: { a: App }) {
  if (!a.client_secret) return null
  return (
    <Alert tone="warning">
      <div className="space-y-2"><div>Copy the client secret now — it is stored only as a hash and cannot be shown again.</div>
        <Copyable label="Client secret" value={a.client_secret} secret /></div>
    </Alert>
  )
}

export function ApplicationsPage() {
  const { can } = useAuth()
  const nav = useNavigate()
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['applications'], queryFn: () => api.get<App[]>('/applications') })
  const [open, setOpen] = useState(false)
  const [f, setF] = useState({ name: '', description: '', client_type: 'confidential', redirect: '', launch_url: '', mfa_required: false })
  const [created, setCreated] = useState<App | null>(null)
  const create = useMutation({
    mutationFn: () => api.post<App>('/applications', {
      name: f.name, description: f.description, client_type: f.client_type, mfa_required: f.mfa_required,
      redirect_uris: f.redirect.split('\n').map((x) => x.trim()).filter(Boolean), launch_url: f.launch_url.trim() || null,
    }),
    onSuccess: (a) => { qc.invalidateQueries({ queryKey: ['applications'] }); setCreated(a) },
  })

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Applications" description="Single sign-on with OpenID Connect. Antiquarian's Cage is the identity provider; employees only reach applications they are assigned."
        actions={can('applications:manage') && <Button size="sm" onClick={() => { create.reset(); setCreated(null); setOpen(true) }}><Plus />Register application</Button>} />
      <Card>
        <CardHeader title="Identity provider endpoints" description="Configure these in the application's OIDC settings." />
        <div className="grid gap-3 p-4 md:grid-cols-2">
          <Copyable label="Issuer" value={ISSUER} />
          <Copyable label="Discovery document" value={`${ISSUER}/.well-known/openid-configuration`} />
        </div>
        <p className="px-4 pb-3 text-xs text-silver-500">Authorization code flow with PKCE (S256) is required. SAML is not implemented yet — do not register SAML-only applications.</p>
      </Card>
      <Card>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : !list.data?.length ? (
          <EmptyState icon={AppWindow} title="No applications registered" description="Register an OIDC application, assign employees, then complete one real sign-in to verify the integration." />
        ) : (
          <Table>
            <thead><tr><Th>Application</Th><Th>Client</Th><Th>Integration</Th><Th>MFA</Th><Th>Employees</Th><Th>Status</Th></tr></thead>
            <tbody>{list.data.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-ink-850" onClick={() => nav(`/applications/${a.id}`)}>
                <Td><Link to={`/applications/${a.id}`} onClick={(e) => e.stopPropagation()} className="text-silver-50 hover:text-emerald-300">{a.name}</Link>
                  {a.description && <div className="max-w-xs truncate text-xs text-silver-500">{a.description}</div>}</Td>
                <Td><code className="font-mono text-xs text-silver-400">{a.client_id}</code><div className="text-xs text-silver-600">{a.client_type}</div></Td>
                <Td><IntegrationBadge a={a} /></Td>
                <Td>{a.mfa_required ? <Badge tone="info">required</Badge> : <span className="text-xs text-silver-600">optional</span>}</Td>
                <Td>{a.assigned_employees}</Td>
                <Td>{a.status === 'active' ? <Badge tone="success">active</Badge> : <Badge>disabled</Badge>}</Td>
              </tr>
            ))}</tbody>
          </Table>
        )}
      </Card>

      <Dialog open={open} onOpenChange={setOpen} title={created ? `${created.name} registered` : 'Register OIDC application'} className="max-w-xl"
        description={created ? 'The integration stays “not yet verified” until a real sign-in completes.' : 'Redirect URIs must match exactly; https is required except for localhost.'}>
        {created ? (
          <div className="space-y-3">
            <SecretNotice a={created} />
            <Copyable label="Client ID" value={created.client_id} />
            <div className="flex justify-end"><Button onClick={() => nav(`/applications/${created.id}`)}>Assign employees</Button></div>
          </div>
        ) : (
          <form className="space-y-3" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}>
            {create.error && <Alert>{describeError(create.error)}</Alert>}
            <Field label="Name" htmlFor="an"><Input id="an" required minLength={2} maxLength={128} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
            <Field label="Description" htmlFor="ad"><Input id="ad" maxLength={1000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
            <Field label="Client type" htmlFor="at">
              <Select id="at" className="w-full" value={f.client_type} onChange={(e) => setF({ ...f, client_type: e.target.value })}>
                <option value="confidential">Confidential (server-side app with a client secret)</option>
                <option value="public">Public (SPA / native app, PKCE only, no secret)</option>
              </Select>
            </Field>
            <Field label="Redirect URIs (one per line)" htmlFor="ar">
              <textarea id="ar" required rows={3} className="w-full rounded-md border border-ink-600 bg-ink-900 px-3 py-2 font-mono text-xs text-silver-100 focus:border-emerald-600/70 focus:outline-none"
                placeholder="https://wiki.example.com/oidc/callback" value={f.redirect} onChange={(e) => setF({ ...f, redirect: e.target.value })} />
            </Field>
            <Field label="Launch URL (shown in employee workspace)" htmlFor="al"><Input id="al" value={f.launch_url} onChange={(e) => setF({ ...f, launch_url: e.target.value })} /></Field>
            <label className="flex items-center gap-2 text-sm text-silver-200"><input type="checkbox" className="size-4 accent-emerald-500" checked={f.mfa_required} onChange={(e) => setF({ ...f, mfa_required: e.target.checked })} />
              Require multi-factor sign-in (passkey or password + authenticator code)</label>
            <div className="flex justify-end"><Button type="submit" loading={create.isPending}>Register</Button></div>
          </form>
        )}
      </Dialog>
    </div>
  )
}

interface Assignment { id: string; employee_id: string; employee_name: string; email: string; employee_status: string; has_portal_account: boolean; granted_at: string }
interface AppEvent { id: string; event_type: string; success: boolean; reason: string | null; email: string | null; ip: string | null; created_at: string }

export function ApplicationDetailPage() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const manage = can('applications:manage')
  const app = useQuery({ queryKey: ['application', id], queryFn: () => api.get<App>(`/applications/${id}`) })
  const assigns = useQuery({ queryKey: ['application', id, 'assignments'], queryFn: () => api.get<Assignment[]>(`/applications/${id}/assignments`) })
  const events = useQuery({ queryKey: ['application', id, 'events'], queryFn: () => api.get<AppEvent[]>(`/applications/${id}/events`), refetchInterval: 15_000 })
  const [assigning, setAssigning] = useState(false)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [secretApp, setSecretApp] = useState<App | null>(null)
  const emps = useQuery({ queryKey: ['employees', 'active-all'], queryFn: () => api.get<Page<Employee>>('/employees?status=active&page_size=100'), enabled: assigning })
  const refresh = () => { qc.invalidateQueries({ queryKey: ['application', id] }); qc.invalidateQueries({ queryKey: ['applications'] }) }
  const assign = useMutation({ mutationFn: () => api.post(`/applications/${id}/assignments`, { employee_ids: [...picked] }), onSuccess: () => { refresh(); setAssigning(false); setPicked(new Set()) } })
  const revoke = useMutation({ mutationFn: (aid: string) => api.del(`/applications/${id}/assignments/${aid}`), onSuccess: refresh })
  const rotate = useMutation({ mutationFn: () => api.post<App>(`/applications/${id}/rotate-secret`), onSuccess: (a) => setSecretApp(a) })
  const toggle = useMutation({ mutationFn: (body: Partial<App>) => api.patch(`/applications/${id}`, body), onSuccess: refresh })

  if (app.isLoading) return <div className="grid h-64 place-items-center"><Spinner /></div>
  if (app.error) return <Alert>{describeError(app.error)}</Alert>
  const a = app.data!
  const assigned = new Set(assigns.data?.map((x) => x.employee_id))

  return (
    <div className="animate-fade-in space-y-4">
      <Link to="/applications" className="inline-flex items-center gap-1 text-xs text-silver-500 hover:text-silver-200"><ArrowLeft className="size-3.5" />Applications</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><div className="flex items-center gap-2"><h1 className="text-lg font-semibold text-silver-50">{a.name}</h1><IntegrationBadge a={a} />{a.status !== 'active' && <Badge tone="danger">disabled</Badge>}</div>
          <p className="mt-0.5 text-sm text-silver-500">{a.description || 'OIDC application'} · {a.client_type} client</p></div>
        {manage && (
          <div className="flex gap-2">
            {a.client_type === 'confidential' && <Button size="sm" variant="outline" onClick={() => rotate.mutate()} loading={rotate.isPending}><KeyRound />Rotate secret</Button>}
            <Button size="sm" variant="outline" onClick={() => toggle.mutate({ mfa_required: !a.mfa_required })}>{a.mfa_required ? 'Make MFA optional' : 'Require MFA'}</Button>
            <Button size="sm" variant={a.status === 'active' ? 'danger' : 'primary'} onClick={() => toggle.mutate({ status: a.status === 'active' ? 'disabled' : 'active' })}>{a.status === 'active' ? 'Disable' : 'Enable'}</Button>
          </div>
        )}
      </div>
      {secretApp && <SecretNotice a={secretApp} />}
      {!a.verified_at && <Alert tone="info">Integration not yet verified: it becomes “verified” automatically after the first successful sign-in (authorization code exchanged for tokens). Until then, do not tell users it works.</Alert>}

      <div className="grid gap-4 xl:grid-cols-2 [&>*]:min-w-0">
        <Card>
          <CardHeader title="Client configuration" />
          <div className="space-y-3 p-4">
            <Copyable label="Client ID" value={a.client_id} />
            <Copyable label="Issuer" value={ISSUER} />
            <div><div className="mb-1 text-xs text-silver-500">Redirect URIs</div>{a.redirect_uris.map((u) => <code key={u} className="block font-mono text-xs text-silver-200">{u}</code>)}</div>
            <div className="text-xs text-silver-500">Scopes: openid profile email · PKCE S256 required · ID token RS256 (5 min) · MFA {a.mfa_required ? 'required' : 'optional'}</div>
          </div>
        </Card>
        <Card>
          <CardHeader title="Assigned employees" action={manage && <Button size="sm" variant="outline" onClick={() => setAssigning(true)}><UserPlus />Assign</Button>} />
          {!assigns.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">Nobody can sign in to this application yet.</p> : (
            <ul className="divide-y divide-ink-800">{assigns.data.map((x) => (
              <li key={x.id} className="flex items-center justify-between gap-2 px-4 py-2">
                <div><Link to={`/employees/${x.employee_id}`} className="text-sm text-silver-100 hover:text-emerald-300">{x.employee_name}</Link>
                  <div className="text-xs text-silver-500">{x.email} · since {relativeTime(x.granted_at)}{!x.has_portal_account && ' · no sign-in account yet'}</div></div>
                {manage && <Button size="sm" variant="ghost" onClick={() => revoke.mutate(x.id)}>Revoke</Button>}
              </li>
            ))}</ul>
          )}
        </Card>
      </div>

      <Card>
        <CardHeader title="Authentication events" description="Every authorization and token exchange for this application." />
        {!events.data?.length ? <p className="px-4 py-3 text-sm text-silver-500">No sign-ins yet.</p> : (
          <Table>
            <thead><tr><Th>When</Th><Th>Event</Th><Th>User</Th><Th>Result</Th><Th>IP</Th></tr></thead>
            <tbody>{events.data.map((e) => (
              <tr key={e.id}><Td className="text-silver-400">{formatDateTime(e.created_at)}</Td><Td>{e.event_type === 'sso_authorize' ? 'Authorization' : 'Token issued'}</Td>
                <Td className="text-silver-300">{e.email ?? '—'}</Td>
                <Td>{e.success ? <Badge tone="success">success</Badge> : <Badge tone="danger">{e.reason ?? 'failed'}</Badge>}</Td>
                <Td className="font-mono text-xs">{e.ip ?? '—'}</Td></tr>
            ))}</tbody>
          </Table>
        )}
      </Card>

      <Dialog open={assigning} onOpenChange={setAssigning} title="Assign employees" description="Only active employees can be granted access. They need a workspace account to sign in.">
        {assign.error && <div className="mb-3"><Alert>{describeError(assign.error)}</Alert></div>}
        {emps.isLoading ? <Spinner /> : (
          <ul className="max-h-72 divide-y divide-ink-800 overflow-y-auto rounded-md border border-ink-700">
            {emps.data?.items.filter((e) => !assigned.has(e.id)).map((e) => (
              <li key={e.id}><label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-ink-850">
                <input type="checkbox" className="size-4 accent-emerald-500" checked={picked.has(e.id)}
                  onChange={(ev) => { const s = new Set(picked); if (ev.target.checked) s.add(e.id); else s.delete(e.id); setPicked(s) }} />
                <span className="text-sm text-silver-100">{e.full_name}<span className="block text-xs text-silver-500">{e.email} · {e.department}</span></span>
              </label></li>
            ))}
          </ul>
        )}
        <div className="mt-4 flex justify-end"><Button disabled={!picked.size} onClick={() => assign.mutate()} loading={assign.isPending}>Grant access</Button></div>
      </Dialog>
    </div>
  )
}
