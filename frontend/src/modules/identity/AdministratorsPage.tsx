import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as DM from '@radix-ui/react-dropdown-menu'
import { Building2, MoreHorizontal, UserPlus } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Table, Td, Th, statusTone } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { AdminCreated, AdminUser, Handover, OrganizationCreated, RoleDetail } from '@/types/api'
import { formatDateTime } from '@/utils/format'

const ASSIGNABLE = ['super_admin', 'admin', 'security_analyst', 'it_support'] as const

interface Reveal { title: string; email: string; password: string }

/** One-time reveal of a temporary password to hand to the account's owner. */
function HandoverDialog({ reveal, onClose }: { reveal: Reveal | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try { await navigator.clipboard.writeText(reveal!.password); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* clipboard unavailable */ }
  }
  return (
    <Dialog open={!!reveal} onOpenChange={(o) => !o && onClose()} title={reveal?.title ?? ''}
      description="Give this temporary password to its owner over a trusted channel. They must change it on first sign-in. It is shown only once.">
      {reveal && (
        <div className="space-y-3">
          <div className="text-sm text-silver-400">Account</div>
          <div className="font-medium text-silver-100">{reveal.email}</div>
          <div className="text-sm text-silver-400">Temporary password</div>
          <div className="flex items-center gap-2">
            <code className="flex-1 select-all rounded bg-ink-800 px-3 py-2 font-mono text-sm text-silver-50">{reveal.password}</code>
            <Button type="button" size="sm" variant="secondary" onClick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
          </div>
          <div className="flex justify-end"><Button type="button" onClick={onClose}>Done</Button></div>
        </div>
      )}
    </Dialog>
  )
}

export function AdministratorsPage() {
  const { me, can } = useAuth()
  const qc = useQueryClient()
  const manage = can('users:manage')
  const isSuperAdmin = !!me?.roles.some((r) => r.key === 'super_admin')
  const users = useQuery({ queryKey: ['admins'], queryFn: () => api.get<AdminUser[]>('/users') })
  const roles = useQuery({ queryKey: ['roles'], queryFn: () => api.get<RoleDetail[]>('/users/roles') })
  const [creating, setCreating] = useState(false)
  const [newAdmin, setNewAdmin] = useState({ email: '', full_name: '', role: 'admin' })
  const [org, setOrg] = useState<null | { organization_name: string; super_admin_email: string; super_admin_full_name: string }>(null)
  const [roleEdit, setRoleEdit] = useState<AdminUser | null>(null)
  const [roleKey, setRoleKey] = useState('admin')
  const [flash, setFlash] = useState<{ tone: 'success' | 'danger'; msg: string } | null>(null)
  const [reveal, setReveal] = useState<Reveal | null>(null)
  const invalidate = () => qc.invalidateQueries({ queryKey: ['admins'] })

  const createM = useMutation({
    mutationFn: () => api.post<AdminCreated>('/users', newAdmin),
    onSuccess: (r) => {
      invalidate(); setCreating(false); setNewAdmin({ email: '', full_name: '', role: 'admin' })
      setReveal({ title: 'Administrator created', email: r.user.email, password: r.temporary_password })
    },
  })
  const orgM = useMutation({
    mutationFn: () => api.post<OrganizationCreated>('/organizations', org),
    onSuccess: (r) => {
      setOrg(null)
      setReveal({ title: `Organisation “${r.organization_name}” created`, email: r.super_admin_email, password: r.temporary_password })
    },
  })
  const rolesM = useMutation({
    mutationFn: () => api.put<AdminUser>(`/users/${roleEdit!.id}/roles`, { roles: [roleKey] }),
    onSuccess: () => { invalidate(); setRoleEdit(null); setFlash({ tone: 'success', msg: 'Role updated. The administrator must sign in again.' }) },
  })
  const resetM = useMutation({
    mutationFn: (id: string) => api.post<Handover>(`/users/${id}/reset-password`),
    onSuccess: (r) => { invalidate(); setReveal({ title: 'Temporary password reset', email: r.email, password: r.temporary_password }) },
    onError: (e) => setFlash({ tone: 'danger', msg: describeError(e) }),
  })
  const action = useMutation({
    mutationFn: ({ id, op }: { id: string; op: string }) => api.post<unknown>(`/users/${id}/${op}`),
    onSuccess: (_d, v) => { invalidate(); setFlash({ tone: 'success', msg: `Action “${v.op.replace('-', ' ')}” completed.` }) },
    onError: (e) => setFlash({ tone: 'danger', msg: describeError(e) }),
  })

  function submitCreate(e: FormEvent) { e.preventDefault(); createM.mutate() }

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Administrators" description="Console accounts and their roles. Only Super Admins can manage administrators and organisations."
        actions={manage && (
          <div className="flex gap-2">
            {isSuperAdmin && <Button size="sm" variant="secondary" onClick={() => { orgM.reset(); setOrg({ organization_name: '', super_admin_email: '', super_admin_full_name: '' }) }}><Building2 />New organisation</Button>}
            <Button size="sm" onClick={() => { createM.reset(); setCreating(true) }}><UserPlus />Create administrator</Button>
          </div>
        )} />
      {flash && <Alert tone={flash.tone}>{flash.msg}</Alert>}
      <Card>
        {users.isLoading ? <div className="p-6"><Spinner /></div> : users.error ? <div className="p-4"><Alert>{describeError(users.error)}</Alert></div> : (
          <Table>
            <thead><tr><Th>Administrator</Th><Th>Role</Th><Th>Status</Th><Th>Last sign-in</Th>{manage && <Th className="w-10" />}</tr></thead>
            <tbody>
              {users.data!.map((u) => {
                const locked = u.locked_until && new Date(u.locked_until) > new Date()
                return (
                  <tr key={u.id} className="hover:bg-ink-850">
                    <Td><div className="text-silver-50">{u.full_name}{u.id === me?.id && <span className="ml-1.5 text-xs text-silver-500">(you)</span>}</div><div className="text-xs text-silver-500">{u.email}</div></Td>
                    <Td>{u.roles.map((r) => <Badge key={r.key} className="mr-1">{r.name}</Badge>)}</Td>
                    <Td><Badge tone={statusTone(u.status)}>{u.status}</Badge>{locked && <Badge tone="danger" className="ml-1">locked</Badge>}</Td>
                    <Td className="text-silver-400">{formatDateTime(u.last_login_at)}</Td>
                    {manage && (
                      <Td>
                        <DM.Root>
                          <DM.Trigger className="rounded p-1 text-silver-500 hover:bg-ink-700 hover:text-silver-100" aria-label={`Actions for ${u.email}`}><MoreHorizontal className="size-4" /></DM.Trigger>
                          <DM.Portal>
                            <DM.Content align="end" className="z-40 w-56 rounded-md border border-ink-600 bg-ink-900 p-1 text-sm shadow-xl">
                              {[
                                { label: 'Change role', show: true, run: () => { rolesM.reset(); setRoleKey(u.roles[0]?.key ?? 'admin'); setRoleEdit(u) } },
                                { label: 'Reset password & hand over', show: u.id !== me?.id && u.status !== 'disabled', run: () => resetM.mutate(u.id) },
                                { label: 'Unlock account', show: !!locked, run: () => action.mutate({ id: u.id, op: 'unlock' }) },
                                { label: 'Revoke all sessions', show: u.status === 'active', run: () => action.mutate({ id: u.id, op: 'revoke-sessions' }) },
                                { label: 'Disable account', show: u.status !== 'disabled' && u.id !== me?.id, run: () => action.mutate({ id: u.id, op: 'disable' }) },
                                { label: 'Re-enable account', show: u.status === 'disabled', run: () => action.mutate({ id: u.id, op: 'enable' }) },
                              ].filter((i) => i.show).map((i) => (
                                <DM.Item key={i.label} onSelect={i.run} className="cursor-pointer rounded px-2.5 py-1.5 text-silver-200 outline-none data-[highlighted]:bg-ink-800">{i.label}</DM.Item>
                              ))}
                            </DM.Content>
                          </DM.Portal>
                        </DM.Root>
                      </Td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="Roles & permissions" description="Built-in roles. Every permission is enforced by the API, not the interface." />
        <div className="grid gap-px bg-ink-700 md:grid-cols-2 xl:grid-cols-3">
          {roles.data?.map((r) => (
            <div key={r.key} className="bg-ink-900 p-4">
              <div className="text-sm font-medium text-silver-100">{r.name}</div>
              <p className="mt-0.5 text-xs text-silver-500">{r.description}</p>
              <div className="mt-2 flex flex-wrap gap-1">{r.permissions.map((p) => <code key={p} className="rounded bg-ink-800 px-1.5 py-0.5 text-[10px] text-silver-400">{p}</code>)}</div>
            </div>
          ))}
        </div>
      </Card>

      <Dialog open={creating} onOpenChange={setCreating} title="Create administrator" description="A temporary password is generated for handover. The administrator must change it on first sign-in.">
        <form onSubmit={submitCreate} className="space-y-3">
          {createM.error && <Alert>{describeError(createM.error)}</Alert>}
          <Field label="Full name" htmlFor="iname"><Input id="iname" required minLength={2} value={newAdmin.full_name} onChange={(e) => setNewAdmin({ ...newAdmin, full_name: e.target.value })} /></Field>
          <Field label="Work email" htmlFor="iemail"><Input id="iemail" type="email" required value={newAdmin.email} onChange={(e) => setNewAdmin({ ...newAdmin, email: e.target.value })} /></Field>
          <Field label="Role" htmlFor="irole">
            <Select id="irole" className="w-full" value={newAdmin.role} onChange={(e) => setNewAdmin({ ...newAdmin, role: e.target.value })}>
              {ASSIGNABLE.map((k) => <option key={k} value={k}>{roles.data?.find((r) => r.key === k)?.name ?? k}</option>)}
            </Select>
          </Field>
          <div className="flex justify-end"><Button type="submit" loading={createM.isPending}>Create account</Button></div>
        </form>
      </Dialog>

      <Dialog open={!!org} onOpenChange={(o) => !o && setOrg(null)} title="Create organisation" description="Creates a new organisation and its first Super Admin, with a temporary password to hand over.">
        {org && (
          <form onSubmit={(e) => { e.preventDefault(); orgM.mutate() }} className="space-y-3">
            {orgM.error && <Alert>{describeError(orgM.error)}</Alert>}
            <Field label="Organisation name" htmlFor="oname"><Input id="oname" required minLength={2} value={org.organization_name} onChange={(e) => setOrg({ ...org, organization_name: e.target.value })} /></Field>
            <Field label="Super Admin full name" htmlFor="osa"><Input id="osa" required minLength={2} value={org.super_admin_full_name} onChange={(e) => setOrg({ ...org, super_admin_full_name: e.target.value })} /></Field>
            <Field label="Super Admin email" htmlFor="osae"><Input id="osae" type="email" required value={org.super_admin_email} onChange={(e) => setOrg({ ...org, super_admin_email: e.target.value })} /></Field>
            <div className="flex justify-end"><Button type="submit" loading={orgM.isPending}>Create organisation</Button></div>
          </form>
        )}
      </Dialog>

      <Dialog open={!!roleEdit} onOpenChange={(o) => !o && setRoleEdit(null)} title="Change role" description={`${roleEdit?.email ?? ''} will be signed out of all sessions.`}>
        <form onSubmit={(e) => { e.preventDefault(); rolesM.mutate() }} className="space-y-3">
          {rolesM.error && <Alert>{describeError(rolesM.error)}</Alert>}
          <Select className="w-full" value={roleKey} onChange={(e) => setRoleKey(e.target.value)} aria-label="Role">
            {ASSIGNABLE.map((k) => <option key={k} value={k}>{roles.data?.find((r) => r.key === k)?.name ?? k}</option>)}
          </Select>
          <div className="flex justify-end"><Button type="submit" loading={rolesM.isPending}>Save role</Button></div>
        </form>
      </Dialog>

      <HandoverDialog reveal={reveal} onClose={() => setReveal(null)} />
    </div>
  )
}
