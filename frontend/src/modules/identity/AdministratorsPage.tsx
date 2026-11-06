import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as DM from '@radix-ui/react-dropdown-menu'
import { MoreHorizontal, UserPlus } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, Table, Td, Th, statusTone } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError } from '@/services/api'
import type { AdminUser, RoleDetail } from '@/types/api'
import { formatDateTime } from '@/utils/format'

const ASSIGNABLE = ['super_admin', 'admin', 'security_analyst', 'it_support'] as const

export function AdministratorsPage() {
  const { me, can } = useAuth()
  const qc = useQueryClient()
  const manage = can('users:manage')
  const users = useQuery({ queryKey: ['admins'], queryFn: () => api.get<AdminUser[]>('/users') })
  const roles = useQuery({ queryKey: ['roles'], queryFn: () => api.get<RoleDetail[]>('/users/roles') })
  const [inviting, setInviting] = useState(false)
  const [invite, setInvite] = useState({ email: '', full_name: '', role: 'admin' })
  const [roleEdit, setRoleEdit] = useState<AdminUser | null>(null)
  const [roleKey, setRoleKey] = useState('admin')
  const [flash, setFlash] = useState<{ tone: 'success' | 'danger'; msg: string } | null>(null)
  const invalidate = () => qc.invalidateQueries({ queryKey: ['admins'] })

  const inviteM = useMutation({
    mutationFn: () => api.post<AdminUser>('/users', invite),
    onSuccess: (u) => { invalidate(); setInviting(false); setInvite({ email: '', full_name: '', role: 'admin' }); setFlash({ tone: 'success', msg: `Invitation sent to ${u.email}.` }) },
  })
  const rolesM = useMutation({
    mutationFn: () => api.put<AdminUser>(`/users/${roleEdit!.id}/roles`, { roles: [roleKey] }),
    onSuccess: () => { invalidate(); setRoleEdit(null); setFlash({ tone: 'success', msg: 'Role updated. The administrator must sign in again.' }) },
  })
  const action = useMutation({
    mutationFn: ({ id, op }: { id: string; op: string }) => api.post<unknown>(`/users/${id}/${op}`),
    onSuccess: (_d, v) => { invalidate(); setFlash({ tone: 'success', msg: `Action “${v.op.replace('-', ' ')}” completed.` }) },
    onError: (e) => setFlash({ tone: 'danger', msg: describeError(e) }),
  })

  function submitInvite(e: FormEvent) { e.preventDefault(); inviteM.mutate() }

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Administrators" description="Console accounts and their roles. Only Super Admins can manage administrators."
        actions={manage && <Button size="sm" onClick={() => { inviteM.reset(); setInviting(true) }}><UserPlus />Invite administrator</Button>} />
      {flash && <Alert tone={flash.tone}>{flash.msg}</Alert>}
      <Card>
        {users.isLoading ? <div className="p-6"><Spinner /></div> : users.error ? <div className="p-4"><Alert>{describeError(users.error)}</Alert></div> : (
          <Table>
            <thead><tr><Th>Administrator</Th><Th>Role</Th><Th>Status</Th><Th>MFA</Th><Th>Last sign-in</Th>{manage && <Th className="w-10" />}</tr></thead>
            <tbody>
              {users.data!.map((u) => {
                const locked = u.locked_until && new Date(u.locked_until) > new Date()
                return (
                  <tr key={u.id} className="hover:bg-ink-850">
                    <Td><div className="text-silver-50">{u.full_name}{u.id === me?.id && <span className="ml-1.5 text-xs text-silver-500">(you)</span>}</div><div className="text-xs text-silver-500">{u.email}</div></Td>
                    <Td>{u.roles.map((r) => <Badge key={r.key} className="mr-1">{r.name}</Badge>)}</Td>
                    <Td><Badge tone={statusTone(u.status)}>{u.status}</Badge>{locked && <Badge tone="danger" className="ml-1">locked</Badge>}</Td>
                    <Td>{u.mfa_enabled ? <Badge tone="success">enabled</Badge> : <Badge tone="warning">off</Badge>}</Td>
                    <Td className="text-silver-400">{formatDateTime(u.last_login_at)}</Td>
                    {manage && (
                      <Td>
                        <DM.Root>
                          <DM.Trigger className="rounded p-1 text-silver-500 hover:bg-ink-700 hover:text-silver-100" aria-label={`Actions for ${u.email}`}><MoreHorizontal className="size-4" /></DM.Trigger>
                          <DM.Portal>
                            <DM.Content align="end" className="z-40 w-48 rounded-md border border-ink-600 bg-ink-900 p-1 text-sm shadow-xl">
                              {[
                                { label: 'Change role', show: true, run: () => { rolesM.reset(); setRoleKey(u.roles[0]?.key ?? 'admin'); setRoleEdit(u) } },
                                { label: 'Resend invitation', show: u.status === 'pending', run: () => action.mutate({ id: u.id, op: 'resend-invite' }) },
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

      <Dialog open={inviting} onOpenChange={setInviting} title="Invite administrator" description="The invitee receives a single-use link (valid 72 hours) to set their password.">
        <form onSubmit={submitInvite} className="space-y-3">
          {inviteM.error && <Alert>{describeError(inviteM.error)}</Alert>}
          <Field label="Full name" htmlFor="iname"><Input id="iname" required minLength={2} value={invite.full_name} onChange={(e) => setInvite({ ...invite, full_name: e.target.value })} /></Field>
          <Field label="Work email" htmlFor="iemail"><Input id="iemail" type="email" required value={invite.email} onChange={(e) => setInvite({ ...invite, email: e.target.value })} /></Field>
          <Field label="Role" htmlFor="irole">
            <Select id="irole" className="w-full" value={invite.role} onChange={(e) => setInvite({ ...invite, role: e.target.value })}>
              {ASSIGNABLE.map((k) => <option key={k} value={k}>{roles.data?.find((r) => r.key === k)?.name ?? k}</option>)}
            </Select>
          </Field>
          <div className="flex justify-end"><Button type="submit" loading={inviteM.isPending}>Send invitation</Button></div>
        </form>
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
    </div>
  )
}
