import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Plus, Users } from 'lucide-react'
import {
  Alert, Badge, Button, Card, EmptyState, Field, Input, PageHeader, Pagination, Select, Spinner, Table, Td, Th, statusTone,
} from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError, download, qs } from '@/services/api'
import type { Employee, Page } from '@/types/api'
import { formatDate } from '@/utils/format'

export function EmployeeForm({ initial, onSubmit, submitting, error, submitLabel, includeIdentity = true }: {
  initial?: Partial<Employee>
  onSubmit: (body: Record<string, unknown>) => void
  submitting: boolean
  error: string | null
  submitLabel: string
  includeIdentity?: boolean
}) {
  const [f, setF] = useState({
    employee_number: initial?.employee_number ?? '',
    full_name: initial?.full_name ?? '',
    email: initial?.email ?? '',
    department: initial?.department ?? '',
    job_title: initial?.job_title ?? '',
    start_date: initial?.start_date ?? '',
    status: 'active',
  })
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value })
  function submit(e: FormEvent) {
    e.preventDefault()
    const body: Record<string, unknown> = {
      full_name: f.full_name, email: f.email, department: f.department, job_title: f.job_title,
      start_date: f.start_date || null,
    }
    if (includeIdentity) { body.employee_number = f.employee_number; body.status = f.status }
    onSubmit(body)
  }
  return (
    <form onSubmit={submit} className="space-y-3">
      {error && <Alert>{error}</Alert>}
      <div className="grid grid-cols-2 gap-3">
        {includeIdentity && (
          <Field label="Employee ID" htmlFor="eid"><Input id="eid" required pattern="[A-Za-z0-9._\-]+" maxLength={32} value={f.employee_number} onChange={set('employee_number')} /></Field>
        )}
        <Field label="Full name" htmlFor="fn"><Input id="fn" required minLength={2} value={f.full_name} onChange={set('full_name')} /></Field>
        <Field label="Work email" htmlFor="em"><Input id="em" type="email" required value={f.email} onChange={set('email')} /></Field>
        <Field label="Department" htmlFor="dp"><Input id="dp" required value={f.department} onChange={set('department')} /></Field>
        <Field label="Job title" htmlFor="jt"><Input id="jt" required value={f.job_title} onChange={set('job_title')} /></Field>
        <Field label="Start date" htmlFor="sd"><Input id="sd" type="date" value={f.start_date ?? ''} onChange={set('start_date')} /></Field>
        {includeIdentity && (
          <Field label="Initial status" htmlFor="st">
            <Select id="st" className="w-full" value={f.status} onChange={set('status')}>
              <option value="active">Active</option><option value="invited">Invited (not yet started)</option>
            </Select>
          </Field>
        )}
      </div>
      <div className="flex justify-end pt-2"><Button type="submit" loading={submitting}>{submitLabel}</Button></div>
    </form>
  )
}

export function EmployeesPage() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [department, setDepartment] = useState('')
  const [page, setPage] = useState(1)
  const [creating, setCreating] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const params = { q, status, department }

  const list = useQuery({
    queryKey: ['employees', params, page],
    queryFn: () => api.get<Page<Employee>>(`/employees${qs({ ...params, page, page_size: 25 })}`),
    placeholderData: keepPreviousData,
  })
  const depts = useQuery({ queryKey: ['employees', 'departments'], queryFn: () => api.get<string[]>('/employees/departments') })
  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Employee>('/employees', body),
    onSuccess: (emp) => { qc.invalidateQueries({ queryKey: ['employees'] }); setCreating(false); nav(`/employees/${emp.id}`) },
  })

  return (
    <div className="animate-fade-in">
      <PageHeader title="Employees" description="Workforce identities, lifecycle state and joiner / mover / leaver history."
        actions={<>
          {can('reports:export') && <Button variant="outline" size="sm" onClick={() => download(`/employees/export.csv${qs(params)}`, 'employees.csv').catch((e) => setExportError(describeError(e)))}><Download />Export CSV</Button>}
          {can('employees:write') && <Button size="sm" onClick={() => { create.reset(); setCreating(true) }}><Plus />Add employee</Button>}
        </>} />
      {exportError && <div className="mb-3"><Alert>{exportError}</Alert></div>}
      <Card>
        <div className="flex flex-wrap gap-2 border-b border-ink-700 p-3">
          <Input placeholder="Search name, email or ID…" className="max-w-xs" value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} aria-label="Search employees" />
          <Select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }} aria-label="Filter by status">
            <option value="">All statuses</option><option value="active">Active</option><option value="invited">Invited</option>
            <option value="suspended">Suspended</option><option value="offboarded">Offboarded</option>
          </Select>
          <Select value={department} onChange={(e) => { setDepartment(e.target.value); setPage(1) }} aria-label="Filter by department">
            <option value="">All departments</option>
            {depts.data?.map((d) => <option key={d} value={d}>{d}</option>)}
          </Select>
        </div>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : list.error ? <div className="p-4"><Alert>{describeError(list.error)}</Alert></div>
          : !list.data?.items.length ? (
            <EmptyState icon={Users} title={q || status || department ? 'No employees match these filters' : 'No employees yet'}
              description="Employees are the people whose endpoints and application access this console governs."
              action={can('employees:write') && !q && !status && !department ? <Button size="sm" onClick={() => setCreating(true)}><Plus />Add the first employee</Button> : undefined} />
          ) : (
            <>
              <Table>
                <thead><tr><Th>Employee</Th><Th>ID</Th><Th>Department</Th><Th>Title</Th><Th>Status</Th><Th>Endpoint enrolment</Th><Th>Start date</Th></tr></thead>
                <tbody>
                  {list.data.items.map((e) => (
                    <tr key={e.id} className="cursor-pointer hover:bg-ink-850" onClick={() => nav(`/employees/${e.id}`)}>
                      <Td><Link to={`/employees/${e.id}`} className="block text-silver-50 hover:text-emerald-300" onClick={(ev) => ev.stopPropagation()}>{e.full_name}</Link><span className="text-xs text-silver-500">{e.email}</span></Td>
                      <Td className="font-mono text-xs text-silver-400">{e.employee_number}</Td>
                      <Td>{e.department}</Td>
                      <Td className="text-silver-400">{e.job_title}</Td>
                      <Td><Badge tone={statusTone(e.status)}>{e.status}</Badge></Td>
                      <Td className="text-xs text-silver-500">{e.enrollment_status.replace('_', ' ')}</Td>
                      <Td className="text-silver-400">{formatDate(e.start_date)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={page} pageSize={25} total={list.data.total} onPage={setPage} />
            </>
          )}
      </Card>
      <Dialog open={creating} onOpenChange={setCreating} title="Add employee" description="Creates the employee record and logs a joiner event.">
        <EmployeeForm onSubmit={(b) => create.mutate(b)} submitting={create.isPending} error={create.error ? describeError(create.error) : null} submitLabel="Create employee" />
      </Dialog>
    </div>
  )
}
