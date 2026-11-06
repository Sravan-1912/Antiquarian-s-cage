import { Fragment, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Anchor, ChevronDown, ChevronRight, Download, ShieldCheck, ShieldX } from 'lucide-react'
import { Alert, Badge, Button, Card, Input, PageHeader, Pagination, Select, Spinner, Table, Td, Th, statusTone } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api, describeError, download, qs } from '@/services/api'
import type { AuditAnchor, AuditEntry, AuditVerify, Page } from '@/types/api'
import { formatDateTime } from '@/utils/format'

export function AuditPage() {
  const { can } = useAuth()
  const [filters, setFilters] = useState({ action: '', actor: '', result: '', date_from: '', date_to: '' })
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<string | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const set = (k: keyof typeof filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => { setFilters({ ...filters, [k]: e.target.value }); setPage(1) }

  const list = useQuery({ queryKey: ['audit', filters, page], queryFn: () => api.get<Page<AuditEntry>>(`/audit${qs({ ...filters, page, page_size: 50 })}`), placeholderData: keepPreviousData })
  const actions = useQuery({ queryKey: ['audit', 'actions'], queryFn: () => api.get<string[]>('/audit/actions') })
  const verify = useMutation({ mutationFn: () => api.post<AuditVerify>('/audit/verify') })
  const qc = useQueryClient()
  const anchors = useQuery({ queryKey: ['audit', 'anchors'], queryFn: () => api.get<AuditAnchor[]>('/audit/anchors'), enabled: can('audit:verify') })
  const anchorNow = useMutation({
    mutationFn: () => api.post<AuditAnchor | null>('/audit/anchors'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['audit'] }) },
  })
  const lastAnchor = anchors.data?.[0]

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Audit log" description="Append-only, hash-chained record of privileged and security-relevant actions."
        actions={<>
          {can('reports:export') && <Button size="sm" variant="outline" onClick={() => download(`/audit/export.csv${qs(filters)}`, 'audit-log.csv').catch((e) => setExportError(describeError(e)))}><Download />Export CSV</Button>}
          {can('audit:verify') && <Button size="sm" variant="outline" onClick={() => anchorNow.mutate()} loading={anchorNow.isPending}><Anchor />Anchor now</Button>}
          {can('audit:verify') && <Button size="sm" onClick={() => verify.mutate()} loading={verify.isPending}><ShieldCheck />Verify integrity</Button>}
        </>} />
      {anchorNow.error && <Alert>{describeError(anchorNow.error)}</Alert>}
      {can('audit:verify') && anchors.data && (
        lastAnchor ? (
          <p className="text-xs text-ink-300">
            Last anchor: record #{lastAnchor.seq} at {formatDateTime(lastAnchor.created_at)} ({lastAnchor.key_id})
            {lastAnchor.external_written
              ? ' — written to external anchor storage.'
              : <span className="text-red-400"> — external write failed: {lastAnchor.external_error}. Truncation is not detectable from outside until fixed.</span>}
          </p>
        ) : <p className="text-xs text-ink-300">No anchors yet — the scheduler anchors the chain head hourly, or use “Anchor now”.</p>
      )}
      {exportError && <Alert>{exportError}</Alert>}
      {verify.error && <Alert>{describeError(verify.error)}</Alert>}
      {verify.data && (verify.data.valid ? (
        <Alert tone="success">
          <span className="inline-flex items-center gap-1.5 font-medium"><ShieldCheck className="size-4" />Chain intact</span> — {verify.data.checked} records verified at {formatDateTime(verify.data.verified_at)}.
          Head #{verify.data.head_seq}: <code className="font-mono text-xs">{verify.data.head_hash?.slice(0, 16)}…</code>
          {verify.data.anchors && <span className="mt-1 block text-xs opacity-80">{verify.data.anchors.anchors_checked} anchors checked ({verify.data.anchors.external_anchors} in external storage); no truncation or rewrite detected.</span>}
        </Alert>
      ) : (
        <Alert tone="danger"><span className="inline-flex items-center gap-1.5 font-medium"><ShieldX className="size-4" />Integrity failure</span> {verify.data.first_invalid_seq != null && <> at record #{verify.data.first_invalid_seq}</>}: {verify.data.reason}. Treat this as a security incident.
          {verify.data.anchors && verify.data.anchors.problems.length > 0 && <ul className="mt-1 list-disc pl-5 text-xs">{verify.data.anchors.problems.map((p) => <li key={p}>{p}</li>)}</ul>}
        </Alert>
      ))}
      <Card>
        <div className="flex flex-wrap gap-2 border-b border-ink-700 p-3">
          <Select value={filters.action} onChange={set('action')} aria-label="Action"><option value="">All actions</option>{actions.data?.map((a) => <option key={a}>{a}</option>)}</Select>
          <Input placeholder="Actor email…" className="max-w-[200px]" value={filters.actor} onChange={set('actor')} aria-label="Actor" />
          <Select value={filters.result} onChange={set('result')} aria-label="Result"><option value="">Any result</option><option>success</option><option>failure</option><option>denied</option></Select>
          <Input type="date" className="w-auto" value={filters.date_from} onChange={set('date_from')} aria-label="From date" />
          <Input type="date" className="w-auto" value={filters.date_to} onChange={set('date_to')} aria-label="To date" />
        </div>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : list.error ? <div className="p-4"><Alert>{describeError(list.error)}</Alert></div> : (
          <>
            <Table>
              <thead><tr><Th className="w-6" /><Th>#</Th><Th>Time</Th><Th>Actor</Th><Th>Action</Th><Th>Target</Th><Th>Result</Th><Th>Source IP</Th></tr></thead>
              <tbody>
                {list.data!.items.map((a) => (
                  <Fragment key={a.id}>
                    <tr className="cursor-pointer hover:bg-ink-850" onClick={() => setOpen(open === a.id ? null : a.id)}>
                      <Td>{open === a.id ? <ChevronDown className="size-3.5 text-silver-500" /> : <ChevronRight className="size-3.5 text-silver-500" />}</Td>
                      <Td className="font-mono text-xs text-silver-500">{a.seq}</Td>
                      <Td className="whitespace-nowrap text-silver-400">{formatDateTime(a.created_at)}</Td>
                      <Td className="max-w-[200px] truncate">{a.actor_label}</Td>
                      <Td><code className="text-xs text-silver-100">{a.action}</code></Td>
                      <Td className="max-w-[220px] truncate text-silver-400">{a.target_label ?? '—'}</Td>
                      <Td><Badge tone={statusTone(a.result)}>{a.result}</Badge></Td>
                      <Td className="font-mono text-xs">{a.source_ip ?? '—'}</Td>
                    </tr>
                    {open === a.id && (
                      <tr className="bg-ink-950/60">
                        <Td colSpan={8}>
                          <div className="grid gap-3 py-1 text-xs md:grid-cols-2">
                            <div><div className="mb-1 text-silver-500">Metadata</div><pre className="overflow-x-auto rounded bg-ink-900 p-2 font-mono text-[11px] text-silver-300">{JSON.stringify(a.metadata, null, 2)}</pre></div>
                            <div className="space-y-1.5 font-mono text-[11px]">
                              <div><span className="text-silver-500">target </span>{a.target_type ?? '—'} {a.target_id ?? ''}</div>
                              <div className="break-all"><span className="text-silver-500">prev_hash </span>{a.prev_hash}</div>
                              <div className="break-all"><span className="text-silver-500">hash </span><span className="text-emerald-300">{a.hash}</span></div>
                            </div>
                          </div>
                        </Td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </Table>
            <Pagination page={page} pageSize={50} total={list.data!.total} onPage={setPage} />
          </>
        )}
      </Card>
    </div>
  )
}
