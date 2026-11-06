import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FileDown, FileSpreadsheet, FileText } from 'lucide-react'
import { Alert, Button, Card, Field, Input, PageHeader, Spinner } from '@/components/ui/primitives'
import { api, describeError, download, qs } from '@/services/api'

interface ReportDef { key: string; title: string; description: string; dated: boolean; available: boolean; requires: string[] }

function iso(d: Date) { return d.toISOString().slice(0, 10) }

export function ReportsPage() {
  const q = useQuery({ queryKey: ['reports'], queryFn: () => api.get<ReportDef[]>('/reports') })
  const today = new Date()
  const [from, setFrom] = useState(iso(new Date(today.getTime() - 30 * 86400_000)))
  const [to, setTo] = useState(iso(today))
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function get(r: ReportDef, format: 'csv' | 'pdf') {
    setBusy(`${r.key}:${format}`)
    setError(null)
    try {
      await download(`/reports/${r.key}${qs({ format, ...(r.dated ? { date_from: from, date_to: to } : {}) })}`, `${r.key}.${format}`)
    } catch (e) {
      setError(describeError(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader title="Reports" description="Generated on demand from live data. Every export is recorded in the audit log." />
      <Card className="flex flex-wrap items-end gap-3 p-4">
        <Field label="From" htmlFor="rf"><Input id="rf" type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
        <Field label="To" htmlFor="rt"><Input id="rt" type="date" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
        <p className="pb-2 text-xs text-silver-500">The period applies to time-based reports (deployments, authentication, audit, alerts). Others are a current snapshot.</p>
      </Card>
      {error && <Alert>{error}</Alert>}
      {q.isLoading ? <Spinner /> : q.error ? <Alert>{describeError(q.error)}</Alert> : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">{q.data!.map((r) => (
          <Card key={r.key} className={`flex flex-col p-4 ${r.available ? '' : 'opacity-60'}`}>
            <div className="flex items-center gap-2"><FileText className="size-4 text-emerald-400" /><span className="text-sm font-medium text-silver-50">{r.title}</span></div>
            <p className="mt-1 text-xs text-silver-500">{r.description}</p>
            <p className="mt-1 text-[11px] text-silver-600">{r.dated ? 'Uses the selected period' : 'Current snapshot'}</p>
            <div className="mt-auto flex gap-2 pt-3">
              {r.available ? <>
                <Button size="sm" variant="secondary" onClick={() => get(r, 'csv')} loading={busy === `${r.key}:csv`}><FileSpreadsheet />CSV</Button>
                <Button size="sm" variant="secondary" onClick={() => get(r, 'pdf')} loading={busy === `${r.key}:pdf`}><FileDown />PDF</Button>
              </> : <span className="text-xs text-silver-500">Requires {r.requires.join(', ')}</span>}
            </div>
          </Card>
        ))}</div>
      )}
    </div>
  )
}
