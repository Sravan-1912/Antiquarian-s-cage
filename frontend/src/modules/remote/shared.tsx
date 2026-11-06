import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { XCircle } from 'lucide-react'
import { Alert, Badge, Button, Field, Input } from '@/components/ui/primitives'
import { Dialog } from '@/components/ui/dialog'
import { api, describeError } from '@/services/api'
import type { RemoteSession, SessionStatus } from '@/types/api'

const TONE: Record<SessionStatus, 'success' | 'danger' | 'warning' | 'info' | 'neutral'> = {
  requested: 'info', awaiting_consent: 'info', active: 'warning', ending: 'info', ended: 'neutral',
  denied: 'danger', expired: 'neutral', cancelled: 'neutral', failed: 'danger',
}

export function SessionStatusBadge({ s }: { s: SessionStatus }) {
  return <Badge tone={TONE[s]}>{s.replace('_', ' ')}</Badge>
}

export function TerminateButton({ session, onDone }: { session: RemoteSession; onDone: () => void }) {
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const m = useMutation({
    mutationFn: () => api.post(`/remote-sessions/${session.id}/terminate`, { reason }),
    onSuccess: () => { setOpen(false); setReason(''); onDone() },
  })
  return (
    <>
      <Button size="sm" variant="danger" onClick={() => { m.reset(); setOpen(true) }}><XCircle />End session</Button>
      <Dialog open={open} onOpenChange={setOpen} title="End remote assistance" description="Sends a signed end command; the endpoint closes the indicator and Quick Assist.">
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); m.mutate() }} className="space-y-3">
          {m.error && <Alert>{describeError(m.error)}</Alert>}
          <Field label="Reason" htmlFor="tr"><Input id="tr" required minLength={3} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <div className="flex justify-end"><Button type="submit" variant="danger" loading={m.isPending}>End session</Button></div>
        </form>
      </Dialog>
    </>
  )
}
