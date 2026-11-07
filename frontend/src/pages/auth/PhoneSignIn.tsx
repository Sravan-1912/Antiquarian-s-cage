import { useEffect, useRef, useState } from 'react'
import { Smartphone, ShieldCheck, ShieldX } from 'lucide-react'
import { Button } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'

type Started = { request_id: string; number: number; expires_at: string }
type Status = 'pending' | 'approved' | 'denied' | 'expired' | 'consumed'

/**
 * "Approve on your phone": shows the number the user must pick in Cage Authenticator and waits for the
 * biometric-signed approval. The browser holds an HttpOnly secret for this request, so only this browser can
 * collect the resulting session.
 */
export function PhoneApproval({ email, onApproved, onCancel }: { email: string; onApproved: () => void; onCancel: () => void }) {
  const [req, setReq] = useState<Started | null>(null)
  const [status, setStatus] = useState<Status>('pending')
  const [error, setError] = useState<string | null>(null)
  const [left, setLeft] = useState(120)
  const started = useRef(false)

  async function start() {
    setError(null); setStatus('pending'); setReq(null)
    try {
      const r = await api.post<Started>('/auth/phone/start', { email })
      setReq(r)
    } catch (e) { setError(describeError(e)) }
  }

  useEffect(() => { if (!started.current) { started.current = true; void start() } })  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!req || status !== 'pending') return
    const tick = setInterval(() => setLeft(Math.max(0, Math.round((new Date(req.expires_at).getTime() - Date.now()) / 1000))), 500)
    const poll = setInterval(async () => {
      try {
        const r = await api.post<{ status: Status }>('/auth/phone/status', { request_id: req.request_id })
        if (r.status !== 'pending') {
          setStatus(r.status)
          if (r.status === 'approved') setTimeout(onApproved, 900)
        }
      } catch (e) { setError(describeError(e)); setStatus('expired') }
    }, 2000)
    return () => { clearInterval(tick); clearInterval(poll) }
  }, [req, status, onApproved])

  const approved = status === 'approved'
  const failed = status === 'denied' || status === 'expired' || !!error
  return (
    <div className="space-y-4">
      <div className={`relative overflow-hidden rounded-xl border p-6 text-center transition-colors ${approved ? 'border-emerald-500/60 bg-emerald-950/30' : failed ? 'border-red-500/40 bg-red-950/20' : 'border-ink-600 bg-ink-900/70'}`}>
        <div className={`mx-auto mb-4 grid size-12 place-items-center rounded-xl border ${approved ? 'border-emerald-500/60 bg-emerald-900/40 text-emerald-300' : failed ? 'border-red-500/40 text-red-300' : 'border-emerald-700/50 bg-emerald-950/40 text-emerald-400'}`}>
          {approved ? <ShieldCheck className="size-6" /> : failed ? <ShieldX className="size-6" /> : <Smartphone className="size-6" />}
        </div>
        <h2 className="text-lg font-semibold text-silver-50">
          {approved ? 'Verified' : status === 'denied' ? 'Request declined' : status === 'expired' ? 'Request expired' : 'Approve on your phone'}
        </h2>
        <p className="mx-auto mt-1 max-w-xs text-sm text-silver-400">
          {approved ? 'Identity confirmed on your phone. Signing you in…'
            : status === 'denied' ? 'The request was declined on your phone. If that was not you, tell your security team.'
              : status === 'expired' ? 'No approval arrived in time.'
                : 'Open Cage Authenticator, tap the number shown below, then confirm with your fingerprint or face.'}
        </p>
        {req && !failed && (
          <div className="mt-5">
            <div className="font-mono text-6xl font-bold tracking-tight text-silver-50" aria-label={`Number to select: ${req.number}`}>{req.number}</div>
            <div className="mt-4 inline-flex items-center gap-2 rounded-full border border-ink-600 bg-ink-950/60 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.18em] text-silver-300">
              <span className={`size-1.5 rounded-full ${approved ? 'bg-emerald-400' : 'animate-pulse bg-emerald-500'}`} />
              {approved ? 'Biometric verified' : `Waiting for approval · ${left}s`}
            </div>
          </div>
        )}
        {error && <p className="mt-3 text-sm text-red-300">{error}</p>}
      </div>
      <p className="text-center text-xs text-silver-600">Signing in as <span className="text-silver-300">{email}</span>. No password is typed on this computer.</p>
      <div className="flex gap-2">
        {failed && <Button className="flex-1" onClick={() => void start()}>Send a new request</Button>}
        <Button variant="ghost" className="flex-1" onClick={onCancel}>Use another method</Button>
      </div>
    </div>
  )
}
