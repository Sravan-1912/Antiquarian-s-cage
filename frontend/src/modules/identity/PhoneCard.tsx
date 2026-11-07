import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { Smartphone, Trash2 } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Spinner } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'
import { formatDateTime } from '@/utils/format'

type Phone = { id: string; name: string; platform: string; key_alg: string; created_at: string; last_used_at: string | null }
type Pairing = { payload: Record<string, unknown>; expires_at: string }

/** Pair Cage Authenticator: one-time QR (5 min). The phone proves possession of its biometric key while pairing. */
export function PhoneCard() {
  const qc = useQueryClient()
  const phones = useQuery({ queryKey: ['phones'], queryFn: () => api.get<Phone[]>('/me/phone-authenticators') })
  const [pairing, setPairing] = useState<Pairing | null>(null)
  const [qr, setQr] = useState<string | null>(null)
  const [left, setLeft] = useState(0)
  const [msg, setMsg] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null)
  const known = phones.data?.length ?? 0

  const start = useMutation({
    mutationFn: () => api.post<Pairing>('/me/phone-authenticators/pairing'),
    onSuccess: (p) => { setMsg(null); setPairing(p) },
    onError: (e) => setMsg({ tone: 'danger', text: describeError(e) }),
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/me/phone-authenticators/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['phones'] }); setMsg({ tone: 'success', text: 'Phone removed. It can no longer approve sign-ins.' }) },
    onError: (e) => setMsg({ tone: 'danger', text: describeError(e) }),
  })

  useEffect(() => {
    if (!pairing) { setQr(null); return }
    QRCode.toDataURL(JSON.stringify(pairing.payload), { margin: 1, width: 220, errorCorrectionLevel: 'M', color: { dark: '#0d0e10', light: '#eceef0' } }).then(setQr)
    const t = setInterval(() => {
      const s = Math.max(0, Math.round((new Date(pairing.expires_at).getTime() - Date.now()) / 1000))
      setLeft(s)
      if (s === 0) setPairing(null)
    }, 500)
    // Watch for the phone completing the pairing.
    const poll = setInterval(async () => {
      const list = await api.get<Phone[]>('/me/phone-authenticators').catch(() => null)
      if (list && list.length > known) {
        setPairing(null)
        qc.setQueryData(['phones'], list)
        setMsg({ tone: 'success', text: `${list[list.length - 1].name} paired. You can now sign in by approving on your phone.` })
      }
    }, 2000)
    return () => { clearInterval(t); clearInterval(poll) }
  }, [pairing, known, qc])

  return (
    <Card>
      <CardHeader title="Phone authenticator" description="Approve sign-ins on your phone with fingerprint or face. No password is typed on the computer."
        action={known ? <Badge tone="success">{known} paired</Badge> : <Badge tone="warning">Not paired</Badge>} />
      <div className="space-y-3 p-4">
        {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
        {phones.isLoading ? <Spinner /> : phones.data && phones.data.length > 0 && (
          <ul className="divide-y divide-ink-700 rounded-md border border-ink-700">
            {phones.data.map((p) => (
              <li key={p.id} className="flex items-center gap-3 px-3 py-2.5">
                <Smartphone className="size-4 text-emerald-400" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-silver-100">{p.name}</div>
                  <div className="text-xs text-silver-500">{p.platform} · paired {formatDateTime(p.created_at)} · {p.last_used_at ? `last used ${formatDateTime(p.last_used_at)}` : 'not used yet'}</div>
                </div>
                <Button size="sm" variant="ghost" onClick={() => remove.mutate(p.id)} loading={remove.isPending && remove.variables === p.id} aria-label={`Remove ${p.name}`}><Trash2 />Remove</Button>
              </li>
            ))}
          </ul>
        )}
        {pairing ? (
          <div className="grid gap-4 sm:grid-cols-[auto_1fr] sm:items-center">
            <div className="rounded-md bg-silver-50 p-1.5">{qr ? <img src={qr} alt="Phone pairing QR code" className="size-52" /> : <div className="grid size-52 place-items-center"><Spinner /></div>}</div>
            <div className="space-y-2 text-sm text-silver-300">
              <ol className="list-decimal space-y-1 pl-5">
                <li>Install and open <span className="font-medium text-silver-100">Cage Authenticator</span> on your phone.</li>
                <li>Tap <span className="font-medium text-silver-100">Pair with console</span> and scan this code.</li>
                <li>Confirm with your fingerprint or face.</li>
              </ol>
              <p className="text-xs text-silver-500">Single use · expires in {left}s · waiting for your phone…</p>
              <Button size="sm" variant="ghost" onClick={() => setPairing(null)}>Cancel</Button>
            </div>
          </div>
        ) : (
          <Button onClick={() => start.mutate()} loading={start.isPending}><Smartphone />{known ? 'Pair another phone' : 'Pair a phone'}</Button>
        )}
      </div>
    </Card>
  )
}
