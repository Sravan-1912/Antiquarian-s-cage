import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { Dialog } from '@/components/ui/dialog'
import { Alert } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'

type Status = 'connecting' | 'open' | 'closed' | 'error'

/**
 * Operator terminal for a live-response shell. Attaches to the endpoint over the backend relay (the same mode-agnostic
 * byte relay RDP uses) and renders it with xterm.js. v1 is plaintext over the relay (the browser's Web Crypto has no
 * ChaCha20-Poly1305 for the E2E path); the agent still writes every command to the audit trail.
 */
export function ShellTerminal({ sessionId, hostname, onClose }: { sessionId: string; hostname: string; onClose: () => void }) {
  const mount = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<Status>('connecting')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let disposed = false
    let term: Terminal | null = null
    let ws: WebSocket | null = null
    const enc = new TextEncoder()

    const run = async () => {
      try {
        const t = await api.post<{ operator_token: string; tunnel_path: string }>(`/remote-sessions/${sessionId}/shell-connect`)
        if (disposed || !mount.current) return
        term = new Terminal({ fontSize: 13, fontFamily: 'ui-monospace, Menlo, Consolas, monospace', cursorBlink: true,
          theme: { background: '#0a0f1a', foreground: '#cdd9ee', cursor: '#5aa6ff' } })
        const fit = new FitAddon()
        term.loadAddon(fit)
        term.open(mount.current)
        try { fit.fit() } catch { /* not laid out yet */ }
        const base = window.location.origin.replace(/^http/, 'ws')
        ws = new WebSocket(`${base}${t.tunnel_path}?session=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(t.operator_token)}`)
        ws.binaryType = 'arraybuffer'
        ws.onopen = () => setStatus('open')
        ws.onclose = () => setStatus((s) => (s === 'error' ? s : 'closed'))
        ws.onerror = () => setStatus('error')
        ws.onmessage = (e) => { if (term) term.write(typeof e.data === 'string' ? e.data : new Uint8Array(e.data as ArrayBuffer)) }
        term.onData((d) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d)) })
        const onResize = () => { try { fit.fit() } catch { /* ignore */ } }
        window.addEventListener('resize', onResize)
        ;(term as unknown as { _cageCleanup?: () => void })._cageCleanup = () => window.removeEventListener('resize', onResize)
      } catch (e) {
        if (!disposed) { setError(describeError(e)); setStatus('error') }
      }
    }
    run()
    return () => {
      disposed = true
      try { ws?.close() } catch { /* ignore */ }
      try { (term as unknown as { _cageCleanup?: () => void } | null)?._cageCleanup?.() } catch { /* ignore */ }
      try { term?.dispose() } catch { /* ignore */ }
    }
  }, [sessionId])

  const note = { connecting: 'Connecting to the endpoint…', open: 'Connected · every command is audited', closed: 'Session closed', error: error ?? 'Connection error' }[status]
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }} title={`Live-response shell — ${hostname}`}
      description="Interactive shell on the endpoint, relayed over the backend. Arbitrary commands run as the logged-in user and are audited.">
      <div className="space-y-2">
        <Alert tone={status === 'error' ? 'danger' : status === 'open' ? 'success' : 'info'}>{note}</Alert>
        <div ref={mount} className="h-[420px] w-full overflow-hidden rounded-md border border-ink-700 bg-[#0a0f1a] p-1" />
        <p className="text-xs text-silver-600">A banner is shown on the endpoint for the whole session. Close this dialog or end the session to disconnect.</p>
      </div>
    </Dialog>
  )
}
