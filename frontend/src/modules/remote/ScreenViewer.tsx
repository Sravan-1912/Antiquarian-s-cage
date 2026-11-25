import { useEffect, useRef, useState } from 'react'
import { Dialog } from '@/components/ui/dialog'
import { Alert } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'

type Status = 'connecting' | 'open' | 'closed' | 'error'

/**
 * Operator viewer for an agent-driven remote-screen session. The endpoint's agent captures the screen and injects
 * input, tunnelled over the backend relay — so it works on any Windows edition (incl. Home) and across any network,
 * with no RDP host. Frames arrive as JPEG (opcode 0x01) with one meta frame (0x02 {w,h}); we send mouse/keyboard as
 * JSON. A banner is shown on the endpoint for the whole session.
 */
export function ScreenViewer({ sessionId, hostname, onClose }: { sessionId: string; hostname: string; onClose: () => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const [status, setStatus] = useState<Status>('connecting')
  const [error, setError] = useState<string | null>(null)
  const [dims, setDims] = useState<{ w: number; h: number }>({ w: 1280, h: 720 })

  useEffect(() => {
    let disposed = false
    let ws: WebSocket | null = null
    let lastMove = 0

    const send = (obj: unknown) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)) }

    const run = async () => {
      try {
        const t = await api.post<{ operator_token: string; tunnel_path: string }>(`/remote-sessions/${sessionId}/screen-connect`)
        if (disposed) return
        const base = window.location.origin.replace(/^http/, 'ws')
        ws = new WebSocket(`${base}${t.tunnel_path}?session=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(t.operator_token)}`)
        wsRef.current = ws
        ws.binaryType = 'arraybuffer'
        ws.onopen = () => setStatus('open')
        ws.onclose = () => setStatus((s) => (s === 'error' ? s : 'closed'))
        ws.onerror = () => setStatus('error')
        ws.onmessage = async (e) => {
          if (typeof e.data === 'string') return
          const bytes = new Uint8Array(e.data as ArrayBuffer)
          const op = bytes[0]
          const body = bytes.subarray(1)
          if (op === 0x02) {
            try { const meta = JSON.parse(new TextDecoder().decode(body)); if (meta.w && meta.h) setDims({ w: meta.w, h: meta.h }) } catch { /* ignore */ }
          } else if (op === 0x01) {
            const canvas = canvasRef.current
            if (!canvas) return
            try {
              const bmp = await createImageBitmap(new Blob([body], { type: 'image/jpeg' }))
              const ctx = canvas.getContext('2d')
              if (ctx) ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height)
              bmp.close()
            } catch { /* drop a bad frame */ }
          }
        }
      } catch (e) {
        if (!disposed) { setError(describeError(e)); setStatus('error') }
      }
    }
    run()

    // input: map pointer position on the canvas to normalized [0,1] coords the agent scales to the real screen
    const norm = (ev: { clientX: number; clientY: number }) => {
      const c = canvasRef.current
      if (!c) return null
      const r = c.getBoundingClientRect()
      return { x: Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width)), y: Math.min(1, Math.max(0, (ev.clientY - r.top) / r.height)) }
    }
    const onMove = (ev: MouseEvent) => { const now = performance.now(); if (now - lastMove < 33) return; lastMove = now; const p = norm(ev); if (p) send({ t: 'm', ...p, e: 'move' }) }
    const onDown = (ev: MouseEvent) => { const p = norm(ev); if (p) send({ t: 'm', ...p, b: ev.button, e: 'down' }) }
    const onUp = (ev: MouseEvent) => { const p = norm(ev); if (p) send({ t: 'm', ...p, b: ev.button, e: 'up' }) }
    const onWheel = (ev: WheelEvent) => { ev.preventDefault(); send({ t: 'scroll', dy: ev.deltaY }) }
    const onCtx = (ev: Event) => ev.preventDefault()
    const onKey = (ev: KeyboardEvent) => {
      ev.preventDefault(); ev.stopPropagation()  // forward the key to the endpoint (and don't let Radix close on Escape)
      send({ t: 'k', code: ev.code, key: ev.key, e: ev.type === 'keyup' ? 'up' : 'down' })
    }
    const c = canvasRef.current
    c?.addEventListener('mousemove', onMove)
    c?.addEventListener('mousedown', onDown)
    c?.addEventListener('mouseup', onUp)
    c?.addEventListener('wheel', onWheel, { passive: false })
    c?.addEventListener('contextmenu', onCtx)
    c?.addEventListener('keydown', onKey)
    c?.addEventListener('keyup', onKey)

    return () => {
      disposed = true
      c?.removeEventListener('mousemove', onMove)
      c?.removeEventListener('mousedown', onDown)
      c?.removeEventListener('mouseup', onUp)
      c?.removeEventListener('wheel', onWheel)
      c?.removeEventListener('contextmenu', onCtx)
      c?.removeEventListener('keydown', onKey)
      c?.removeEventListener('keyup', onKey)
      try { ws?.close() } catch { /* ignore */ }
      wsRef.current = null
    }
  }, [sessionId])

  const note = { connecting: 'Connecting to the endpoint…', open: 'Connected · click the screen to control it · every session is audited', closed: 'Session closed', error: error ?? 'Connection error' }[status]
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }} title={`Remote screen — ${hostname}`} className="max-w-5xl"
      description="Live screen of the endpoint, relayed over the backend. Click to focus, then use your mouse and keyboard to control it. A banner is shown on the endpoint for the whole session.">
      <div className="space-y-2">
        <Alert tone={status === 'error' ? 'danger' : status === 'open' ? 'success' : 'info'}>{note}</Alert>
        <div className="grid w-full place-items-center overflow-hidden rounded-md border border-ink-700 bg-black">
          <canvas
            ref={canvasRef} width={dims.w} height={dims.h} tabIndex={0}
            className="max-h-[70vh] w-full cursor-crosshair object-contain outline-none"
            style={{ aspectRatio: `${dims.w} / ${dims.h}` }}
          />
        </div>
        <p className="text-xs text-silver-600">Works on any Windows edition — the agent streams the screen and injects your input. Close this dialog or end the session to disconnect.</p>
      </div>
    </Dialog>
  )
}
