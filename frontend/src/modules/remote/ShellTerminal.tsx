import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { CornerDownLeft } from 'lucide-react'
import { Dialog } from '@/components/ui/dialog'
import { Alert } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'

type Status = 'connecting' | 'open' | 'closed' | 'error'

// Sentinel the frontend injects after each command to read back the endpoint's current directory, so we can show a
// real prompt even though PowerShell's `-Command -` stdin mode never prints one. \x01 is a control char that never
// appears in normal shell output, so it is safe to strip.
const M = '\x01'
const CWD_QUERY = `[Console]::Out.Write([char]1 + 'CWD:' + (Get-Location).Path + [char]1)`

/**
 * Operator terminal for a live-response shell. Attaches to the endpoint over the backend relay and renders output with
 * xterm.js. Input is a compose box: type a command (multi-line allowed) and press Ctrl+Enter to run it — the command
 * is echoed into the log and the prompt shows the endpoint's live working directory. The agent audits every command.
 */
export function ShellTerminal({ sessionId, hostname, onClose }: { sessionId: string; hostname: string; onClose: () => void }) {
  const mount = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const [status, setStatus] = useState<Status>('connecting')
  const [error, setError] = useState<string | null>(null)
  const [cwd, setCwd] = useState('PS')

  useEffect(() => {
    let disposed = false
    let term: Terminal | null = null
    let ws: WebSocket | null = null
    const enc = new TextEncoder()
    const dec = new TextDecoder()
    let pending = ''  // holds a partial \x01…\x01 marker split across frames

    const handle = (chunk: string) => {
      pending += chunk
      let out = ''
      for (;;) {
        const i = pending.indexOf(M)
        if (i === -1) { out += pending; pending = ''; break }
        out += pending.slice(0, i)
        const j = pending.indexOf(M, i + 1)
        if (j === -1) { pending = pending.slice(i); break }  // marker not complete yet — keep it buffered
        const tok = pending.slice(i + 1, j)
        if (tok.startsWith('CWD:')) setCwd(tok.slice(4))
        pending = pending.slice(j + 1)
      }
      if (out && term) term.write(out)
    }

    const run = async () => {
      try {
        const t = await api.post<{ operator_token: string; tunnel_path: string }>(`/remote-sessions/${sessionId}/shell-connect`)
        if (disposed || !mount.current) return
        term = new Terminal({ fontSize: 13, fontFamily: 'ui-monospace, Menlo, Consolas, monospace', cursorBlink: false,
          disableStdin: true, convertEol: true,
          theme: { background: '#0a0f1a', foreground: '#cdd9ee', cursor: '#5aa6ff' } })
        termRef.current = term
        const fit = new FitAddon()
        term.loadAddon(fit)
        term.open(mount.current)
        try { fit.fit() } catch { /* not laid out yet */ }
        const base = window.location.origin.replace(/^http/, 'ws')
        ws = new WebSocket(`${base}${t.tunnel_path}?session=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(t.operator_token)}`)
        wsRef.current = ws
        ws.binaryType = 'arraybuffer'
        ws.onopen = () => {
          setStatus('open')
          ws?.send(enc.encode(CWD_QUERY + '\n'))  // prime the prompt with the starting directory
          inputRef.current?.focus()
        }
        ws.onclose = () => setStatus((s) => (s === 'error' ? s : 'closed'))
        ws.onerror = () => setStatus('error')
        ws.onmessage = (e) => handle(typeof e.data === 'string' ? e.data : dec.decode(new Uint8Array(e.data as ArrayBuffer), { stream: true }))
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
      termRef.current = null
      wsRef.current = null
    }
  }, [sessionId])

  const send = () => {
    const ta = inputRef.current
    const ws = wsRef.current
    const term = termRef.current
    if (!ta || !ws || ws.readyState !== WebSocket.OPEN) return
    const cmd = ta.value
    if (!cmd.trim()) return
    // Echo the command into the log with the prompt, then run it and re-query the directory.
    term?.write(`\r\n\x1b[36m${cwd}>\x1b[0m ${cmd}\r\n`)
    ws.send(new TextEncoder().encode(cmd + '\n' + CWD_QUERY + '\n'))
    ta.value = ''
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send() }
  }

  const note = { connecting: 'Connecting to the endpoint…', open: 'Connected · every command is audited', closed: 'Session closed', error: error ?? 'Connection error' }[status]
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }} title={`Live-response shell — ${hostname}`}
      description="Interactive shell on the endpoint, relayed over the backend. Type a command and press Ctrl+Enter to run it. Arbitrary commands run as the logged-in user and are audited.">
      <div className="space-y-2">
        <Alert tone={status === 'error' ? 'danger' : status === 'open' ? 'success' : 'info'}>{note}</Alert>
        <div ref={mount} className="h-[340px] w-full overflow-hidden rounded-md border border-ink-700 bg-[#0a0f1a] p-1" />
        <div className="rounded-md border border-ink-700 bg-[#0a0f1a]">
          <div className="flex items-center gap-2 border-b border-ink-800 px-2.5 py-1 font-mono text-xs text-sky-300">
            <span className="truncate">{cwd}&gt;</span>
          </div>
          <textarea
            ref={inputRef} rows={2} spellCheck={false} disabled={status !== 'open'}
            onKeyDown={onKeyDown} placeholder={status === 'open' ? 'Type a command, then Ctrl+Enter to run…' : 'Waiting for the session…'}
            className="w-full resize-none bg-transparent px-2.5 py-2 font-mono text-sm text-silver-100 placeholder:text-silver-600 focus:outline-none disabled:opacity-50"
          />
        </div>
        <div className="flex items-center justify-between text-xs text-silver-600">
          <span>A banner is shown on the endpoint for the whole session. Close this dialog or end the session to disconnect.</span>
          <button type="button" onClick={send} disabled={status !== 'open'}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-ink-600 px-2 py-1 text-silver-200 hover:bg-ink-800 disabled:opacity-40">
            Run <kbd className="rounded bg-ink-700 px-1">Ctrl</kbd>+<CornerDownLeft className="size-3" />
          </button>
        </div>
      </div>
    </Dialog>
  )
}
