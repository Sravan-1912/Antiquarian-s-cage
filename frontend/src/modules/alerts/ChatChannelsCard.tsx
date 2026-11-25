import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Send, Trash2 } from 'lucide-react'
import { Alert, Badge, Button, Card, CardHeader, Input, Select, Spinner } from '@/components/ui/primitives'
import { api, describeError } from '@/services/api'

interface ChatHook { platform: string; enabled: boolean; min_severity: string; configured: boolean; last_error: string | null; last_success_at: string | null }
const PLATFORMS: { id: string; name: string; hint: string }[] = [
  { id: 'slack', name: 'Slack', hint: 'https://hooks.slack.com/services/…' },
  { id: 'teams', name: 'Microsoft Teams', hint: 'Teams incoming-webhook URL' },
  { id: 'discord', name: 'Discord', hint: 'https://discord.com/api/webhooks/…' },
  { id: 'generic', name: 'Generic webhook', hint: 'Any URL — receives the raw alert JSON' },
]

function ChannelRow({ platform, name, hint, hook }: { platform: string; name: string; hint: string; hook?: ChatHook }) {
  const qc = useQueryClient()
  const [url, setUrl] = useState('')
  const [enabled, setEnabled] = useState(hook?.enabled ?? true)
  const [minSev, setMinSev] = useState(hook?.min_severity ?? 'high')
  const [tested, setTested] = useState<null | boolean>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: ['chat-webhooks'] })

  const save = useMutation({
    mutationFn: () => api.put('/chat-webhooks', { platform, enabled, min_severity: minSev, ...(url ? { url } : {}) }),
    onSuccess: () => { setUrl(''); refresh() },
  })
  const test = useMutation({
    mutationFn: () => api.post<{ ok: boolean; error?: string }>(`/chat-webhooks/${platform}/test`, {}),
    onSuccess: (r) => setTested(r.ok),
  })
  const remove = useMutation({ mutationFn: () => api.del(`/chat-webhooks/${platform}`), onSuccess: refresh })

  return (
    <div className="border-t border-ink-800 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-32 text-sm font-medium text-silver-100">{name}</div>
        {hook?.configured ? <Badge tone="success">connected</Badge> : <Badge tone="neutral">not set</Badge>}
        {hook?.last_error && <Badge tone="danger" title={hook.last_error}>last post failed</Badge>}
        {tested === true && <span className="text-xs text-emerald-400">test sent ✓</span>}
        {tested === false && <span className="text-xs text-red-400">test failed</span>}
        <div className="ml-auto flex items-center gap-2">
          <Select className="h-8 text-xs" value={minSev} onChange={(e) => setMinSev(e.target.value)} aria-label={`${name} min severity`}>
            <option value="low">Low+</option><option value="medium">Medium+</option><option value="high">High+</option><option value="critical">Critical only</option>
          </Select>
          <button type="button" role="switch" aria-checked={enabled} aria-label={`${name} enabled`} onClick={() => setEnabled(!enabled)}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${enabled ? 'bg-[color:var(--cage-accent)]' : 'bg-ink-600'}`}>
            <span className={`inline-block size-4 rounded-full bg-white transition ${enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
          </button>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Input className="min-w-0 flex-1" type="url" placeholder={hook?.configured ? 'Leave blank to keep saved URL' : hint}
          value={url} onChange={(e) => setUrl(e.target.value)} aria-label={`${name} webhook URL`} />
        <Button size="sm" loading={save.isPending} onClick={() => save.mutate()}><Check />Save</Button>
        {hook?.configured && <Button size="sm" variant="outline" loading={test.isPending} onClick={() => test.mutate()}><Send />Test</Button>}
        {hook?.configured && <Button size="sm" variant="ghost" loading={remove.isPending} onClick={() => remove.mutate()}><Trash2 /></Button>}
      </div>
      {save.error && <div className="mt-2"><Alert>{describeError(save.error)}</Alert></div>}
    </div>
  )
}

export function ChatChannelsCard() {
  const q = useQuery({ queryKey: ['chat-webhooks'], queryFn: () => api.get<ChatHook[]>('/chat-webhooks') })
  const byPlatform = new Map((q.data ?? []).map((h) => [h.platform, h]))
  return (
    <Card>
      <CardHeader title="Chat alert channels" description="Post security alerts to Slack, Teams, Discord, or any webhook. Each channel fires at or above its chosen severity; URLs are stored encrypted." />
      {q.isLoading ? <div className="grid h-24 place-items-center"><Spinner /></div> : (
        <div>{PLATFORMS.map((p) => <ChannelRow key={p.id} platform={p.id} name={p.name} hint={p.hint} hook={byPlatform.get(p.id)} />)}</div>
      )}
    </Card>
  )
}
