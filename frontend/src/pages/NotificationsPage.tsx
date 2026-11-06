import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Bell } from 'lucide-react'
import { Badge, Button, Card, EmptyState, PageHeader, Spinner } from '@/components/ui/primitives'
import { api } from '@/services/api'
import type { NotificationItem } from '@/types/api'
import { cn, formatDateTime } from '@/utils/format'

export function NotificationsPage() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['notifications', 'list'], queryFn: () => api.get<NotificationItem[]>('/notifications') })
  const inv = () => qc.invalidateQueries({ queryKey: ['notifications'] })
  const readAll = useMutation({ mutationFn: () => api.post('/notifications/read-all'), onSuccess: inv })
  const readOne = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: inv })
  return (
    <div className="animate-fade-in">
      <PageHeader title="Notifications" description="In-app alerts addressed to you."
        actions={<Button size="sm" variant="outline" onClick={() => readAll.mutate()} loading={readAll.isPending}>Mark all read</Button>} />
      <Card>
        {list.isLoading ? <div className="p-6"><Spinner /></div> : !list.data?.length ? <EmptyState icon={Bell} title="No notifications" /> : (
          <ul className="divide-y divide-ink-800">
            {list.data.map((n) => (
              <li key={n.id} className={cn('flex items-start gap-3 px-4 py-3', !n.read_at && 'bg-ink-850')}>
                <span className={cn('mt-1.5 size-2 shrink-0 rounded-full', n.read_at ? 'bg-ink-600' : 'bg-emerald-400')} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2"><span className="text-sm text-silver-100">{n.title}</span><Badge tone={n.severity === 'high' ? 'danger' : n.severity === 'medium' ? 'warning' : 'neutral'}>{n.severity}</Badge></div>
                  {n.body && <p className="mt-0.5 text-xs text-silver-400">{n.body}</p>}
                  <div className="mt-1 text-[11px] text-silver-600">{formatDateTime(n.created_at)}</div>
                </div>
                <div className="flex gap-1">
                  {n.link && <Button asChild size="sm" variant="ghost"><Link to={n.link} onClick={() => !n.read_at && readOne.mutate(n.id)}>Open</Link></Button>}
                  {!n.read_at && <Button size="sm" variant="ghost" onClick={() => readOne.mutate(n.id)}>Mark read</Button>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
