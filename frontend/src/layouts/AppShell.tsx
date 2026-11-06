import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import * as DM from '@radix-ui/react-dropdown-menu'
import {
  AppWindow, Bell, Briefcase, FileBarChart, ShieldAlert, ChevronDown, ClipboardCheck, FileLock2, Headset, LaptopMinimal, LayoutDashboard, LogOut, Menu, ScrollText, Search, ShieldCheck, UserCog, Users, X,
} from 'lucide-react'
import { Wordmark } from '@/components/Logo'
import { Badge, Spinner } from '@/components/ui/primitives'
import { useAuth } from '@/hooks/useAuth'
import { api } from '@/services/api'
import type { NotificationItem, SearchHit } from '@/types/api'
import { cn, relativeTime } from '@/utils/format'

interface NavItem { to: string; label: string; icon: React.ComponentType<{ className?: string }>; perm?: string; anyPerm?: string[] }

// Only modules that are implemented appear here; later phases add their entries when their backend exists.
const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: 'Overview',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard, perm: 'dashboard:read' },
      { to: '/workspace', label: 'My workspace', icon: Briefcase, perm: 'self:read' },
    ],
  },
  {
    section: 'Endpoints',
    items: [
      { to: '/endpoints', label: 'Endpoints', icon: LaptopMinimal, anyPerm: ['devices:read', 'devices:read_assigned'] },
      { to: '/remote-sessions', label: 'Remote sessions', icon: Headset, anyPerm: ['devices:read', 'devices:read_assigned'] },
    ],
  },
  {
    section: 'Security',
    items: [
      { to: '/alerts', label: 'Alerts', icon: ShieldAlert, perm: 'alerts:read' },
      { to: '/policies', label: 'Policies', icon: FileLock2, perm: 'policies:read' },
      { to: '/compliance', label: 'Compliance', icon: ClipboardCheck, perm: 'compliance:read' },
      { to: '/applications', label: 'Applications (SSO)', icon: AppWindow, perm: 'applications:read' },
    ],
  },
  { section: 'Workforce', items: [{ to: '/employees', label: 'Employees', icon: Users, perm: 'employees:read' }] },
  {
    section: 'Governance',
    items: [
      { to: '/administrators', label: 'Administrators', icon: UserCog, perm: 'users:read' },
      { to: '/audit', label: 'Audit log', icon: ScrollText, perm: 'audit:read' },
      { to: '/reports', label: 'Reports', icon: FileBarChart, perm: 'reports:read' },
    ],
  },
  { section: 'Account', items: [{ to: '/account/security', label: 'Security settings', icon: ShieldCheck }] },
]

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { can, me } = useAuth()
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-14 items-center border-b border-ink-800 px-4"><Wordmark /></div>
      <nav className="flex-1 space-y-5 overflow-y-auto px-2.5 py-4" aria-label="Primary">
        {NAV.map((group) => {
          const items = group.items.filter((i) => (!i.perm || can(i.perm)) && (!i.anyPerm || i.anyPerm.some(can)))
          if (!items.length) return null
          return (
            <div key={group.section}>
              <div className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-silver-600">{group.section}</div>
              <ul className="space-y-0.5">
                {items.map(({ to, label, icon: Icon }) => (
                  <li key={to}>
                    <NavLink to={to} end={to === '/'} onClick={onNavigate}
                      className={({ isActive }) => cn(
                        'group flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] transition-colors',
                        isActive ? 'bg-ink-800 text-silver-50 shadow-[inset_2px_0_0_0_#10b981]' : 'text-silver-400 hover:bg-ink-800/60 hover:text-silver-100',
                      )}>
                      <Icon className="size-4 opacity-80" />{label}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          )
        })}
      </nav>
      <div className="border-t border-ink-800 px-4 py-3 text-[11px] text-silver-600">
        <div className="truncate text-silver-400">{me?.organization_name}</div>
        <div>Phase 6 · Security operations</div>
      </div>
    </div>
  )
}

function GlobalSearch() {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [debounced, setDebounced] = useState('')
  const nav = useNavigate()
  const ref = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim()), 200)
    return () => clearTimeout(t)
  }, [q])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); ref.current?.focus() }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const res = useQuery({
    queryKey: ['search', debounced],
    queryFn: () => api.get<SearchHit[]>(`/search?q=${encodeURIComponent(debounced)}`),
    enabled: debounced.length >= 2,
  })

  function go(link: string) { setOpen(false); setQ(''); nav(link) }

  return (
    <div className="relative w-full max-w-md">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-silver-600" />
      <input ref={ref} value={q} onChange={(e) => { setQ(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => { if (e.key === 'Enter' && res.data?.[0]) go(res.data[0].link); if (e.key === 'Escape') ref.current?.blur() }}
        placeholder="Search endpoints, employees, administrators…" aria-label="Global search"
        className="h-8 w-full rounded-md border border-ink-700 bg-ink-900 pl-8 pr-12 text-sm text-silver-100 placeholder:text-silver-600 focus:border-emerald-600/60 focus:outline-none" />
      <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-ink-600 px-1 text-[10px] text-silver-600">Ctrl K</kbd>
      {open && debounced.length >= 2 && (
        <div className="absolute z-30 mt-1 w-full overflow-hidden rounded-md border border-ink-600 bg-ink-900 shadow-xl shadow-black/40">
          {res.isLoading ? <div className="p-3"><Spinner /></div> : res.data?.length ? (
            <ul>{res.data.map((h) => (
              <li key={`${h.type}-${h.id}`}>
                <button onMouseDown={() => go(h.link)} className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left hover:bg-ink-800">
                  <span><span className="block text-sm text-silver-100">{h.title}</span><span className="block text-xs text-silver-500">{h.subtitle}</span></span>
                  <Badge>{h.type}</Badge>
                </button>
              </li>
            ))}</ul>
          ) : <div className="p-3 text-xs text-silver-500">No matches for “{debounced}”.</div>}
        </div>
      )}
    </div>
  )
}

function NotificationCenter() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const count = useQuery({ queryKey: ['notifications', 'count'], queryFn: () => api.get<{ count: number }>('/notifications/unread-count'), refetchInterval: 30_000 })
  const [open, setOpen] = useState(false)
  const list = useQuery({ queryKey: ['notifications', 'list'], queryFn: () => api.get<NotificationItem[]>('/notifications'), enabled: open })
  const invalidate = () => qc.invalidateQueries({ queryKey: ['notifications'] })
  const markAll = useMutation({ mutationFn: () => api.post('/notifications/read-all'), onSuccess: invalidate })
  const markOne = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: invalidate })
  const unread = count.data?.count ?? 0

  return (
    <DM.Root open={open} onOpenChange={setOpen}>
      <DM.Trigger className="relative rounded-md p-2 text-silver-400 hover:bg-ink-800 hover:text-silver-100" aria-label={`Notifications (${unread} unread)`}>
        <Bell className="size-4" />
        {unread > 0 && <span className="absolute right-1 top-1 grid min-w-3.5 place-items-center rounded-full bg-emerald-500 px-1 text-[9px] font-semibold leading-3.5 text-ink-950">{unread > 99 ? '99+' : unread}</span>}
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={6} className="z-40 w-96 overflow-hidden rounded-lg border border-ink-600 bg-ink-900 shadow-2xl shadow-black/50">
          <div className="flex items-center justify-between border-b border-ink-700 px-3 py-2">
            <span className="text-sm font-medium text-silver-100">Notifications</span>
            <button className="text-xs text-emerald-400 hover:text-emerald-300 disabled:opacity-40" disabled={!unread || markAll.isPending} onClick={() => markAll.mutate()}>Mark all read</button>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {list.isLoading ? <div className="p-4"><Spinner /></div> : !list.data?.length ? (
              <p className="p-6 text-center text-xs text-silver-500">You're all caught up.</p>
            ) : list.data.map((n) => (
              <DM.Item key={n.id} onSelect={() => { if (!n.read_at) markOne.mutate(n.id); if (n.link) nav(n.link) }}
                className={cn('flex cursor-pointer gap-2.5 border-b border-ink-800 px-3 py-2.5 outline-none data-[highlighted]:bg-ink-800', !n.read_at && 'bg-ink-850')}>
                <span className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', n.read_at ? 'bg-transparent' : n.severity === 'high' ? 'bg-red-400' : 'bg-emerald-400')} />
                <span className="min-w-0">
                  <span className="block text-[13px] text-silver-100">{n.title}</span>
                  {n.body && <span className="mt-0.5 line-clamp-2 block text-xs text-silver-500">{n.body}</span>}
                  <span className="mt-1 block text-[11px] text-silver-600">{relativeTime(n.created_at)}</span>
                </span>
              </DM.Item>
            ))}
          </div>
          <Link to="/notifications" onClick={() => setOpen(false)} className="block border-t border-ink-700 px-3 py-2 text-center text-xs text-silver-400 hover:text-silver-100">View all</Link>
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  )
}

function ProfileMenu() {
  const { me, logout } = useAuth()
  const nav = useNavigate()
  if (!me) return null
  const initials = me.full_name.split(' ').map((p) => p[0]).slice(0, 2).join('').toUpperCase()
  return (
    <DM.Root>
      <DM.Trigger className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 hover:bg-ink-800" aria-label="Profile menu">
        <span className="grid size-7 place-items-center rounded-full border border-ink-600 bg-ink-700 text-[11px] font-semibold text-silver-100">{initials}</span>
        <span className="hidden text-left leading-tight md:block">
          <span className="block text-[13px] text-silver-100">{me.full_name}</span>
          <span className="block text-[11px] text-silver-500">{me.roles.map((r) => r.name).join(', ')}</span>
        </span>
        <ChevronDown className="size-3.5 text-silver-500" />
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={6} className="z-40 w-60 rounded-lg border border-ink-600 bg-ink-900 p-1 shadow-2xl shadow-black/50">
          <div className="px-2.5 py-2">
            <div className="truncate text-sm text-silver-100">{me.email}</div>
            <div className="mt-1 flex gap-1">{me.mfa_enabled ? <Badge tone="success">MFA on</Badge> : <Badge tone="warning">MFA off</Badge>}</div>
          </div>
          <DM.Separator className="my-1 h-px bg-ink-700" />
          <DM.Item onSelect={() => nav('/account/security')} className="flex cursor-pointer items-center gap-2 rounded px-2.5 py-1.5 text-sm text-silver-200 outline-none data-[highlighted]:bg-ink-800">
            <ShieldCheck className="size-4" /> Security settings
          </DM.Item>
          <DM.Item onSelect={async () => { await logout(); nav('/login') }} className="flex cursor-pointer items-center gap-2 rounded px-2.5 py-1.5 text-sm text-silver-200 outline-none data-[highlighted]:bg-ink-800">
            <LogOut className="size-4" /> Sign out
          </DM.Item>
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  )
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const { me } = useAuth()
  return (
    <div className="flex h-full">
      <aside className="hidden w-60 shrink-0 border-r border-ink-800 bg-ink-950 lg:block"><Sidebar /></aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 border-r border-ink-800 bg-ink-950">
            <button className="absolute right-2 top-3 rounded p-1.5 text-silver-500 hover:bg-ink-800" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X className="size-4" /></button>
            <Sidebar onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-ink-800 bg-ink-900/80 px-4 backdrop-blur">
          <button className="rounded p-1.5 text-silver-400 hover:bg-ink-800 lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu className="size-5" /></button>
          <GlobalSearch />
          <div className="ml-auto flex items-center gap-1">
            <NotificationCenter />
            <div className="mx-1 h-6 w-px bg-ink-700" />
            <ProfileMenu />
          </div>
        </header>
        {me && !me.mfa_enabled && (
          <div className="border-b border-amber-500/20 bg-amber-500/5 px-4 py-1.5 text-xs text-amber-200">
            Multi-factor authentication is not enabled on your account. <Link to="/account/security" className="underline underline-offset-2 hover:text-amber-100">Enable it now</Link>.
          </div>
        )}
        <main className="min-h-0 flex-1 overflow-y-auto px-4 py-5 md:px-6"><div className="mx-auto max-w-[1400px]"><Outlet /></div></main>
      </div>
    </div>
  )
}
