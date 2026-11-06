import { Badge } from '@/components/ui/primitives'
import type { Connectivity, SecurityCheck } from '@/types/api'
import { cn, relativeTime } from '@/utils/format'

export function ConnectivityBadge({ c, last }: { c: Connectivity; last?: string | null }) {
  const label = c === 'online' ? 'Online' : c === 'offline' ? 'Offline' : 'Never reported'
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" title={last ? `Last authenticated heartbeat ${relativeTime(last)}` : 'No authenticated heartbeat received yet'}>
      <span className={cn('size-1.5 rounded-full', c === 'online' ? 'bg-emerald-400' : c === 'offline' ? 'bg-red-400' : 'bg-silver-600')} />
      <span className={c === 'online' ? 'text-emerald-300' : c === 'offline' ? 'text-red-300' : 'text-silver-500'}>{label}</span>
    </span>
  )
}

export function DeviceStatusBadge({ status }: { status: string }) {
  const tone = status === 'active' ? 'success' : status === 'suspended' ? 'warning' : 'danger'
  return <Badge tone={tone}>{status}</Badge>
}

const STATE_TONE = { enabled: 'success', disabled: 'danger', partial: 'warning', unknown: 'neutral', not_applicable: 'neutral' } as const

// For these checks the secure state is "disabled" (feature off). Remote Desktop is neutral: it needs review, not a verdict.
const SECURE_WHEN_DISABLED = new Set(['smb1', 'guest_account'])
// usb_storage: 'enabled' means storage allowed — a policy choice, not a verdict.
const NEUTRAL = new Set(['remote_desktop', '_collection_errors', 'usb_storage'])

export function SecurityStateBadge({ name, check }: { name: string; check: SecurityCheck }) {
  let tone: 'success' | 'danger' | 'warning' | 'neutral' = STATE_TONE[check.state]
  if (SECURE_WHEN_DISABLED.has(name) && (check.state === 'enabled' || check.state === 'disabled')) {
    tone = check.state === 'disabled' ? 'success' : 'danger'
  }
  if (NEUTRAL.has(name)) tone = 'neutral'
  return <Badge tone={tone} className="shrink-0">{check.state.replace('_', ' ')}</Badge>
}

export const SECURITY_LABELS: Record<string, string> = {
  firewall: 'Windows Firewall', defender: 'Microsoft Defender', secure_boot: 'Secure Boot', bitlocker: 'BitLocker (system drive)',
  guest_account: 'Guest account', smb1: 'SMBv1 protocol', remote_desktop: 'Remote Desktop', credential_guard: 'Credential Guard',
  screen_lock: 'Screen lock policy', _collection_errors: 'Collection errors', windows_update: 'Windows Update',
  account_policy: 'Account & lockout policy', audit_policy: 'Audit policy', usb_storage: 'USB mass storage',
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`
}
