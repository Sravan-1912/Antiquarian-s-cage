import { useState } from 'react'
import { Badge, Field, Input, Select } from '@/components/ui/primitives'
import type { DeploymentStatus, PolicyCategory } from '@/types/api'

export const CATEGORY_LABEL: Record<PolicyCategory, string> = {
  firewall: 'Firewall', bitlocker: 'Disk encryption (BitLocker)', usb: 'USB device control', antivirus: 'Antivirus (Defender)',
  screen_lock: 'Screen lock', windows_update: 'Windows Update', password: 'Password & lockout',
}

export const CATEGORY_NOTE: Record<PolicyCategory, string> = {
  firewall: 'Enables Windows Firewall on the selected profiles. Previous state is recorded and restored on rollback.',
  bitlocker: 'Verification only. Encryption is never started automatically — doing so without escrowed recovery keys risks lockout.',
  usb: 'Read-only or block mass storage; allowlisted device IDs use Windows Device Installation Restrictions (Pro/Enterprise).',
  antivirus: 'Checks Defender health; when enforcing, re-enables real-time protection and refreshes signatures. Tamper Protection may block changes.',
  screen_lock: 'Sets the machine inactivity limit and a password-protected screen saver policy.',
  windows_update: 'Reports update recency and configures automatic install scheduling (Windows Home may ignore scheduling).',
  password: 'Local account policy only. Domain-joined devices follow domain policy.',
}

export const DEFAULTS: Record<PolicyCategory, Record<string, unknown>> = {
  firewall: { profiles: ['domain', 'private', 'public'], enforce: true },
  bitlocker: { require_system_drive_encryption: true, allowed_methods: ['XtsAes128', 'XtsAes256'] },
  usb: { mode: 'read_only', allowlist: [], monitor_connections: true },
  antivirus: { require_real_time_protection: true, max_signature_age_days: 3, enforce: true },
  screen_lock: { inactivity_timeout_seconds: 600, require_password_on_resume: true },
  windows_update: { max_days_since_last_update: 35, configure_automatic_updates: true, scheduled_install_day: 0, scheduled_install_hour: 3 },
  password: { min_length: 12, complexity_enabled: true, lockout_threshold: 5, lockout_duration_minutes: 15, lockout_window_minutes: 15 },
}

const STATUS_TONE: Record<DeploymentStatus, 'success' | 'danger' | 'warning' | 'neutral' | 'info'> = {
  applied: 'success', failed: 'danger', needs_attention: 'warning', offline: 'neutral', pending: 'info', in_progress: 'info', revoked: 'neutral',
}
export function DeploymentBadge({ status }: { status: DeploymentStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{status.replace('_', ' ')}</Badge>
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-silver-200">
      <input type="checkbox" className="size-4 accent-emerald-500" checked={checked} onChange={(e) => onChange(e.target.checked)} />{label}
    </label>
  )
}

function Num({ id, label, value, min, max, onChange, hint }: { id: string; label: string; value: number; min: number; max: number; onChange: (v: number) => void; hint?: string }) {
  return <Field label={label} htmlFor={id} hint={hint}><Input id={id} type="number" min={min} max={max} required value={value} onChange={(e) => onChange(Number(e.target.value))} /></Field>
}

/** Category-specific editor. The backend re-validates every field; these controls only guide input. */
export function ConfigEditor({ category, value, onChange }: { category: PolicyCategory; value: Record<string, unknown>; onChange: (v: Record<string, unknown>) => void }) {
  const set = (k: string, v: unknown) => onChange({ ...value, [k]: v })
  const [allowText, setAllowText] = useState(((value.allowlist as string[]) ?? []).join('\n'))
  switch (category) {
    case 'firewall': {
      const profiles = (value.profiles as string[]) ?? []
      return (
        <div className="space-y-2">
          <div className="text-xs text-silver-500">Profiles to enforce</div>
          <div className="flex gap-4">{['domain', 'private', 'public'].map((p) => (
            <Check key={p} label={p} checked={profiles.includes(p)} onChange={(on) => set('profiles', on ? [...profiles, p] : profiles.filter((x) => x !== p))} />
          ))}</div>
          <Check label="Enforce (unchecked = report only)" checked={!!value.enforce} onChange={(v) => set('enforce', v)} />
        </div>
      )
    }
    case 'bitlocker': {
      const methods = (value.allowed_methods as string[]) ?? []
      return (
        <div className="space-y-2">
          <Check label="Require BitLocker on the system drive" checked={!!value.require_system_drive_encryption} onChange={(v) => set('require_system_drive_encryption', v)} />
          <div className="text-xs text-silver-500">Approved encryption methods</div>
          <div className="flex flex-wrap gap-4">{['XtsAes128', 'XtsAes256', 'AesCbc128', 'AesCbc256'].map((m) => (
            <Check key={m} label={m} checked={methods.includes(m)} onChange={(on) => set('allowed_methods', on ? [...methods, m] : methods.filter((x) => x !== m))} />
          ))}</div>
        </div>
      )
    }
    case 'usb':
      return (
        <div className="space-y-3">
          <Field label="Mode" htmlFor="um">
            <Select id="um" className="w-full" value={String(value.mode)} onChange={(e) => set('mode', e.target.value)}>
              <option value="allow">Allow (no restriction)</option><option value="read_only">Read-only removable storage</option><option value="block_storage">Block USB mass storage</option>
            </Select>
          </Field>
          <Field label="Allowlisted device instance IDs (one per line)" htmlFor="ua" hint="e.g. USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler — only used with Block mode">
            <textarea id="ua" rows={3} className="w-full rounded-md border border-ink-600 bg-ink-900 px-3 py-2 font-mono text-xs text-silver-100 focus:border-emerald-600/70 focus:outline-none"
              value={allowText} onChange={(e) => { setAllowText(e.target.value); set('allowlist', e.target.value.split('\n').map((x) => x.trim()).filter(Boolean)) }} />
          </Field>
          <Check label="Report USB storage connections" checked={!!value.monitor_connections} onChange={(v) => set('monitor_connections', v)} />
        </div>
      )
    case 'antivirus':
      return (
        <div className="space-y-3">
          <Check label="Require real-time protection" checked={!!value.require_real_time_protection} onChange={(v) => set('require_real_time_protection', v)} />
          <Num id="as" label="Maximum signature age (days)" min={0} max={30} value={Number(value.max_signature_age_days)} onChange={(v) => set('max_signature_age_days', v)} />
          <Check label="Enforce (re-enable protection, update signatures)" checked={!!value.enforce} onChange={(v) => set('enforce', v)} />
        </div>
      )
    case 'screen_lock':
      return (
        <div className="space-y-3">
          <Num id="st" label="Inactivity timeout (seconds)" min={60} max={3600} value={Number(value.inactivity_timeout_seconds)} onChange={(v) => set('inactivity_timeout_seconds', v)} hint="60–3600; CIS recommends ≤ 900" />
          <Check label="Require password on resume" checked={!!value.require_password_on_resume} onChange={(v) => set('require_password_on_resume', v)} />
        </div>
      )
    case 'windows_update':
      return (
        <div className="grid grid-cols-2 gap-3">
          <Num id="wd" label="Max days since last update" min={7} max={120} value={Number(value.max_days_since_last_update)} onChange={(v) => set('max_days_since_last_update', v)} />
          <div className="flex items-end pb-2"><Check label="Configure automatic install" checked={!!value.configure_automatic_updates} onChange={(v) => set('configure_automatic_updates', v)} /></div>
          <Field label="Install day" htmlFor="wday">
            <Select id="wday" className="w-full" value={Number(value.scheduled_install_day)} onChange={(e) => set('scheduled_install_day', Number(e.target.value))}>
              {['Every day', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].map((d, i) => <option key={d} value={i}>{d}</option>)}
            </Select>
          </Field>
          <Num id="wh" label="Install hour (0–23)" min={0} max={23} value={Number(value.scheduled_install_hour)} onChange={(v) => set('scheduled_install_hour', v)} />
        </div>
      )
    case 'password':
      return (
        <div className="grid grid-cols-2 gap-3">
          <Num id="pl" label="Minimum length" min={8} max={14} value={Number(value.min_length)} onChange={(v) => set('min_length', v)} hint="Windows local policy max is 14" />
          <div className="flex items-end pb-2"><Check label="Complexity required" checked={!!value.complexity_enabled} onChange={(v) => set('complexity_enabled', v)} /></div>
          <Num id="lt" label="Lockout threshold (attempts)" min={3} max={50} value={Number(value.lockout_threshold)} onChange={(v) => set('lockout_threshold', v)} />
          <Num id="ld" label="Lockout duration (minutes)" min={5} max={1440} value={Number(value.lockout_duration_minutes)} onChange={(v) => set('lockout_duration_minutes', v)} />
          <Num id="lw" label="Reset counter after (minutes)" min={5} max={1440} value={Number(value.lockout_window_minutes)} onChange={(v) => set('lockout_window_minutes', v)} hint="Must not exceed the lockout duration" />
        </div>
      )
  }
}

export function summarizeConfig(category: PolicyCategory, c: Record<string, unknown>): string {
  switch (category) {
    case 'firewall': return `${(c.profiles as string[]).join(', ')}${c.enforce ? '' : ' · report only'}`
    case 'bitlocker': return c.require_system_drive_encryption ? `System drive · ${(c.allowed_methods as string[]).join('/')}` : 'Not required'
    case 'usb': return `${String(c.mode).replace('_', ' ')}${(c.allowlist as string[])?.length ? ` · ${(c.allowlist as string[]).length} allowlisted` : ''}`
    case 'antivirus': return `RTP ${c.require_real_time_protection ? 'required' : 'optional'} · signatures ≤ ${c.max_signature_age_days}d${c.enforce ? '' : ' · report only'}`
    case 'screen_lock': return `${Math.round(Number(c.inactivity_timeout_seconds) / 60)} min${c.require_password_on_resume ? ' · password on resume' : ''}`
    case 'windows_update': return `≤ ${c.max_days_since_last_update} days${c.configure_automatic_updates ? ' · auto install' : ''}`
    case 'password': return `min ${c.min_length} · lockout ${c.lockout_threshold}/${c.lockout_duration_minutes}m${c.complexity_enabled ? ' · complex' : ''}`
  }
}
