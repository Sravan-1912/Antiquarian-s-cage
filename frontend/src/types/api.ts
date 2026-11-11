export interface Role { key: string; name: string }

export interface Me {
  id: string
  email: string
  full_name: string
  organization_id: string
  organization_name: string
  roles: Role[]
  permissions: string[]
  email_verified: boolean
  last_login_at: string | null
}

export interface Page<T> { items: T[]; total: number; page: number; page_size: number }

export type EmployeeStatus = 'invited' | 'active' | 'suspended' | 'offboarded'

export interface Employee {
  id: string
  employee_number: string
  full_name: string
  email: string
  department: string
  job_title: string
  status: EmployeeStatus
  enrollment_status: string
  manager_id: string | null
  start_date: string | null
  end_date: string | null
  user_id: string | null
  created_at: string
  updated_at: string
}

export interface EmployeeEvent {
  id: string
  kind: string
  details: Record<string, unknown>
  actor_id: string | null
  created_at: string
}

export interface AdminUser {
  id: string
  email: string
  full_name: string
  status: 'pending' | 'active' | 'disabled'
  email_verified_at: string | null
  last_login_at: string | null
  locked_until: string | null
  created_at: string
  roles: Role[]
}

export interface RoleDetail { key: string; name: string; description: string; permissions: string[] }

export interface AuditEntry {
  id: string
  seq: number
  actor_type: string
  actor_label: string
  action: string
  target_type: string | null
  target_id: string | null
  target_label: string | null
  source_ip: string | null
  result: 'success' | 'failure' | 'denied'
  metadata: Record<string, unknown>
  created_at: string
  prev_hash: string
  hash: string
}

export interface AuditVerify {
  valid: boolean
  checked: number
  first_invalid_seq: number | null
  reason: string | null
  head_seq: number | null
  head_hash: string | null
  verified_at: string
  anchors: AnchorReport | null
}

export interface AnchorReport {
  valid: boolean
  anchors_checked: number
  external_file: string
  external_anchors: number
  last_anchor_seq: number | null
  last_anchor_at: string | null
  problems: string[]
}

export interface AuditAnchor {
  seq: number
  hash: string
  created_at: string
  key_id: string
  external_written: boolean
  external_error: string | null
}

export interface NotificationItem {
  id: string
  kind: string
  severity: string
  title: string
  body: string
  link: string | null
  read_at: string | null
  created_at: string
}

export interface SessionItem {
  id: string
  ip: string | null
  user_agent: string | null
  created_at: string
  last_seen_at: string
  expires_at: string
  current: boolean
}

export interface AuthEvent {
  id: string
  event_type: string
  success: boolean
  reason: string | null
  ip: string | null
  user_agent: string | null
  created_at: string
}

export interface SearchHit { type: string; id: string; title: string; subtitle: string; link: string }

export interface ModuleStatus { available: false; module: string; phase: number }

export interface DashboardSummary {
  generated_at: string
  employees: {
    active: number
    invited: number
    suspended: number
    offboarded: number
    by_department: { department: string; count: number }[]
    joiners_by_day: { date: string; count: number }[]
  }
  authentication: {
    failed_logins_24h: number
    locked_accounts: number
    logins_by_day: { date: string; success: number; failure: number }[]
  }
  administrators: { total: number; active: number; with_passkey: number; online: number }
  endpoints: ModuleStatus | EndpointSummary
  compliance: ModuleStatus | ComplianceDash
  policies: ModuleStatus | PolicyDash
  alerts: ModuleStatus | AlertDash
  recent_activity: { id: string; action: string; actor: string; target: string | null; result: string; created_at: string }[]
  recent_activity_visible: boolean
}

export type Connectivity = 'online' | 'offline' | 'never'

export interface Device {
  id: string
  display_name: string
  hostname: string
  employee_id: string | null
  employee_name: string | null
  support_owner_id: string | null
  os_name: string | null
  os_version: string | null
  os_build: string | null
  manufacturer: string | null
  model: string | null
  serial_number: string | null
  agent_version: string | null
  status: 'active' | 'suspended' | 'revoked' | 'unenrolled'
  compliance_state: string
  enrolled_at: string
  last_heartbeat_at: string | null
  last_inventory_at: string | null
  last_seen_ip: string | null
  reported_ip_addresses: { addresses?: string[] }
  reported_mac_addresses: { addresses?: string[] }
  online: boolean
  connectivity: Connectivity
}

export interface SecurityCheck { state: 'enabled' | 'disabled' | 'partial' | 'unknown' | 'not_applicable'; detail: string | null; data: Record<string, unknown> }

export interface Inventory {
  id: string
  collected_at: string
  agent_collected_at: string | null
  cpu: { name?: string; manufacturer?: string; physical_cores?: number; logical_processors?: number; max_clock_mhz?: number }
  memory_bytes: number | null
  disks: { items: { device: string; mountpoint: string; filesystem: string | null; total_bytes: number; used_bytes: number; free_bytes: number }[] }
  network_interfaces: { items: { name: string; mac_address: string | null; ipv4: string[]; ipv6: string[]; is_up: boolean | null; speed_mbps: number | null }[] }
  security: Record<string, SecurityCheck>
  os: Record<string, string | null>
}

export interface DeviceCertificate { id: string; serial: string; fingerprint_sha256: string; not_before: string; not_after: string; status: string; revoked_at: string | null; revoked_reason: string | null; created_at: string }
export interface DeviceEvent { id: string; kind: string; details: Record<string, unknown>; actor_id: string | null; created_at: string }
export interface Heartbeat { received_at: string; source_ip: string | null; agent_version: string | null; uptime_seconds: number | null }

export interface EnrollmentToken {
  id: string
  label: string
  employee_id: string | null
  created_at: string
  expires_at: string
  used_at: string | null
  used_by_device_id: string | null
  revoked_at: string | null
  state: 'active' | 'used' | 'expired' | 'revoked'
  token?: string
}

export interface EndpointSummary {
  available: true
  enrolled: number
  online: number
  offline: number
  never_reported: number
  suspended: number
  revoked: number
  unenrolled: number
  os_distribution: { os: string; count: number }[]
  enrollments_by_day: { date: string; count: number }[]
  compliance_states: Record<string, number>
  offline_threshold_seconds: number
  last_contact: { online: number; under_1h: number; '1h_24h': number; '1d_7d': number; over_7d: number; never: number }
  platforms: { platform: string; count: number }[]
  network: NetworkUsage
}

export interface NetworkUsage {
  window_hours: number
  devices_reporting: number
  bytes_sent: number
  bytes_received: number
  avg_sent: number | null
  avg_received: number | null
}

export interface AlertDash {
  available: true
  open_by_severity: Record<'critical' | 'high' | 'medium' | 'low' | 'informational', number>
  open_total: number
  unassigned: number
  detected_by_day: { date: string; count: number }[]
}

export type PolicyCategory = 'firewall' | 'bitlocker' | 'usb' | 'antivirus' | 'screen_lock' | 'windows_update' | 'password'
export type DeploymentStatus = 'pending' | 'in_progress' | 'applied' | 'failed' | 'offline' | 'needs_attention' | 'revoked'

export interface Policy {
  id: string
  name: string
  description: string
  category: PolicyCategory
  configuration: Record<string, unknown>
  version: number
  status: 'active' | 'retired'
  created_by: string | null
  created_at: string
  updated_at: string
  assigned_devices: number
  deployment_summary: Partial<Record<DeploymentStatus, number>>
}

export interface Deployment {
  id: string
  policy_id: string
  device_id: string
  device_name: string | null
  policy_name: string | null
  policy_version: number
  action: 'apply' | 'remove'
  status: DeploymentStatus
  detail: string | null
  result: Record<string, unknown>
  previous_state: Record<string, unknown>
  command_job_id: string | null
  created_at: string
  updated_at: string
}

export interface Assignment { id: string; policy_id: string; device_id: string; device_name: string | null; assigned_at: string; revoked_at: string | null; latest_status: DeploymentStatus | null }
export interface PolicyRevision { version: number; configuration: Record<string, unknown>; changed_by: string | null; created_at: string }

export type CheckResult = 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_APPLICABLE'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export interface ComplianceCheckDef { key: string; name: string; description: string; remediation: string; default_severity: Severity; severity: Severity; enabled: boolean }
export interface ComplianceHistoryPoint { date: string; devices: number; average_score: number | null; compliant: number; non_compliant: number; unknown: number }
export interface ComplianceSummary {
  devices: number
  evaluated: number
  states: { compliant: number; non_compliant: number; unknown: number }
  average_score: number | null
  failing_checks: { key: string; name: string; devices: number }[]
  unknown_checks: { key: string; name: string; devices: number }[]
  history: ComplianceHistoryPoint[]
}
export interface ComplianceDeviceRow { device_id: string; name: string; state: string; score: number | null; failed: number | null; unknown: number | null; evaluated_at: string | null }
export interface DeviceCompliance {
  device_id: string
  state: string
  evaluation: { evaluated_at: string; score: number; passed: number; failed: number; unknown: number; not_applicable: number } | null
  results: { key: string; name: string; result: CheckResult; severity: Severity; evidence: Record<string, unknown>; remediation: string | null }[]
  history: { evaluated_at: string; score: number; state: string }[]
}
export interface ComplianceDash { available: true; compliant: number; non_compliant: number; unknown: number; trend: { date: string; average_score: number | null; non_compliant: number }[] }
export interface PolicyDash { available: true; active_policies: number; total_policies: number; inactive_policies: number; pending: number; by_status: Partial<Record<DeploymentStatus, number>>; success_rate: number | null }

export type RemoteCommand = 'device.inspect' | 'device.lock' | 'device.restart' | 'device.restart_cancel' | 'account.disable' | 'account.enable' | 'account.remove_admin'
export interface RemoteAction {
  id: string
  device_id: string
  command: string
  parameters: Record<string, unknown>
  status: 'queued' | 'delivered' | 'succeeded' | 'failed' | 'expired' | 'revoked'
  issued_at: string
  expires_at: string
  delivered_at: string | null
  completed_at: string | null
  result: { status?: string; detail?: string | null; current_state?: Record<string, unknown> }
  requested_by: string | null
  requested_by_label: string | null
}
export type SessionStatus = 'requested' | 'awaiting_consent' | 'active' | 'ending' | 'ended' | 'denied' | 'expired' | 'cancelled' | 'failed'
export interface RemoteSession {
  id: string
  device_id: string
  device_name: string | null
  requested_by_label: string
  reason: string
  require_consent: boolean
  max_minutes: number
  status: SessionStatus
  consent_decision: string | null
  consent_user: string | null
  consented_at: string | null
  started_at: string | null
  expires_at: string | null
  ended_at: string | null
  ended_by: string | null
  end_reason: string | null
  created_at: string
}
export interface AssistSettings { require_consent: boolean; max_session_minutes: number; allow_it_support: boolean }
export interface InspectState {
  uptime_seconds?: number
  cpu_percent?: number
  memory_percent?: number
  logged_on_users?: string[]
  process_count?: number
  disks?: { mount: string; free_percent: number }[]
  local_accounts?: { name: string; enabled: boolean; last_logon: string | null; sid: string }[]
  administrators?: { name: string; source: string }[]
  local_accounts_error?: string
}
