import { Badge } from '@/components/ui/primitives'
import type { CheckResult, Severity } from '@/types/api'

export function ResultBadge({ r }: { r: CheckResult }) {
  const tone = r === 'PASS' ? 'success' : r === 'FAIL' ? 'danger' : r === 'UNKNOWN' ? 'warning' : 'neutral'
  return <Badge tone={tone} className="shrink-0">{r === 'NOT_APPLICABLE' ? 'N/A' : r}</Badge>
}

export function SeverityBadge({ s }: { s: Severity }) {
  const tone = s === 'critical' ? 'danger' : s === 'high' ? 'warning' : s === 'medium' ? 'info' : 'neutral'
  return <Badge tone={tone} className="shrink-0">{s}</Badge>
}

export function StateBadge({ state }: { state: string }) {
  const tone = state === 'compliant' ? 'success' : state === 'non_compliant' ? 'danger' : 'warning'
  const label = state === 'non_compliant' ? 'non-compliant' : state === 'unknown' ? 'unknown (not compliant)' : state
  return <Badge tone={tone}>{label}</Badge>
}
