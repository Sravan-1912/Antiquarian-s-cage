"""Server-side EDR detection engine (Sigma-style rules over streamed endpoint telemetry).

Agents stream events (process creation, and later network/file) to `/agent/v1/telemetry`; this module evaluates each
event against a set of allowlisted detection rules and raises a security alert (reusing the Phase 6 alert pipeline) on a
match. Rules are simple field conditions ANDed together — a pragmatic subset of Sigma that is fully unit-testable and
needs no rule-compilation dependency.

Only matches are persisted (as alerts); the raw high-volume telemetry is evaluated and discarded, so this scales.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models import Device
from app.services import alerts


@dataclass(frozen=True)
class Cond:
    field: str          # dotted path into event["data"], e.g. "cmdline" or "parent.name"
    op: str             # eq | ieq | contains | icontains | startswith | endswith | regex | iregex | in
    value: object


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str       # low | medium | high | critical
    event_type: str     # process_created | network_connection | file_write | "*"
    conditions: tuple[Cond, ...]
    description: str = ""
    key_field: str = "name"   # which event field distinguishes occurrences (for alert dedup)


def _get(data: dict, path: str):
    cur: object = data
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _match(cond: Cond, data: dict) -> bool:
    v = _get(data, cond.field)
    if v is None:
        return False
    s = str(v)
    val = cond.value
    op = cond.op
    if op == "eq":
        return s == str(val)
    if op == "ieq":
        return s.lower() == str(val).lower()
    if op == "contains":
        return str(val) in s
    if op == "icontains":
        return str(val).lower() in s.lower()
    if op == "startswith":
        return s.lower().startswith(str(val).lower())
    if op == "endswith":
        return s.lower().endswith(str(val).lower())
    if op == "regex":
        return re.search(str(val), s) is not None
    if op == "iregex":
        return re.search(str(val), s, re.IGNORECASE) is not None
    if op == "in":
        return s.lower() in {str(x).lower() for x in (val or [])}
    return False


# --------------------------------------------------------------------------------- built-in rules (process_created)
RULES: tuple[Rule, ...] = (
    Rule("encoded_powershell", "Encoded PowerShell command", "high", "process_created",
         (Cond("name", "icontains", "powershell"), Cond("cmdline", "iregex", r"-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}")),
         "A PowerShell process was launched with a base64-encoded command — a common obfuscation for malicious scripts.",
         key_field="cmdline"),
    Rule("lolbin_download", "LOLBin used to download a file", "high", "process_created",
         (Cond("cmdline", "iregex", r"certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+.*/transfer|curl\s+.*http|wget\s+.*http"),),
         "A living-off-the-land binary (certutil/bitsadmin/curl/wget) was used to fetch a remote file.",
         key_field="cmdline"),
    Rule("credential_dumping", "Possible credential dumping", "critical", "process_created",
         (Cond("cmdline", "iregex", r"mimikatz|sekurlsa|lsass\.dmp|procdump.*lsass|comsvcs.*MiniDump"),),
         "Command line matches a known credential-dumping technique targeting LSASS.",
         key_field="cmdline"),
    Rule("persistence_schtasks", "Scheduled task / service persistence", "medium", "process_created",
         (Cond("cmdline", "iregex", r"schtasks(\.exe)?\s+/create|\bsc(\.exe)?\s+create|New-ScheduledTask"),),
         "A scheduled task or service was created — a common persistence mechanism.",
         key_field="cmdline"),
    Rule("office_spawns_shell", "Office application spawned a shell", "high", "process_created",
         (Cond("parent.name", "iregex", r"winword|excel|powerpnt|outlook"),
          Cond("name", "iregex", r"cmd\.exe|powershell|wscript|cscript|mshta")),
         "A Microsoft Office process spawned a command interpreter — a hallmark of malicious macros.",
         key_field="cmdline"),
    Rule("defender_tamper", "Security tooling tamper attempt", "high", "process_created",
         (Cond("cmdline", "iregex", r"Set-MpPreference\s+.*-Disable|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off|Stop-Service\s+.*WinDefend"),),
         "Command line attempts to disable Microsoft Defender or the firewall.",
         key_field="cmdline"),
)


def evaluate(event: dict, rules: tuple[Rule, ...] = RULES) -> list[Rule]:
    """Return every rule that matches this event (all conditions AND)."""
    etype = event.get("type")
    data = event.get("data") or {}
    if not isinstance(data, dict):
        return []
    return [r for r in rules if r.event_type in ("*", etype) and all(_match(c, data) for c in r.conditions)]


def ingest(db: Session, device: Device, events: list[dict], rules: tuple[Rule, ...] = RULES) -> int:
    """Evaluate a batch of telemetry events and raise an alert per matched rule (deduplicated). Returns match count."""
    matched = 0
    for ev in events:
        data = ev.get("data") or {}
        for rule in evaluate(ev, rules):
            key = str(_get(data, rule.key_field) or "")[:120]
            alerts.raise_alert(
                db, device.organization_id, "edr_detection",
                title=f"{rule.title} on {device.hostname}", description=rule.description, severity=rule.severity,
                dedup_key=f"edr:{device.id}:{rule.id}:{key}", device_id=device.id,
                evidence={"rule": rule.id, "event_type": ev.get("type"), "event": data})
            matched += 1
    if matched:
        db.commit()
    return matched
