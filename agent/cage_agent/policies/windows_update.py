"""Windows Update policy: report update recency; optionally configure automatic download+install via AU policy keys.
Windows Home ignores parts of the AU policy; the outcome says so instead of claiming success."""
from __future__ import annotations

from cage_agent.collectors.security import windows_update as collect_update
from cage_agent.policies import Outcome
from cage_agent.policies import registry as reg

AU = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"


def _edition() -> str:
    try:
        r = reg.read(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID")
        return str(r.get("value", ""))
    except OSError:
        return ""


def apply(cfg: dict) -> Outcome:
    status = collect_update([])
    days = (status.get("data") or {}).get("days_since_last_update")
    previous: dict = {"registry": {}}
    notes = []
    if cfg["configure_automatic_updates"]:
        values = [(AU, "NoAutoUpdate", 0, "dword"), (AU, "AUOptions", 4, "dword"),
                  (AU, "ScheduledInstallDay", cfg["scheduled_install_day"], "dword"),
                  (AU, "ScheduledInstallTime", cfg["scheduled_install_hour"], "dword")]
        if not all(reg.read(p, n).get("value") == v for p, n, v, _ in values):
            previous["registry"] = reg.apply_values(values)
            notes.append("automatic updates configured")
        if _edition().lower().startswith("core"):
            notes.append("Windows Home may ignore AU scheduling policy")
    current = {"days_since_last_update": days, **(status.get("data") or {})}
    if not isinstance(days, int):
        return Outcome("needs_attention", "Could not determine last update date; " + "; ".join(notes), previous, current)
    if days > cfg["max_days_since_last_update"]:
        return Outcome("needs_attention", f"Last update {days} days ago (limit {cfg['max_days_since_last_update']}); "
                       + "; ".join(notes), previous, current)
    return Outcome("succeeded", f"Updates current ({days} days)" + ("; " + "; ".join(notes) if notes else ""),
                   previous, current)


def remove(previous: dict) -> Outcome:
    reg.restore_values(previous.get("registry", {}))
    return Outcome("succeeded", "Restored previous Windows Update policy keys")
