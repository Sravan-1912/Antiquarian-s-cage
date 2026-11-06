"""Screen lock policy: machine inactivity limit (InactivityTimeoutSecs) plus password-protected screen saver policy."""
from __future__ import annotations

from cage_agent.policies import Outcome
from cage_agent.policies import registry as reg

SYS = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
DESK = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"


def apply(cfg: dict) -> Outcome:
    t = cfg["inactivity_timeout_seconds"]
    values: list[tuple[str, str, object, str]] = [(SYS, "InactivityTimeoutSecs", t, "dword")]
    if cfg["require_password_on_resume"]:
        values += [(DESK, "ScreenSaveActive", "1", "sz"), (DESK, "ScreenSaverIsSecure", "1", "sz"),
                   (DESK, "ScreenSaveTimeOut", str(t), "sz")]
    current_before = {f"{p}\\{n}": reg.read(p, n) for p, n, _, _ in values}
    if all(current_before[f"{p}\\{n}"].get("value") == v for p, n, v, _ in values):
        return Outcome("succeeded", "Already compliant", {"registry": {}}, current_before)
    previous = reg.apply_values(values)
    current = {f"{p}\\{n}": reg.read(p, n) for p, n, _, _ in values}
    return Outcome("succeeded", f"Inactivity lock set to {t}s" + (" with password on resume" if
                   cfg["require_password_on_resume"] else "") + " (applies at next sign-in for some settings)",
                   {"registry": previous}, current)


def remove(previous: dict) -> Outcome:
    reg.restore_values(previous.get("registry", {}))
    return Outcome("succeeded", "Restored previous screen lock configuration")
