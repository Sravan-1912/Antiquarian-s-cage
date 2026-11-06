"""Antivirus policy (Microsoft Defender): verify health; when enforcing, re-enable real-time protection and refresh
signatures. Tamper Protection or a third-party antivirus can legitimately block changes — reported, not hidden."""
from __future__ import annotations

from cage_agent.policies import Outcome
from cage_agent.policies.ps import PSError, run

READ = ("Get-MpComputerStatus | ForEach-Object { [pscustomobject]@{ rtp = [bool]$_.RealTimeProtectionEnabled; "
        "av = [bool]$_.AntivirusEnabled; age = [int]$_.AntivirusSignatureAge; tamper = [bool]$_.IsTamperProtected } }")
ENABLE_RTP = "Set-MpPreference -DisableRealtimeMonitoring $false"
DISABLE_RTP = "Set-MpPreference -DisableRealtimeMonitoring $true"
UPDATE = "Update-MpSignature"


def apply(cfg: dict) -> Outcome:
    before = run(READ) or {}
    problems = []
    if cfg["require_real_time_protection"] and not before.get("rtp"):
        problems.append("real-time protection off")
    if before.get("age", 0) > cfg["max_signature_age_days"]:
        problems.append(f"signatures {before.get('age')} days old")
    if not problems:
        return Outcome("succeeded", "Defender healthy", {}, before)
    if not cfg.get("enforce", True):
        return Outcome("needs_attention", "Report-only: " + "; ".join(problems), {}, before)
    changed = []
    if "real-time protection off" in problems:
        run(ENABLE_RTP)
        changed.append("rtp")
    try:
        if any(p.startswith("signatures") for p in problems):
            run(UPDATE, timeout=600)
    except PSError as exc:
        problems.append(f"signature update failed: {exc}")
    after = run(READ) or {}
    ok = (not cfg["require_real_time_protection"] or after.get("rtp")) and after.get("age", 99) <= cfg["max_signature_age_days"]
    detail = "Defender remediated" if ok else ("Changes did not take effect (Tamper Protection or third-party AV?): "
                                               + "; ".join(problems))
    return Outcome("succeeded" if ok else "needs_attention", detail, {"rtp": before.get("rtp"), "changed": changed}, after)


def remove(previous: dict) -> Outcome:
    if "rtp" in previous.get("changed", []) and previous.get("rtp") is False:
        run(DISABLE_RTP)
        return Outcome("succeeded", "Restored previous real-time protection setting (off)", {}, run(READ) or {})
    return Outcome("succeeded", "No setting changed by this policy; nothing to roll back")
