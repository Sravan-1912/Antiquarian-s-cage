"""Firewall policy: enable Windows Firewall on the selected profiles. Never disables a profile except when rolling
back to a state that was recorded before this policy changed it."""
from __future__ import annotations

from cage_agent.policies import Outcome
from cage_agent.policies.ps import run

READ = "Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name = $_.Name.ToLower(); enabled = [bool]($_.Enabled -eq 'True') } }"
# $env values are code-supplied literals (validated profile name, 'True'/'False'); PowerShell converts the string
# to the GpoBoolean enum.
SET = "Set-NetFirewallProfile -Name $env:CAGE_ARG_PROFILE -Enabled $env:CAGE_ARG_VALUE"


def read_state() -> dict[str, bool]:
    rows = run(READ) or []
    rows = rows if isinstance(rows, list) else [rows]
    return {r["name"]: bool(r["enabled"]) for r in rows}


def apply(cfg: dict) -> Outcome:
    before = read_state()
    targets = [p for p in cfg["profiles"] if not before.get(p)]
    if not targets:
        return Outcome("succeeded", "Already compliant: firewall enabled on " + ", ".join(cfg["profiles"]),
                       {"profiles": before, "changed": []}, before)
    if not cfg.get("enforce", True):
        return Outcome("needs_attention", f"Report-only policy: firewall disabled on {', '.join(targets)}",
                       {"profiles": before, "changed": []}, before)
    changed = []
    for p in targets:
        run(SET, {"PROFILE": p.capitalize(), "VALUE": "True"})
        changed.append(p)
    after = read_state()
    ok = all(after.get(p) for p in cfg["profiles"])
    return Outcome("succeeded" if ok else "failed", f"Enabled firewall on {', '.join(changed)}",
                   {"profiles": before, "changed": changed}, after)


def remove(previous: dict) -> Outcome:
    changed = previous.get("changed") or []
    for p in changed:
        if previous.get("profiles", {}).get(p) is False:
            run(SET, {"PROFILE": p.capitalize(), "VALUE": "False"})
    return Outcome("succeeded", f"Restored previous firewall state on {', '.join(changed) or 'no profiles'}",
                   {}, read_state())
