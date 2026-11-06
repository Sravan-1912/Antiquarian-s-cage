"""BitLocker policy: verification only. The agent deliberately does NOT start encryption: doing so without a verified,
escrowed recovery key risks permanent data loss and lockouts. Non-compliant devices are reported for a guided,
human-supervised remediation."""
from __future__ import annotations

from cage_agent.policies import Outcome
from cage_agent.policies.ps import run

READ = ("Get-BitLockerVolume -MountPoint $env:SystemDrive | ForEach-Object { [pscustomobject]@{ "
        "mount = $_.MountPoint; protection = [string]$_.ProtectionStatus; method = [string]$_.EncryptionMethod; "
        "status = [string]$_.VolumeStatus; percent = $_.EncryptionPercentage } }")


def apply(cfg: dict) -> Outcome:
    state = run(READ) or {}
    encrypted = state.get("protection") == "On"
    method_ok = state.get("method") in cfg.get("allowed_methods", [])
    if not cfg.get("require_system_drive_encryption", True) or (encrypted and method_ok):
        return Outcome("succeeded", f"System drive protection {state.get('protection')} ({state.get('method')})",
                       {}, state)
    if encrypted:
        return Outcome("needs_attention", f"Encrypted with non-approved method {state.get('method')}", {}, state)
    return Outcome("needs_attention", "System drive is not BitLocker-protected. Automatic encryption is disabled by "
                   "design; escrow a recovery key and enable BitLocker under supervision.", {}, state)


def remove(previous: dict) -> Outcome:
    return Outcome("succeeded", "No changes were made by this policy; nothing to roll back")
