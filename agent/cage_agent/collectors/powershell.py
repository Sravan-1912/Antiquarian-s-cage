"""Read-only PowerShell queries from a fixed, code-reviewed allowlist.

Nothing here accepts input from the server or the network: callers select a query by name. Phase 3 policy
*changes* will run in the separate privileged broker, not in this collector process."""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import json
import subprocess
from typing import Any

QUERIES: dict[str, str] = {
    "computer_system": "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory",
    "bios": "Get-CimInstance Win32_BIOS | Select-Object SerialNumber,SMBIOSBIOSVersion",
    "processor": "Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,"
                 "NumberOfLogicalProcessors,MaxClockSpeed",
    "operating_system": "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,"
                        "OSArchitecture,@{n='InstallDate';e={$_.InstallDate.ToString('o')}},"
                        "@{n='LastBootUpTime';e={$_.LastBootUpTime.ToString('o')}}",
    "firewall": "Get-NetFirewallProfile | Select-Object Name,Enabled",
    "defender": "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
                "@{n='SignatureAge';e={$_.AntivirusSignatureAge}},AntivirusSignatureVersion",
    "secure_boot": "Confirm-SecureBootUEFI",
    "bitlocker": "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object MountPoint,"
                 "@{n='ProtectionStatus';e={[string]$_.ProtectionStatus}},"
                 "@{n='VolumeStatus';e={[string]$_.VolumeStatus}},EncryptionPercentage",
    "guest_account": "Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Select-Object Name,Enabled",
    "smb1": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
    "last_update": "Get-CimInstance Win32_QuickFixEngineering | Where-Object { $_.InstalledOn } | "
                   "Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,"
                   "@{n='InstalledOn';e={$_.InstalledOn.ToString('o')}}",
    "usb_storage": "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "
                   "'USBSTOR*' -and $_.Class -eq 'DiskDrive' } | Select-Object FriendlyName,InstanceId",
    "credential_guard": "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
                        "-ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning",
}


class QueryError(Exception):
    pass


def run(name: str, timeout: int = 45) -> Any:
    script = QUERIES[name]  # KeyError for anything not on the allowlist
    cmd = [exe("powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
           f"$ErrorActionPreference='Stop'; {script} | ConvertTo-Json -Depth 3 -Compress"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QueryError(f"{name}: {exc.__class__.__name__}") from exc
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip().splitlines()
        raise QueryError(f"{name}: {msg[0][:200] if msg else 'failed'}")
    out = res.stdout.strip()
    return json.loads(out) if out else None
