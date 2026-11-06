"""USB storage control.

* read_only:     StorageDevicePolicies\\WriteProtect = 1 (applies to newly mounted removable storage).
* block_storage: without allowlist → USBSTOR service Start = 4 (USB mass-storage driver disabled).
                 with allowlist    → Device Installation Restrictions: deny removable devices, allow listed IDs.
                 (Installation restrictions affect *new* device installs; already-installed devices keep working
                 until removed. Honoured by Pro/Enterprise/Education; Home support is not guaranteed.)
* allow:         restores defaults by rolling back.
"""
from __future__ import annotations

from cage_agent.policies import Outcome
from cage_agent.policies import registry as reg

USBSTOR = r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR"
WP = r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
RESTR = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
ALLOW_IDS = RESTR + r"\AllowDeviceIDs"


def apply(cfg: dict) -> Outcome:
    mode = cfg["mode"]
    values: list[tuple[str, str, object, str]] = []
    if mode == "read_only":
        values.append((WP, "WriteProtect", 1, "dword"))
    elif mode == "block_storage" and not cfg.get("allowlist"):
        values.append((USBSTOR, "Start", 4, "dword"))
    elif mode == "block_storage":
        values += [(RESTR, "DenyRemovableDevices", 1, "dword"), (RESTR, "AllowDeviceIDs", 1, "dword")]
        values += [(ALLOW_IDS, str(i + 1), dev, "sz") for i, dev in enumerate(cfg["allowlist"])]
    if not values:
        return Outcome("succeeded", "Mode 'allow': no restrictions applied", {}, {"mode": "allow"})
    previous = reg.apply_values(values)
    current = {f"{p}\\{n}": reg.read(p, n) for p, n, _, _ in values}
    detail = {"read_only": "Removable storage set to read-only",
              "block_storage": "USB mass storage blocked" + (f" except {len(cfg.get('allowlist', []))} allowlisted device(s)"
                                                             if cfg.get("allowlist") else "")}[mode]
    return Outcome("succeeded", detail + " (takes effect for newly connected devices)", {"registry": previous}, current)


def remove(previous: dict) -> Outcome:
    reg.restore_values(previous.get("registry", {}))
    return Outcome("succeeded", "Restored previous USB storage configuration")
