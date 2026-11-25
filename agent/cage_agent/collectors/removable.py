"""Detect newly-connected removable (USB) storage volumes and emit telemetry events for the server-side detection
engine. Read-only, unprivileged, cross-platform, and never raises — a failed scan simply yields no events."""
from __future__ import annotations

import ctypes
import logging
import os
import re
import string
import sys

log = logging.getLogger("cage_agent.removable")
_DRIVE_REMOVABLE = 2


def _win_volume(root: str) -> dict:
    name = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_ulong(0)
    try:
        ctypes.windll.kernel32.GetVolumeInformationW(root, name, 261, ctypes.byref(serial), None, None, fs, 261)
    except Exception:  # noqa: BLE001
        return {"label": None, "serial": None, "fs": None}
    return {"label": name.value or None, "serial": f"{serial.value:08X}" if serial.value else None, "fs": fs.value or None}


def _win_removable() -> dict[str, dict]:
    out: dict[str, dict] = {}
    try:
        k32 = ctypes.windll.kernel32
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if k32.GetDriveTypeW(root) == _DRIVE_REMOVABLE:
                out[root] = {"drive": f"{letter}:", **_win_volume(root)}
    except Exception:  # noqa: BLE001
        pass
    return out


def _linux_removable() -> dict[str, dict]:
    out: dict[str, dict] = {}
    try:
        import psutil
        for p in psutil.disk_partitions(all=False):
            base = re.sub(r"\d+$", "", os.path.basename(p.device))
            try:
                if open(f"/sys/block/{base}/removable").read().strip() == "1":  # noqa: SIM115
                    out[p.device] = {"drive": p.mountpoint, "label": None, "serial": base, "fs": p.fstype or None}
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


class RemovableStorage:
    """Emits a `usb_storage` event the first time each removable volume appears (primes silently on first call)."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self.primed = False

    def _current(self) -> dict[str, dict]:
        if sys.platform == "win32":
            return _win_removable()
        if sys.platform.startswith("linux"):
            return _linux_removable()
        return {}

    def collect(self) -> list[dict]:
        try:
            cur = self._current()
        except Exception as exc:  # noqa: BLE001
            log.debug("removable scan skipped: %s", exc)
            return []
        if not self.primed:
            self._seen = set(cur)
            self.primed = True
            return []
        new = [k for k in cur if k not in self._seen]
        self._seen = set(cur)
        return [{"type": "usb_storage", "data": cur[k]} for k in new]
