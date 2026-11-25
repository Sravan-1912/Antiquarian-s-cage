"""Best-effort Wi-Fi access-point scan for network-based geolocation.

The agent only *scans* nearby access points (MAC + signal); the backend resolves a position from them (via a
geolocation API when a key is configured) or falls back to IP-based geolocation. No position is computed here and no
API key ever reaches the endpoint. Read-only, unprivileged, cross-platform, and never raises — a failed scan just
returns an empty list and the server uses the IP fallback.
"""
from __future__ import annotations

import re
import subprocess
import sys

_CREATE_NO_WINDOW = 0x08000000


def _run(args: list[str], timeout: int = 20) -> str:
    try:
        flags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, creationflags=flags)
        return r.stdout or ""
    except Exception:  # noqa: BLE001 — scanning is best-effort; any failure → IP fallback server-side
        return ""


def _pct_to_dbm(pct: int | None) -> int | None:
    # Windows/nmcli report signal quality as 0–100%. Approximate dBm (what geolocation APIs expect).
    if pct is None:
        return None
    return max(-100, min(-20, pct // 2 - 100))


def _scan_windows() -> list[dict]:
    out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    aps: list[dict] = []
    mac: str | None = None
    signal: int | None = None
    chan: int | None = None
    for line in out.splitlines():
        m = re.search(r"BSSID\s*\d+\s*:\s*([0-9A-Fa-f:]{17})", line)
        if m:
            if mac:
                aps.append({"mac": mac, "signal_dbm": _pct_to_dbm(signal), "channel": chan})
            mac, signal, chan = m.group(1).lower(), None, None
            continue
        m = re.search(r"Signal\s*:\s*(\d+)%", line)
        if m:
            signal = int(m.group(1))
            continue
        m = re.search(r"Channel\s*:\s*(\d+)", line)
        if m:
            chan = int(m.group(1))
    if mac:
        aps.append({"mac": mac, "signal_dbm": _pct_to_dbm(signal), "channel": chan})
    return aps


def _scan_linux() -> list[dict]:
    # nmcli -t escapes the ':' inside the BSSID as '\:'; split on unescaped colons, then unescape.
    out = _run(["nmcli", "-t", "-f", "BSSID,SIGNAL,CHAN", "dev", "wifi"])
    aps: list[dict] = []
    for line in out.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line.strip())]
        if not parts or not re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[0]):
            continue
        signal = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        chan = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
        aps.append({"mac": parts[0].lower(), "signal_dbm": _pct_to_dbm(signal), "channel": chan})
    return aps


def scan_access_points(limit: int = 30) -> list[dict]:
    """Return nearby Wi-Fi access points as [{mac, signal_dbm, channel}], strongest first. Empty when no Wi-Fi."""
    try:
        aps = _scan_windows() if sys.platform == "win32" else _scan_linux() if sys.platform.startswith("linux") else []
    except Exception:  # noqa: BLE001
        aps = []
    # de-dup by MAC, strongest signal wins, strongest first
    best: dict[str, dict] = {}
    for ap in aps:
        cur = best.get(ap["mac"])
        if cur is None or (ap["signal_dbm"] or -999) > (cur["signal_dbm"] or -999):
            best[ap["mac"]] = ap
    ordered = sorted(best.values(), key=lambda a: a["signal_dbm"] if a["signal_dbm"] is not None else -999, reverse=True)
    return ordered[:limit]
