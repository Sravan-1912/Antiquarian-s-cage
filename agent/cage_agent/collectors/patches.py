"""Operating-system patch status: how many updates are pending (by severity), whether a reboot is pending, and when
the endpoint was last patched. Read-only, best-effort, cross-platform; never raises (returns partial/empty data).

Windows uses the Windows Update Agent COM API (the pending search can take a while, so this runs on the slow
inventory cadence, not every heartbeat). Linux uses apt/dnf.
"""
from __future__ import annotations

import logging
import subprocess
import sys

log = logging.getLogger("cage_agent.patches")
_CREATE_NO_WINDOW = 0x08000000


def _run(args: list[str], timeout: int = 40) -> str:
    try:
        flags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, creationflags=flags).stdout or ""
    except Exception:  # noqa: BLE001
        return ""


def _win_reboot_pending() -> bool:
    try:
        import winreg
        for root, path in (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"),
        ):
            try:
                winreg.OpenKey(root, path).Close()
                return True
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return False


def _win_last_patched() -> str | None:
    # Most-recent hotfix InstalledOn (fast, from the servicing stack).
    out = _run(["wmic", "qfe", "get", "InstalledOn", "/format:csv"], timeout=20)
    dates = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        for p in parts:
            # dates look like 11/20/2026 or 20-11-2026
            if p and any(ch.isdigit() for ch in p) and ("/" in p or "-" in p) and len(p) >= 8:
                dates.append(p)
    return max(dates) if dates else None


def _win_pending() -> dict:
    """Count not-installed updates via the Windows Update Agent, classified by MSRC severity. Slow + network-bound."""
    out = {"pending_total": None, "pending_critical": None, "pending_important": None}
    try:
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        try:
            searcher = win32com.client.Dispatch("Microsoft.Update.Session").CreateUpdateSearcher()
            result = searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            total = crit = imp = 0
            for u in result.Updates:
                total += 1
                sev = (u.MsrcSeverity or "").lower()
                if sev == "critical":
                    crit += 1
                elif sev == "important":
                    imp += 1
            out = {"pending_total": total, "pending_critical": crit, "pending_important": imp}
        finally:
            pythoncom.CoUninitialize()
    except Exception as exc:  # noqa: BLE001 — WU unavailable/offline/slow: report nulls, don't fail inventory
        log.debug("windows update search skipped: %s", exc)
    return out


def _linux_pending() -> dict:
    out = {"pending_total": None, "pending_critical": None, "pending_important": None}
    text = _run(["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"], timeout=40)
    if text:
        total = sum(1 for ln in text.splitlines() if ln.startswith("Inst "))
        sec = sum(1 for ln in text.splitlines() if ln.startswith("Inst ") and "security" in ln.lower())
        return {"pending_total": total, "pending_critical": sec, "pending_important": None}
    text = _run(["dnf", "-q", "check-update"], timeout=40)
    if text:
        total = sum(1 for ln in text.splitlines() if ln and not ln.startswith(("Last metadata", "Obsoleting")) and len(ln.split()) >= 3)
        out["pending_total"] = total
    return out


def collect() -> dict:
    """Return {pending_total, pending_critical, pending_important, reboot_pending, last_patched} (values may be None)."""
    try:
        if sys.platform == "win32":
            data = _win_pending()
            data["reboot_pending"] = _win_reboot_pending()
            data["last_patched"] = _win_last_patched()
            return data
        if sys.platform.startswith("linux"):
            data = _linux_pending()
            data["reboot_pending"] = False
            data["last_patched"] = None
            return data
    except Exception as exc:  # noqa: BLE001
        log.debug("patch status skipped: %s", exc)
    return {"pending_total": None, "pending_critical": None, "pending_important": None, "reboot_pending": False, "last_patched": None}
