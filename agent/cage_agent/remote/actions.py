"""Remote one-shot actions. Each returns an Outcome; none accepts free-form commands.

* inspect          (agent)  live status snapshot — read-only
* lock             (agent in an interactive session → LockWorkStation; broker in session 0 → WTSDisconnectSession)
* restart          (broker) shutdown.exe /r with a mandatory warning delay and message; cancellable
* restart_cancel   (broker) shutdown.exe /a
* account.*        (broker) disable / enable a local account, remove it from Administrators — refuses to disable or
                   demote the last enabled administrator so nobody is locked out of the device
"""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import ctypes
import os
import subprocess
import sys
import time

import psutil

from cage_agent.policies import ElevationRequired, Outcome
from cage_agent.policies.ps import PSError, run

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _session_id() -> int:
    sid = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    return sid.value


# ---------------------------------------------------------------------------------------------- inspect
LOCAL_USERS = ("Get-LocalUser | ForEach-Object { [pscustomobject]@{ name = $_.Name; enabled = [bool]$_.Enabled; "
               "last_logon = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { $null }; sid = $_.SID.Value } }")
ADMINS = ("Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [pscustomobject]@{ name = $_.Name; "
          "source = [string]$_.PrincipalSource } }")


def inspect(_: dict) -> Outcome:
    vm = psutil.virtual_memory()
    data = {
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "cpu_percent": psutil.cpu_percent(interval=1.0),
        "memory_percent": vm.percent,
        "logged_on_users": sorted({u.name for u in psutil.users()}),
        "process_count": len(psutil.pids()),
        "disks": [{"mount": p.mountpoint, "free_percent": round(100 - psutil.disk_usage(p.mountpoint).percent, 1)}
                  for p in psutil.disk_partitions(all=False) if p.fstype and "cdrom" not in p.opts][:10],
    }
    try:
        users = run(LOCAL_USERS) or []
        data["local_accounts"] = users if isinstance(users, list) else [users]
    except (PSError, ElevationRequired) as e:
        data["local_accounts_error"] = str(e)[:200]
    try:
        admins = run(ADMINS) or []
        data["administrators"] = admins if isinstance(admins, list) else [admins]
    except (PSError, ElevationRequired) as e:
        data["administrators_error"] = str(e)[:200]
    return Outcome("succeeded", "Status collected", {}, data)


# ---------------------------------------------------------------------------------------------- lock
def lock(_: dict) -> Outcome:
    if sys.platform != "win32":
        return Outcome("failed", "Not Windows")
    if _session_id() != 0:  # running inside the user's interactive session
        if not ctypes.windll.user32.LockWorkStation():
            return Outcome("failed", f"LockWorkStation failed ({ctypes.GetLastError()})")
        return Outcome("succeeded", "Workstation locked")
    import win32ts  # session 0 (service): disconnect the active console session → lock screen
    console = win32ts.WTSGetActiveConsoleSessionId()
    if console == 0xFFFFFFFF:
        return Outcome("needs_attention", "No interactive user session to lock")
    try:
        win32ts.WTSDisconnectSession(win32ts.WTS_CURRENT_SERVER_HANDLE, console, False)
    except Exception as exc:  # pywintypes.error
        if getattr(exc, "winerror", None) == 5:
            raise ElevationRequired("locking another session requires SYSTEM/administrator") from exc
        raise
    return Outcome("succeeded", f"Console session {console} disconnected (locked)")


# ---------------------------------------------------------------------------------------------- restart
def _shutdown(args: list[str]) -> subprocess.CompletedProcess:
    r = subprocess.run([exe("shutdown.exe"), *args], capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW)
    if r.returncode == 5:
        raise ElevationRequired("shutdown.exe: access denied")
    return r


def restart(p: dict) -> Outcome:
    delay, msg = int(p["delay_seconds"]), str(p["message"])
    r = _shutdown(["/r", "/t", str(delay), "/c", msg[:200], "/d", "p:4:1"])  # planned: application maintenance
    if r.returncode == 1190:  # a shutdown is already scheduled
        return Outcome("needs_attention", "A restart/shutdown is already scheduled on this device")
    if r.returncode != 0:
        return Outcome("failed", f"shutdown.exe exit {r.returncode}: {(r.stderr or r.stdout).strip()[:200]}")
    return Outcome("succeeded", f"Restart scheduled in {delay} s with on-screen warning; cancellable", {},
                   {"restart_in_seconds": delay})


def restart_cancel(_: dict) -> Outcome:
    r = _shutdown(["/a"])
    if r.returncode == 1116:  # no shutdown in progress
        return Outcome("succeeded", "No restart was scheduled")
    if r.returncode != 0:
        return Outcome("failed", f"shutdown.exe /a exit {r.returncode}")
    return Outcome("succeeded", "Scheduled restart cancelled")


# ---------------------------------------------------------------------------------------------- accounts
def _accounts() -> tuple[list[dict], set[str]]:
    users = run(LOCAL_USERS) or []
    users = users if isinstance(users, list) else [users]
    admins = run(ADMINS) or []
    admins = admins if isinstance(admins, list) else [admins]
    admin_names = {a["name"].split("\\")[-1].lower() for a in admins if a.get("source") in ("Local", "1")}
    return users, admin_names


def _enabled_local_admins(users: list[dict], admin_names: set[str]) -> set[str]:
    return {u["name"].lower() for u in users if u["enabled"] and u["name"].lower() in admin_names}


def _find(users: list[dict], name: str) -> dict | None:
    return next((u for u in users if u["name"].lower() == name.lower()), None)


SET_ENABLED = "if ($env:CAGE_ARG_ENABLE -eq '1') { Enable-LocalUser -Name $env:CAGE_ARG_USER } else { Disable-LocalUser -Name $env:CAGE_ARG_USER }"
REMOVE_ADMIN = "Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $env:CAGE_ARG_USER"


def account_disable(p: dict) -> Outcome:
    users, admins = _accounts()
    u = _find(users, p["username"])
    if u is None:
        return Outcome("failed", f"No local account named {p['username']!r}")
    if not u["enabled"]:
        return Outcome("succeeded", "Account already disabled", {"enabled": False}, {"enabled": False})
    if _enabled_local_admins(users, admins) == {u["name"].lower()}:
        return Outcome("needs_attention", "Refused: this is the last enabled local administrator")
    run(SET_ENABLED, {"USER": u["name"], "ENABLE": "0"})
    return Outcome("succeeded", f"Local account {u['name']} disabled", {"enabled": True}, {"enabled": False})


def account_enable(p: dict) -> Outcome:
    users, _ = _accounts()
    u = _find(users, p["username"])
    if u is None:
        return Outcome("failed", f"No local account named {p['username']!r}")
    if u["enabled"]:
        return Outcome("succeeded", "Account already enabled", {"enabled": True}, {"enabled": True})
    run(SET_ENABLED, {"USER": u["name"], "ENABLE": "1"})
    return Outcome("succeeded", f"Local account {u['name']} enabled", {"enabled": False}, {"enabled": True})


def account_remove_admin(p: dict) -> Outcome:
    users, admins = _accounts()
    u = _find(users, p["username"])
    if u is None or u["name"].lower() not in admins:
        return Outcome("succeeded", "Account is not a local administrator", {}, {"administrator": False})
    if _enabled_local_admins(users, admins) == {u["name"].lower()}:
        return Outcome("needs_attention", "Refused: this is the last enabled local administrator")
    run(REMOVE_ADMIN, {"USER": u["name"]})
    return Outcome("succeeded", f"{u['name']} removed from Administrators", {"administrator": True}, {"administrator": False})


def close_quick_assist(_: dict) -> Outcome:
    """Broker-only cleanup at the end of a remote-assistance session (Quick Assist runs at high integrity)."""
    subprocess.run([exe("taskkill.exe"), "/IM", "QuickAssist.exe", "/F"], capture_output=True, creationflags=NO_WINDOW)
    r = subprocess.run([exe("tasklist.exe"), "/FI", "IMAGENAME eq QuickAssist.exe", "/NH"], capture_output=True, text=True,
                       creationflags=NO_WINDOW)
    if "QuickAssist.exe" in r.stdout:
        return Outcome("failed", "Quick Assist is still running after termination attempt")
    return Outcome("succeeded", "Quick Assist closed")


HANDLERS = {
    "device.inspect": inspect, "device.lock": lock, "device.restart": restart, "device.restart_cancel": restart_cancel,
    "account.disable": account_disable, "account.enable": account_enable, "account.remove_admin": account_remove_admin,
    "assist.end": close_quick_assist,
}
