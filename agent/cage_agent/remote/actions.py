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


def _top_processes(n: int = 8) -> list[dict]:
    procs = []
    for pr in psutil.process_iter(["pid", "name", "memory_percent"]):
        try:
            procs.append(pr.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    top = sorted(procs, key=lambda x: x.get("memory_percent") or 0, reverse=True)[:n]
    return [{"pid": p["pid"], "name": (p.get("name") or "?")[:48], "mem_percent": round(p.get("memory_percent") or 0, 1)}
            for p in top]


def inspect(_: dict) -> Outcome:
    vm = psutil.virtual_memory()
    data = {
        "top_processes": _top_processes(),
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


def shutdown(p: dict) -> Outcome:
    delay, msg = int(p["delay_seconds"]), str(p["message"])
    r = _shutdown(["/s", "/t", str(delay), "/c", msg[:200], "/d", "p:4:1"])  # planned: application maintenance
    if r.returncode == 1190:  # a shutdown is already scheduled
        return Outcome("needs_attention", "A restart/shutdown is already scheduled on this device")
    if r.returncode != 0:
        return Outcome("failed", f"shutdown.exe exit {r.returncode}: {(r.stderr or r.stdout).strip()[:200]}")
    return Outcome("succeeded", f"Power-off scheduled in {delay} s with an on-screen warning; cancellable", {},
                   {"shutdown_in_seconds": delay})


def logoff(_: dict) -> Outcome:
    import win32ts
    console = win32ts.WTSGetActiveConsoleSessionId()
    if console == 0xFFFFFFFF:
        return Outcome("needs_attention", "No interactive user session to log off")
    try:
        win32ts.WTSLogoffSession(win32ts.WTS_CURRENT_SERVER_HANDLE, console, False)
    except Exception as exc:  # pywintypes.error
        if getattr(exc, "winerror", None) == 5:
            raise ElevationRequired("logging off another session requires SYSTEM/administrator") from exc
        raise
    return Outcome("succeeded", f"Logged off console session {console}")


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


# ------------------------------------------------------------------------------------------- remote desktop (RDP)
def _lan_ip() -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is sent; just picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()


def _rdp_listener_up(timeout: float = 8.0) -> bool:
    """True once something is listening on 127.0.0.1:3389. On Pro/Enterprise the listener starts within a couple of
    seconds of enabling RDP; on Windows Home there is no RDP host, so it never comes up."""
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", 3389)) == 0:
                return True
        time.sleep(0.5)
    return False


def _windows_edition_hint() -> str:
    try:
        import platform
        ed = (platform.win32_edition() or "")
    except Exception:  # noqa: BLE001
        ed = ""
    # Home editions report "Core" / "CoreSingleLanguage" / "CoreN"; they cannot host Remote Desktop.
    return " (this endpoint runs a Windows Home edition, which cannot host Remote Desktop)" \
        if ed.lower().startswith("core") else ""


def rdp_enable(_: dict) -> Outcome:
    """Broker-only: turn on native Windows Remote Desktop and open the firewall for the session. The agent only calls
    this once it is already showing the mandatory on-screen banner, so RDP is never enabled silently."""
    subprocess.run([exe("reg.exe"), "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                    "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f"],
                   capture_output=True, creationflags=NO_WINDOW, check=True)
    subprocess.run([exe("netsh.exe"), "advfirewall", "firewall", "set", "rule", "group=remote desktop",
                    "new", "enable=Yes"], capture_output=True, creationflags=NO_WINDOW)
    # Verify a Remote Desktop host actually came up. On Windows Home it never will, so fail with a clear,
    # actionable message instead of letting the operator's mstsc hit a cryptic "can't connect" dialog later.
    if not _rdp_listener_up():
        rdp_disable(_)  # revert the registry/firewall changes we just made — the session did not start
        return Outcome("failed",
                       "Remote Desktop could not be enabled on this endpoint" + _windows_edition_hint() +
                       ". Use Remote Assistance instead.",
                       {"rdp_enabled": False}, {"rdp_enabled": False})
    return Outcome("succeeded", "Remote Desktop enabled for this session", {"rdp_enabled": False},
                   {"rdp_enabled": True, "connection": f"{_lan_ip()}:3389"})


def rdp_disable(_: dict) -> Outcome:
    """Broker-only: turn Remote Desktop back off and close the firewall at the end of the session."""
    subprocess.run([exe("reg.exe"), "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                    "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"],
                   capture_output=True, creationflags=NO_WINDOW, check=True)
    subprocess.run([exe("netsh.exe"), "advfirewall", "firewall", "set", "rule", "group=remote desktop",
                    "new", "enable=No"], capture_output=True, creationflags=NO_WINDOW)
    return Outcome("succeeded", "Remote Desktop disabled", {"rdp_enabled": True}, {"rdp_enabled": False})


_ISO_RULES = ("CageIsolation-Backend", "CageIsolation-DNS", "CageIsolation-DNS-TCP", "CageIsolation-DHCP")


def isolate(p: dict) -> Outcome:
    """Broker-only: network-isolate (contain) the endpoint — block all traffic EXCEPT the agent→backend management
    channel (so the endpoint can still be released) + DNS/DHCP. Reversible with release()."""
    host = str(p.get("server_host") or "").strip()
    ips: set[str] = set()
    if host:
        import socket
        try:
            ips = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        except OSError:
            ips = set()
    if host and not ips:
        # Refuse rather than cut the endpoint off from the only channel that can release it.
        return Outcome("failed", f"Could not resolve the backend host ({host}); not isolating (would cut off management).",
                       {"isolated": False}, {"isolated": False})
    subprocess.run([exe("netsh.exe"), "advfirewall", "set", "allprofiles", "firewallpolicy",
                    "blockinbound,blockoutbound"], capture_output=True, creationflags=NO_WINDOW, check=True)

    def allow(name: str, *args: str) -> None:
        subprocess.run([exe("netsh.exe"), "advfirewall", "firewall", "add", "rule", f"name={name}",
                        "dir=out", "action=allow", *args], capture_output=True, creationflags=NO_WINDOW)

    if ips:
        allow("CageIsolation-Backend", f"remoteip={','.join(sorted(ips))}")
    allow("CageIsolation-DNS", "protocol=UDP", "remoteport=53")
    allow("CageIsolation-DNS-TCP", "protocol=TCP", "remoteport=53")
    allow("CageIsolation-DHCP", "protocol=UDP", "remoteport=67-68")
    return Outcome("succeeded", f"Endpoint isolated — network locked to the management channel ({host or 'backend'})",
                   {"isolated": False}, {"isolated": True, "allowed_ips": sorted(ips)})


def release(_: dict) -> Outcome:
    """Broker-only: lift network isolation — restore the default firewall policy and remove the isolation allow-rules."""
    subprocess.run([exe("netsh.exe"), "advfirewall", "set", "allprofiles", "firewallpolicy",
                    "blockinbound,allowoutbound"], capture_output=True, creationflags=NO_WINDOW, check=True)
    for name in _ISO_RULES:
        subprocess.run([exe("netsh.exe"), "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True, creationflags=NO_WINDOW)
    return Outcome("succeeded", "Endpoint released from isolation", {"isolated": True}, {"isolated": False})


HANDLERS = {
    "device.inspect": inspect, "device.lock": lock, "device.restart": restart, "device.restart_cancel": restart_cancel,
    "device.shutdown": shutdown, "device.logoff": logoff,
    "account.disable": account_disable, "account.enable": account_enable, "account.remove_admin": account_remove_admin,
    "device.isolate": isolate, "device.release": release,
    "assist.end": close_quick_assist, "rdp.start": rdp_enable, "rdp.end": rdp_disable,
}

from cage_agent.remote.script_runner import run_script  # noqa: E402 — shared across platforms
HANDLERS["script.run"] = run_script

# On Linux the POSIX implementations replace the whole handler set (see remote/linux_actions.py).
if sys.platform.startswith("linux"):
    from cage_agent.remote import linux_actions
    HANDLERS = linux_actions.HANDLERS
