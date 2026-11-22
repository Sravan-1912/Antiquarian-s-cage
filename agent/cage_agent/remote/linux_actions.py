"""Linux remote one-shot actions — the POSIX counterparts of remote/actions.py. Allowlisted, no free-form commands.

* inspect          read-only live snapshot (psutil + local accounts from the user database)
* lock             loginctl lock-sessions (locks the active graphical session)
* restart          shutdown -r with a warning delay and broadcast message; cancellable
* restart_cancel   shutdown -c
* account.*         lock / unlock a local account (passwd -l / usermod), remove it from the sudo/wheel groups —
                    refuses to disable or de-sudo the last remaining able-to-login sudoer so nobody is locked out.

Privileged actions (restart, account.*) require the agent to run as root (the Linux equivalent of the Windows broker).
"""
from __future__ import annotations

import math
import pwd
import shutil
import subprocess
import time
from pathlib import Path

import psutil

from cage_agent.policies import ElevationRequired, Outcome

SUDO_GROUPS = ("sudo", "wheel")


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    exe = shutil.which(cmd[0])
    if not exe:
        raise FileNotFoundError(f"{cmd[0]} not found")
    r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0 and ("permission denied" in (r.stderr or "").lower() or "must be root" in (r.stderr or "").lower()
                              or "not permitted" in (r.stderr or "").lower()):
        raise ElevationRequired(f"{cmd[0]}: {r.stderr.strip()[:200]}")
    return r


# --------------------------------------------------------------------------------------------- local accounts
def _local_users() -> list[dict]:
    """Real local login accounts (UID 0 or >= 1000 with a login shell), with enabled state from the shadow lock state.

    Reads /etc/shadow directly (the spwd module was removed in Python 3.13); needs root, which the agent has as a
    service. When /etc/shadow is unreadable, the enabled state is reported as unknown (None)."""
    shadow: dict[str, str] = {}
    try:
        for line in Path("/etc/shadow").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                shadow[parts[0]] = parts[1]
    except OSError:
        shadow = {}
    out = []
    for p in pwd.getpwall():
        if p.pw_uid != 0 and (p.pw_uid < 1000 or p.pw_uid >= 65534):
            continue
        if p.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""):
            continue
        pw = shadow.get(p.pw_name)
        enabled = None if pw is None else not (pw.startswith("!") or pw.startswith("*") or pw.startswith("!!"))
        out.append({"name": p.pw_name, "uid": p.pw_uid, "enabled": enabled, "shell": p.pw_shell})
    return out


def _sudoers() -> set[str]:
    import grp
    members: set[str] = set()
    for g in SUDO_GROUPS:
        try:
            members |= set(grp.getgrnam(g).gr_mem)
        except KeyError:
            continue
    return {m.lower() for m in members}


def _find(users: list[dict], name: str) -> dict | None:
    return next((u for u in users if u["name"].lower() == name.lower()), None)


def _enabled_sudoers(users: list[dict], sudoers: set[str]) -> set[str]:
    return {u["name"].lower() for u in users if u["name"].lower() in sudoers and u["enabled"] is not False}


# --------------------------------------------------------------------------------------------------- inspect
def _top_processes(n: int = 8) -> list[dict]:
    """Top processes by memory — a quick live resource view."""
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
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "cpu_percent": psutil.cpu_percent(interval=1.0),
        "memory_percent": vm.percent,
        "logged_on_users": sorted({u.name for u in psutil.users()}),
        "process_count": len(psutil.pids()),
        "disks": [{"mount": p.mountpoint, "free_percent": round(100 - psutil.disk_usage(p.mountpoint).percent, 1)}
                  for p in psutil.disk_partitions(all=False) if p.fstype and "cdrom" not in p.opts][:10],
        "top_processes": _top_processes(),
    }
    try:
        users = _local_users()
        sudoers = _sudoers()
        data["local_accounts"] = [{"name": u["name"], "enabled": u["enabled"],
                                   "sudo": u["name"].lower() in sudoers} for u in users]
        data["administrators"] = sorted(u["name"] for u in users if u["name"].lower() in sudoers)
    except Exception as e:  # noqa: BLE001
        data["local_accounts_error"] = str(e)[:200]
    return Outcome("succeeded", "Status collected", {}, data)


# --------------------------------------------------------------------------------------------------- lock
def lock(_: dict) -> Outcome:
    """Lock the interactive session. `loginctl lock-sessions` only signals logind (a desktop with no active locker,
    e.g. a root XFCE session, just blanks), so prefer `dm-tool lock` (the display manager actually switches to the
    greeter) and fall back through the common lockers. Returns on the first method that reports success."""
    # (command, human label, extra env). dm-tool needs the seat; harmless when already set.
    attempts = [
        (["dm-tool", "lock"], "display manager (dm-tool)"),
        (["loginctl", "lock-sessions"], "systemd-logind"),
        (["xdg-screensaver", "lock"], "xdg-screensaver"),
        (["xfce4-screensaver-command", "--lock"], "xfce4-screensaver"),
        (["light-locker-command", "--lock"], "light-locker"),
    ]
    tried, errors = [], []
    for cmd, label in attempts:
        if not shutil.which(cmd[0]):
            continue
        tried.append(label)
        try:
            r = _run(cmd)
        except FileNotFoundError:
            continue
        if r.returncode == 0:
            return Outcome("succeeded", f"Screen locked via {label}")
        errors.append(f"{cmd[0]}: {(r.stderr or r.stdout).strip()[:80]}")
    if not tried:
        return Outcome("needs_attention", "No screen locker found (install a display manager or light-locker/"
                                           "xscreensaver and run it in the desktop session)")
    return Outcome("needs_attention", "Lock signalled but no locker confirmed it (" + "; ".join(errors or tried)[:200]
                                      + "). On a root desktop session, lockers often blank without locking.")


# --------------------------------------------------------------------------------------------------- restart
def restart(p: dict) -> Outcome:
    delay, msg = int(p["delay_seconds"]), str(p["message"])
    minutes = max(1, math.ceil(delay / 60))   # shutdown granularity is whole minutes
    r = _run(["shutdown", "-r", f"+{minutes}", msg[:200]])
    if r.returncode != 0:
        return Outcome("failed", f"shutdown exit {r.returncode}: {(r.stderr or r.stdout).strip()[:200]}")
    return Outcome("succeeded", f"Restart scheduled in ~{minutes} min with a broadcast warning; cancellable", {},
                   {"restart_in_seconds": minutes * 60})


def restart_cancel(_: dict) -> Outcome:
    r = _run(["shutdown", "-c"])
    # shutdown -c returns non-zero when nothing is scheduled; treat that as success (idempotent).
    return Outcome("succeeded", "Scheduled restart/shutdown cancelled (if any was pending)")


# --------------------------------------------------------------------------------------------------- shutdown
def shutdown(p: dict) -> Outcome:
    delay, msg = int(p["delay_seconds"]), str(p["message"])
    minutes = max(1, math.ceil(delay / 60))
    r = _run(["shutdown", "-h", f"+{minutes}", msg[:200]])
    if r.returncode != 0:
        return Outcome("failed", f"shutdown exit {r.returncode}: {(r.stderr or r.stdout).strip()[:200]}")
    return Outcome("succeeded", f"Power-off scheduled in ~{minutes} min with a broadcast warning; cancellable", {},
                   {"shutdown_in_seconds": minutes * 60})


# ----------------------------------------------------------------------------------------------------- log off
def logoff(_: dict) -> Outcome:
    """Log off the active graphical session's user via logind."""
    if not shutil.which("loginctl"):
        return Outcome("needs_attention", "loginctl not available (no systemd-logind)")
    r = _run(["loginctl", "list-sessions", "--no-legend"])
    active = None
    for line in r.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        info = _run(["loginctl", "show-session", parts[0], "-p", "Active", "-p", "Type"]).stdout
        if "Active=yes" in info and ("Type=x11" in info or "Type=wayland" in info):
            active = parts[0]
            break
    if active is None:
        return Outcome("needs_attention", "No active graphical session to log off")
    rr = _run(["loginctl", "terminate-session", active])
    if rr.returncode != 0:
        return Outcome("failed", f"terminate-session failed: {(rr.stderr or rr.stdout).strip()[:200]}")
    return Outcome("succeeded", f"Logged off active session {active}")


# --------------------------------------------------------------------------------------------------- accounts
def account_disable(p: dict) -> Outcome:
    users = _local_users()
    u = _find(users, p["username"])
    if u is None:
        return Outcome("failed", f"No local account named {p['username']!r}")
    if u["enabled"] is False:
        return Outcome("succeeded", "Account already disabled", {"enabled": False}, {"enabled": False})
    if _enabled_sudoers(users, _sudoers()) == {u["name"].lower()}:
        return Outcome("needs_attention", "Refused: this is the last enabled administrator (sudoer)")
    _run(["usermod", "--lock", u["name"]])                       # lock the password
    _run(["usermod", "--expiredate", "1", u["name"]])            # expire the account (blocks all logins)
    return Outcome("succeeded", f"Local account {u['name']} disabled", {"enabled": True}, {"enabled": False})


def account_enable(p: dict) -> Outcome:
    users = _local_users()
    u = _find(users, p["username"])
    if u is None:
        return Outcome("failed", f"No local account named {p['username']!r}")
    if u["enabled"]:
        return Outcome("succeeded", "Account already enabled", {"enabled": True}, {"enabled": True})
    _run(["usermod", "--unlock", u["name"]])
    _run(["usermod", "--expiredate", "", u["name"]])
    return Outcome("succeeded", f"Local account {u['name']} enabled", {"enabled": False}, {"enabled": True})


def account_remove_admin(p: dict) -> Outcome:
    users = _local_users()
    sudoers = _sudoers()
    u = _find(users, p["username"])
    if u is None or u["name"].lower() not in sudoers:
        return Outcome("succeeded", "Account is not an administrator (sudoer)", {}, {"administrator": False})
    if _enabled_sudoers(users, sudoers) == {u["name"].lower()}:
        return Outcome("needs_attention", "Refused: this is the last enabled administrator (sudoer)")
    import grp
    removed = []
    for g in SUDO_GROUPS:
        try:
            if u["name"] in grp.getgrnam(g).gr_mem:
                _run(["gpasswd", "--delete", u["name"], g])
                removed.append(g)
        except KeyError:
            continue
    return Outcome("succeeded", f"{u['name']} removed from {', '.join(removed) or 'admin groups'}",
                   {"administrator": True}, {"administrator": False})


def close_quick_assist(_: dict) -> Outcome:
    return Outcome("succeeded", "No remote-assistance helper to close on Linux")


# ------------------------------------------------------------------------------------------------- remote desktop
def _lan_ip() -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is sent; just picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _rdp_listener_up(timeout: float = 12.0) -> bool:
    """True once xrdp is listening on 127.0.0.1:3389 (it can take a few seconds to come up after enable)."""
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", 3389)) == 0:
                return True
        time.sleep(0.5)
    return False


def _firewall_3389(opening: bool) -> None:
    """Best-effort open/close of TCP 3389 across ufw and firewalld. Silent if neither (or an inactive) firewall."""
    try:
        if shutil.which("ufw"):
            _run(["ufw", "allow", "3389/tcp"] if opening else ["ufw", "delete", "allow", "3389/tcp"], timeout=15)
        elif shutil.which("firewall-cmd"):
            _run(["firewall-cmd", "--add-port=3389/tcp" if opening else "--remove-port=3389/tcp"], timeout=15)
    except Exception:  # noqa: BLE001 - firewall is best-effort; xrdp + the relay still work without it
        pass


def rdp_enable(_: dict) -> Outcome:
    """Enable the Linux Remote Desktop host (xrdp) and open the firewall for the session. Requires root (the Linux
    broker-equivalent). The agent only calls this once the mandatory on-screen banner is already showing."""
    if not shutil.which("xrdp"):
        return Outcome("needs_attention",
                       "xrdp is not installed on this endpoint. Install it (e.g. 'sudo apt install xrdp') to allow "
                       "Remote Desktop, or use Remote Assistance instead.",
                       {"rdp_enabled": False}, {"rdp_enabled": False})
    try:
        _run(["systemctl", "enable", "--now", "xrdp"], timeout=40)
    except ElevationRequired:
        raise
    except Exception as exc:  # noqa: BLE001
        return Outcome("failed", f"Could not start xrdp: {str(exc)[:200]}", {"rdp_enabled": False},
                       {"rdp_enabled": False})
    _firewall_3389(True)
    if not _rdp_listener_up():
        return Outcome("failed", "xrdp did not start listening on port 3389 on this endpoint. Check 'systemctl status "
                       "xrdp' / that a desktop environment is installed.", {"rdp_enabled": False},
                       {"rdp_enabled": False})
    return Outcome("succeeded", "Remote Desktop (xrdp) enabled for this session", {"rdp_enabled": False},
                   {"rdp_enabled": True, "connection": f"{_lan_ip()}:3389"})


def rdp_disable(_: dict) -> Outcome:
    """Turn the Linux RDP host (xrdp) back off and close the firewall at the end of the session."""
    _firewall_3389(False)
    try:
        _run(["systemctl", "disable", "--now", "xrdp"], timeout=40)
    except Exception:  # noqa: BLE001 - make end-of-session teardown best-effort
        pass
    return Outcome("succeeded", "Remote Desktop (xrdp) disabled", {"rdp_enabled": True}, {"rdp_enabled": False})


_ISO_CHAIN = "CAGE_ISO"


def isolate(p: dict) -> Outcome:
    """Network-isolate the endpoint (root): block OUTBOUND traffic except the agent→backend channel (so it can still be
    released), DNS/DHCP, loopback and established connections. Reversible via release(). Uses an iptables chain."""
    host = str(p.get("server_host") or "").strip()
    ips: set[str] = set()
    if host:
        import socket
        try:
            ips = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        except OSError:
            ips = set()
    if host and not ips:
        return Outcome("failed", f"Could not resolve the backend host ({host}); not isolating (would cut off management).",
                       {"isolated": False}, {"isolated": False})
    if not shutil.which("iptables"):
        return Outcome("needs_attention", "iptables not available; cannot network-isolate this endpoint.",
                       {"isolated": False}, {"isolated": False})
    _run(["iptables", "-N", _ISO_CHAIN], timeout=10)  # may already exist
    _run(["iptables", "-F", _ISO_CHAIN], timeout=10)
    rules = [["-o", "lo", "-j", "ACCEPT"],
             ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
             *[["-d", ip, "-j", "ACCEPT"] for ip in sorted(ips)],
             ["-p", "udp", "--dport", "53", "-j", "ACCEPT"], ["-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
             ["-p", "udp", "--dport", "67:68", "-j", "ACCEPT"], ["-j", "DROP"]]
    for r in rules:
        _run(["iptables", "-A", _ISO_CHAIN, *r], timeout=10)
    _run(["iptables", "-C", "OUTPUT", "-j", _ISO_CHAIN], timeout=10)  # idempotent insert
    _run(["iptables", "-I", "OUTPUT", "1", "-j", _ISO_CHAIN], timeout=10)
    return Outcome("succeeded", f"Endpoint isolated — outbound locked to the management channel ({host or 'backend'})",
                   {"isolated": False}, {"isolated": True, "allowed_ips": sorted(ips)})


def release(_: dict) -> Outcome:
    """Lift network isolation (root): remove the iptables jump and chain."""
    for _ in range(4):  # remove any duplicate jumps
        if _run(["iptables", "-D", "OUTPUT", "-j", _ISO_CHAIN], timeout=10).returncode != 0:
            break
    _run(["iptables", "-F", _ISO_CHAIN], timeout=10)
    _run(["iptables", "-X", _ISO_CHAIN], timeout=10)
    return Outcome("succeeded", "Endpoint released from isolation", {"isolated": True}, {"isolated": False})


HANDLERS = {
    "device.inspect": inspect, "device.lock": lock, "device.restart": restart, "device.restart_cancel": restart_cancel,
    "device.shutdown": shutdown, "device.logoff": logoff,
    "account.disable": account_disable, "account.enable": account_enable, "account.remove_admin": account_remove_admin,
    "device.isolate": isolate, "device.release": release,
    "assist.end": close_quick_assist, "rdp.start": rdp_enable, "rdp.end": rdp_disable,
}

from cage_agent.remote.script_runner import run_script  # noqa: E402 — shared cross-platform runner
HANDLERS["script.run"] = run_script
