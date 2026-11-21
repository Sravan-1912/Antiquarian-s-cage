"""Linux OS and security-configuration facts. Read-only; no changes to the system. Every security check returns an
explicit state (enabled | disabled | partial | unknown | not_applicable); anything the agent cannot determine without
elevation it does not have is reported "unknown", never compliant. The server's compliance engine interprets these,
using the same check names as the Windows collector so one endpoint model covers both platforms."""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run a read-only command. The first element is resolved via PATH; missing tools return (127, '', 'not found')."""
    exe = shutil.which(cmd[0])
    if not exe:
        return 127, "", f"{cmd[0]} not found"
    try:
        r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _unknown(detail: str) -> dict:
    return {"state": "unknown", "detail": detail[:512], "data": {}}


def _na(detail: str) -> dict:
    return {"state": "not_applicable", "detail": detail[:512], "data": {}}


# --------------------------------------------------------------------------------------------------- OS inventory
def _os_release() -> dict:
    out: dict[str, str] = {}
    txt = _read("/etc/os-release") or ""
    for line in txt.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def os_info() -> dict:
    rel = _os_release()
    uname = platform.uname()
    install_date = None
    try:  # root filesystem birth time ≈ install date (best effort)
        st = os.stat("/")
        bt = getattr(st, "st_birthtime", None) or st.st_ctime
        install_date = datetime.fromtimestamp(bt, tz=timezone.utc).isoformat()
    except OSError:
        pass
    last_boot = None
    try:
        import psutil
        last_boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat()
    except Exception:  # noqa: BLE001
        pass
    name = rel.get("PRETTY_NAME") or f"{rel.get('NAME', 'Linux')} {rel.get('VERSION', uname.release)}".strip()
    return {
        "name": name[:128],
        "version": (rel.get("VERSION_ID") or uname.release)[:64],
        "build": uname.release[:64],                       # kernel release
        "edition": (rel.get("VARIANT") or rel.get("ID") or "linux")[:64],
        "architecture": (uname.machine or platform.machine())[:64],
        "install_date": install_date[:32] if install_date else None,
        "last_boot": last_boot[:32] if last_boot else None,
    }


def hardware_firmware() -> dict:
    """Manufacturer / model / serial from DMI (readable without root for product_name/vendor; serial often needs root)."""
    def dmi(f: str) -> str | None:
        v = (_read(f"/sys/class/dmi/id/{f}") or "").strip()
        return v[:128] or None
    return {"manufacturer": dmi("sys_vendor"), "model": dmi("product_name"), "serial": dmi("product_serial")}


# ------------------------------------------------------------------------------------------------- security checks
def firewall() -> dict:
    rc, out, _ = _run(["ufw", "status"])
    if rc == 0:
        active = "status: active" in out.lower()
        return {"state": "enabled" if active else "disabled", "detail": "ufw", "data": {"backend": "ufw"}}
    rc, out, _ = _run(["firewall-cmd", "--state"])
    if rc == 0:
        return {"state": "enabled" if out.strip() == "running" else "disabled",
                "detail": "firewalld", "data": {"backend": "firewalld"}}
    rc, out, _ = _run(["nft", "list", "ruleset"])
    if rc == 0:
        has_rules = bool(re.search(r"\bchain\b", out)) and ("drop" in out.lower() or "reject" in out.lower())
        return {"state": "enabled" if has_rules else "disabled", "detail": "nftables",
                "data": {"backend": "nftables"}}
    rc, out, _ = _run(["iptables", "-S"])
    if rc == 0:
        policy_drop = "-P INPUT DROP" in out or any(l.startswith("-A INPUT") and "DROP" in l for l in out.splitlines())
        return {"state": "enabled" if policy_drop else "disabled", "detail": "iptables",
                "data": {"backend": "iptables"}}
    return _unknown("no firewall tool found (ufw/firewalld/nft/iptables)")


def antivirus() -> dict:
    """Map to the server's 'defender' concept: an on-access AV. ClamAV's clamonacc is the common Linux equivalent."""
    rc, out, _ = _run(["systemctl", "is-active", "clamav-daemon"])
    clamd = rc == 0 and out.strip() == "active"
    rc2, out2, _ = _run(["systemctl", "is-active", "clamav-clamonacc"])
    onaccess = rc2 == 0 and out2.strip() == "active"
    sig_age = None
    log = _read("/var/log/clamav/freshclam.log") or ""
    m = re.findall(r"(\d{4}-\d{2}-\d{2})", log)
    if m:
        try:
            sig_age = (datetime.now(timezone.utc).date() - datetime.fromisoformat(m[-1]).date()).days
        except ValueError:
            pass
    if not clamd and not shutil.which("clamscan"):
        return {"state": "disabled", "detail": "no on-access antivirus detected (ClamAV not installed/running)",
                "data": {"antivirus_enabled": False, "real_time_protection": False, "service_enabled": False,
                         "signature_age_days": None, "signature_version": None}}
    return {"state": "enabled" if clamd and onaccess else "partial" if clamd else "disabled", "detail": "ClamAV",
            "data": {"antivirus_enabled": clamd, "real_time_protection": onaccess, "service_enabled": clamd,
                     "signature_age_days": sig_age, "signature_version": None}}


def secure_boot() -> dict:
    rc, out, _ = _run(["mokutil", "--sb-state"])
    if rc == 0:
        low = out.lower()
        if "enabled" in low:
            return {"state": "enabled", "detail": None, "data": {}}
        if "disabled" in low:
            return {"state": "disabled", "detail": None, "data": {}}
    if not Path("/sys/firmware/efi").exists():
        return _na("Legacy BIOS boot (Secure Boot not applicable)")
    return _unknown("mokutil unavailable (install mokutil to report Secure Boot)")


def disk_encryption() -> dict:
    """Server 'bitlocker' concept: is the root filesystem on a LUKS/dm-crypt device?"""
    rc, out, _ = _run(["findmnt", "-n", "-o", "SOURCE", "/"])
    src = out.strip() if rc == 0 else ""
    rc2, out2, _ = _run(["lsblk", "-o", "NAME,TYPE,MOUNTPOINT", "-rn"])
    encrypted = False
    if rc2 == 0:
        # A crypt device anywhere in root's parent chain shows TYPE=crypt.
        encrypted = any(parts[1] == "crypt" for parts in (l.split() for l in out2.splitlines()) if len(parts) >= 2
                        and (len(parts) < 3 or parts[2] in ("/", "")))
        if not encrypted:
            encrypted = " crypt " in f" {out2} " or "\tcrypt" in out2 or any(
                p.split()[1] == "crypt" for p in out2.splitlines() if len(p.split()) >= 2)
    return {"state": "enabled" if encrypted else "disabled",
            "detail": "LUKS/dm-crypt on root" if encrypted else "root filesystem is not encrypted",
            "data": {"root_source": src[:64], "encrypted": encrypted}}


def remote_access() -> dict:
    """Server 'remote_desktop' concept: SSH is Linux's remote access. Report whether sshd is listening and hardened."""
    rc, out, _ = _run(["systemctl", "is-active", "ssh"])
    rc2, out2, _ = _run(["systemctl", "is-active", "sshd"])
    active = (rc == 0 and out.strip() == "active") or (rc2 == 0 and out2.strip() == "active")
    cfg = _read("/etc/ssh/sshd_config") or ""
    def directive(name: str) -> str | None:
        m = re.search(rf"^\s*{name}\s+(\S+)", cfg, re.IGNORECASE | re.MULTILINE)
        return m.group(1).lower() if m else None
    password_auth = directive("PasswordAuthentication")
    root_login = directive("PermitRootLogin")
    # "nla_required"-style field reused by the server UI: here it means key-only auth (password auth disabled).
    return {"state": "enabled" if active else "disabled", "detail": "OpenSSH",
            "data": {"nla_required": password_auth == "no",
                     "permit_root_login": root_login, "password_authentication": password_auth}}


def screen_lock() -> dict:
    """GNOME/most desktops via gsettings. Headless servers have no interactive lock → not_applicable."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and not shutil.which("gsettings"):
        return _na("no graphical session (headless) — screen lock not applicable")
    rc, idle, _ = _run(["gsettings", "get", "org.gnome.desktop.session", "idle-delay"])
    rc2, lock_enabled, _ = _run(["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"])
    rc3, lock_delay, _ = _run(["gsettings", "get", "org.gnome.desktop.screensaver", "lock-delay"])
    if rc != 0 and rc2 != 0:
        return _unknown("gsettings unavailable or not a GNOME session")
    idle_secs = None
    m = re.search(r"(\d+)", idle or "")
    if m:
        idle_secs = int(m.group(1))
    enabled = "true" in (lock_enabled or "").lower()
    data = {"idle_delay_seconds": idle_secs, "lock_enabled": enabled, "lock_delay": (lock_delay or "").strip()[:32]}
    if enabled and idle_secs and 0 < idle_secs <= 3600:
        return {"state": "enabled", "detail": "screen lock on idle", "data": data}
    return {"state": "disabled", "detail": "no idle screen lock enforced", "data": data}


def os_updates() -> dict:
    """Server 'windows_update' concept: when was the system last updated, and is a reboot pending?"""
    pending_reboot = Path("/var/run/reboot-required").exists() or Path("/run/reboot-required").exists()
    last = None
    # Debian/Ubuntu: apt history; Fedora/RHEL: dnf/yum log mtime.
    for src, pat in (("/var/log/apt/history.log", r"End-Date:\s*([\d-]+\s+[\d:]+)"),):
        txt = _read(src)
        if txt:
            ms = re.findall(pat, txt)
            if ms:
                try:
                    last = datetime.strptime(ms[-1].strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
    if last is None:
        for p in ("/var/lib/dnf/history.sqlite", "/var/log/dnf.rpm.log", "/var/lib/rpm/Packages"):
            try:
                last = datetime.fromtimestamp(os.stat(p).st_mtime, tz=timezone.utc)
                break
            except OSError:
                continue
    if last is None:
        return {**_unknown("no package-manager history found"), "data": {"pending_reboot": pending_reboot}}
    days = max((datetime.now(timezone.utc) - last).days, 0)
    return {"state": "enabled", "detail": "last package update",
            "data": {"days_since_last_update": days, "last_update": last.isoformat()[:32],
                     "last_hotfix": None, "pending_reboot": pending_reboot}}


def account_policy() -> dict:
    """Password aging from /etc/login.defs; account lockout from pam_faillock/pam_tally2 if configured."""
    defs = _read("/etc/login.defs") or ""
    def defint(name: str) -> int | None:
        m = re.search(rf"^\s*{name}\s+(\d+)", defs, re.MULTILINE)
        return int(m.group(1)) if m else None
    max_age = defint("PASS_MAX_DAYS")
    min_len = defint("PASS_MIN_LEN")
    lockout_threshold = 0
    for conf in ("/etc/security/faillock.conf", "/etc/pam.d/system-auth", "/etc/pam.d/common-auth"):
        txt = _read(conf) or ""
        m = re.search(r"deny\s*=\s*(\d+)", txt)
        if m:
            lockout_threshold = int(m.group(1))
            break
    return {"state": "enabled" if lockout_threshold > 0 else "disabled", "detail": None,
            "data": {"lockout_threshold": lockout_threshold, "lockout_duration_minutes": None,
                     "lockout_window_minutes": None, "min_password_length": min_len,
                     "max_password_age_days": max_age if max_age and max_age < 99999 else 0}}


def audit_policy() -> dict:
    rc, out, _ = _run(["systemctl", "is-active", "auditd"])
    active = rc == 0 and out.strip() == "active"
    rc2, rules, _ = _run(["auditctl", "-l"])
    has_rules = rc2 == 0 and rules.strip() not in ("", "No rules")
    if not shutil.which("auditctl") and not active:
        return _unknown("auditd not installed")
    if rc2 != 0 and active:
        return _unknown("requires elevation to read audit rules")
    return {"state": "enabled" if active and has_rules else "partial" if active else "disabled", "detail": None,
            "data": {"auditd_active": active, "rules_loaded": has_rules}}


def usb_storage() -> dict:
    """Is USB mass-storage blocked? (modprobe blacklist / install-false, or usbguard running.)"""
    blocked = False
    for p in Path("/etc/modprobe.d").glob("*.conf") if Path("/etc/modprobe.d").is_dir() else []:
        txt = _read(str(p)) or ""
        if re.search(r"^\s*(blacklist\s+usb[-_]storage|install\s+usb[-_]storage\s+/bin/(true|false))", txt, re.MULTILINE):
            blocked = True
            break
    rc, out, _ = _run(["systemctl", "is-active", "usbguard"])
    usbguard = rc == 0 and out.strip() == "active"
    state = "disabled" if blocked else "partial" if usbguard else "enabled"  # 'enabled' = storage allowed
    return {"state": state, "detail": "USB mass storage (disabled = blocked)",
            "data": {"usb_storage_blacklisted": blocked, "usbguard_active": usbguard}}


def collect_security(errors: list[str]) -> dict:  # noqa: ARG001 - errors kept for signature parity
    return {
        "firewall": firewall(),
        "defender": antivirus(),
        "secure_boot": secure_boot(),
        "bitlocker": disk_encryption(),
        "guest_account": _na("no built-in guest account on Linux"),
        "smb1": _na("SMBv1 not applicable (no Windows file sharing stack)"),
        "remote_desktop": remote_access(),
        "credential_guard": _na("Credential Guard is Windows-only"),
        "screen_lock": screen_lock(),
        "windows_update": os_updates(),
        "account_policy": account_policy(),
        "audit_policy": audit_policy(),
        "usb_storage": usb_storage(),
    }
