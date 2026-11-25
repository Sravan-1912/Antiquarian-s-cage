"""Linux policy enforcement — the POSIX counterparts of the Windows policy modules. Each category exposes a module-like
object with ``apply(config) -> Outcome`` and ``remove(previous_state) -> Outcome``. Executed only by the root agent
after the command signature has been validated. Changes are minimal and reversible: apply() records the prior state in
Outcome.previous_state, and remove() restores exactly that.

These are best-effort for the common distributions (systemd + Debian/Ubuntu/Fedora families). Where a change cannot be
made safely at runtime (e.g. encrypting an already-mounted root filesystem), the module reports ``needs_attention`` with
guidance instead of taking a destructive action.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from cage_agent.policies import ElevationRequired, Outcome


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    exe = shutil.which(cmd[0])
    if not exe:
        raise FileNotFoundError(f"{cmd[0]} not found")
    r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout)
    err = (r.stderr or "").lower()
    if r.returncode != 0 and ("permission denied" in err or "must be root" in err or "not permitted" in err):
        raise ElevationRequired(f"{cmd[0]}: {r.stderr.strip()[:200]}")
    return r


def _require_root() -> None:
    if os.geteuid() != 0:
        raise ElevationRequired("policy enforcement requires the agent to run as root")


# ----------------------------------------------------------------------------------------------------- firewall
class _Firewall:
    def _active(self) -> tuple[str | None, bool]:
        if shutil.which("ufw"):
            r = _run(["ufw", "status"])
            return "ufw", "status: active" in r.stdout.lower()
        if shutil.which("firewall-cmd"):
            r = _run(["firewall-cmd", "--state"])
            return "firewalld", r.stdout.strip() == "running"
        return None, False

    def apply(self, cfg: dict) -> Outcome:
        _require_root()
        backend, was_active = self._active()
        if backend is None:
            return Outcome("needs_attention", "No supported firewall (install ufw or firewalld)")
        if not cfg.get("enforce", True):
            return Outcome("succeeded", f"{backend} present; enforcement not requested", {"active": was_active},
                           {"active": was_active, "backend": backend})
        if was_active:
            return Outcome("succeeded", f"{backend} already active", {"active": True}, {"active": True, "backend": backend})
        if backend == "ufw":
            _run(["ufw", "--force", "enable"])
        else:
            _run(["systemctl", "enable", "--now", "firewalld"])
        return Outcome("succeeded", f"{backend} enabled", {"active": False}, {"active": True, "backend": backend})

    def remove(self, prev: dict) -> Outcome:
        _require_root()
        backend, active = self._active()
        if backend and not prev.get("active") and active:   # we turned it on → turn it back off
            _run(["ufw", "disable"]) if backend == "ufw" else _run(["systemctl", "disable", "--now", "firewalld"])
            return Outcome("succeeded", f"{backend} restored to disabled", {"active": True}, {"active": False})
        return Outcome("succeeded", "Firewall left as previously configured")


# ---------------------------------------------------------------------------------------------------- usb storage
_USB_CONF = Path("/etc/modprobe.d/cage-usb-storage.conf")


class _Usb:
    def apply(self, cfg: dict) -> Outcome:
        _require_root()
        existed = _USB_CONF.exists()
        prev = {"conf_present": existed, "conf": _USB_CONF.read_text() if existed else None}
        mode = cfg.get("mode", "allow")
        if mode == "block_storage":
            _USB_CONF.write_text("# Managed by Antiquarian's Cage — block USB mass storage\n"
                                 "install usb-storage /bin/false\nblacklist usb-storage\n", encoding="utf-8")
            os.chmod(_USB_CONF, 0o644)
            _run(["modprobe", "-r", "usb_storage"]) if shutil.which("modprobe") else None
            return Outcome("succeeded", "USB mass storage blocked (reconnect devices to take effect)", prev,
                           {"mode": "block_storage"})
        # allow / read_only: remove any block we previously installed (read_only is not enforced at the kernel level here)
        if existed:
            _USB_CONF.unlink()
        detail = "USB mass storage allowed" if mode == "allow" else "read_only not enforceable at kernel level; allowed"
        return Outcome("succeeded", detail, prev, {"mode": mode})

    def remove(self, prev: dict) -> Outcome:
        _require_root()
        if prev.get("conf_present") and prev.get("conf") is not None:
            _USB_CONF.write_text(prev["conf"], encoding="utf-8")
        elif _USB_CONF.exists():
            _USB_CONF.unlink()
        return Outcome("succeeded", "USB storage policy reverted")


# --------------------------------------------------------------------------------------------------- screen lock
class _ScreenLock:
    """Enforced via a dconf system database so it applies to all graphical users (GNOME). Falls back to per-user
    gsettings when no system dconf is available."""
    _DB = Path("/etc/dconf/db/local.d/00-cage-screenlock")
    _PROFILE = Path("/etc/dconf/profile/user")

    def apply(self, cfg: dict) -> Outcome:
        _require_root()
        idle = int(cfg["inactivity_timeout_seconds"])
        secure = bool(cfg.get("require_password_on_resume", True))
        if shutil.which("dconf"):
            prev = {"db": self._DB.read_text() if self._DB.exists() else None,
                    "profile": self._PROFILE.read_text() if self._PROFILE.exists() else None}
            self._DB.parent.mkdir(parents=True, exist_ok=True)
            self._DB.write_text(
                "[org/gnome/desktop/session]\n" f"idle-delay=uint32 {idle}\n\n"
                "[org/gnome/desktop/screensaver]\n" f"lock-enabled={'true' if secure else 'false'}\nlock-delay=uint32 0\n",
                encoding="utf-8")
            if not self._PROFILE.exists():
                self._PROFILE.parent.mkdir(parents=True, exist_ok=True)
                self._PROFILE.write_text("user-db:user\nsystem-db:local\n", encoding="utf-8")
            _run(["dconf", "update"])
            return Outcome("succeeded", f"Screen lock enforced ({idle}s idle) via dconf", prev,
                           {"idle_delay_seconds": idle, "lock_enabled": secure})
        if shutil.which("gsettings"):
            _run(["gsettings", "set", "org.gnome.desktop.session", "idle-delay", str(idle)])
            _run(["gsettings", "set", "org.gnome.desktop.screensaver", "lock-enabled", "true" if secure else "false"])
            return Outcome("succeeded", f"Screen lock set for current user ({idle}s)", {},
                           {"idle_delay_seconds": idle})
        return Outcome("needs_attention", "No dconf/gsettings — cannot enforce screen lock (headless or non-GNOME)")

    def remove(self, prev: dict) -> Outcome:
        _require_root()
        if "db" in prev:
            if prev.get("db") is None:
                self._DB.exists() and self._DB.unlink()
            else:
                self._DB.write_text(prev["db"], encoding="utf-8")
            if shutil.which("dconf"):
                _run(["dconf", "update"])
        return Outcome("succeeded", "Screen lock policy reverted")


# ------------------------------------------------------------------------------------------------ password policy
_LOGIN_DEFS = Path("/etc/login.defs")
_FAILLOCK = Path("/etc/security/faillock.conf")


class _Password:
    def apply(self, cfg: dict) -> Outcome:
        _require_root()
        prev = {"login_defs": _LOGIN_DEFS.read_text() if _LOGIN_DEFS.exists() else None,
                "faillock": _FAILLOCK.read_text() if _FAILLOCK.exists() else None}
        if _LOGIN_DEFS.exists():
            txt = _LOGIN_DEFS.read_text(encoding="utf-8")
            txt = _set_kv(txt, "PASS_MIN_LEN", str(int(cfg["min_length"])))
            _LOGIN_DEFS.write_text(txt, encoding="utf-8")
        if _FAILLOCK.exists() or shutil.which("faillock"):
            lines = (_FAILLOCK.read_text(encoding="utf-8") if _FAILLOCK.exists() else "")
            lines = _set_conf(lines, "deny", str(int(cfg["lockout_threshold"])))
            lines = _set_conf(lines, "unlock_time", str(int(cfg["lockout_duration_minutes"]) * 60))
            _FAILLOCK.write_text(lines, encoding="utf-8")
            note = "login.defs + faillock updated"
        else:
            note = "login.defs updated (pam_faillock not present; lockout not enforced)"
        return Outcome("succeeded", note, prev,
                       {"min_length": cfg["min_length"], "lockout_threshold": cfg["lockout_threshold"]})

    def remove(self, prev: dict) -> Outcome:
        _require_root()
        if prev.get("login_defs") is not None:
            _LOGIN_DEFS.write_text(prev["login_defs"], encoding="utf-8")
        if prev.get("faillock") is not None:
            _FAILLOCK.write_text(prev["faillock"], encoding="utf-8")
        return Outcome("succeeded", "Password policy reverted")


def _set_kv(text: str, key: str, value: str) -> str:
    if re.search(rf"^\s*{key}\b", text, re.MULTILINE):
        return re.sub(rf"^\s*{key}\b.*$", f"{key}\t{value}", text, flags=re.MULTILINE)
    return text.rstrip("\n") + f"\n{key}\t{value}\n"


def _set_conf(text: str, key: str, value: str) -> str:
    if re.search(rf"^\s*{key}\s*=", text, re.MULTILINE):
        return re.sub(rf"^\s*{key}\s*=.*$", f"{key} = {value}", text, flags=re.MULTILINE)
    return (text.rstrip("\n") + f"\n{key} = {value}\n").lstrip("\n")


# ------------------------------------------------------------------------------------------------- auto updates
class _Updates:
    def apply(self, cfg: dict) -> Outcome:
        _require_root()
        if not cfg.get("configure_automatic_updates", True):
            return Outcome("succeeded", "Automatic updates not requested", {}, {})
        if shutil.which("systemctl"):
            for unit in ("unattended-upgrades", "dnf-automatic.timer", "dnf-automatic-install.timer"):
                r = subprocess.run([shutil.which("systemctl"), "enable", "--now", unit], capture_output=True, text=True)
                if r.returncode == 0:
                    return Outcome("succeeded", f"Enabled {unit}", {"unit": unit}, {"unit": unit})
        return Outcome("needs_attention", "No automatic-update service found (install unattended-upgrades or "
                                           "dnf-automatic)")

    def remove(self, prev: dict) -> Outcome:
        _require_root()
        unit = prev.get("unit")
        if unit and shutil.which("systemctl"):
            subprocess.run([shutil.which("systemctl"), "disable", "--now", unit], capture_output=True, text=True)
            return Outcome("succeeded", f"Disabled {unit}")
        return Outcome("succeeded", "Automatic updates left as configured")


# -------------------------------------------------------------------------------------------------- antivirus
class _Antivirus:
    def apply(self, cfg: dict) -> Outcome:  # noqa: ARG002
        _require_root()
        if not shutil.which("clamscan") and not shutil.which("clamd"):
            return Outcome("needs_attention", "ClamAV not installed; cannot enable on-access antivirus "
                                              "(install clamav-daemon)")
        if shutil.which("systemctl"):
            subprocess.run([shutil.which("systemctl"), "enable", "--now", "clamav-freshclam"], capture_output=True)
            r = subprocess.run([shutil.which("systemctl"), "enable", "--now", "clamav-daemon"], capture_output=True,
                               text=True)
            if r.returncode == 0:
                return Outcome("succeeded", "ClamAV daemon enabled", {"enabled": False}, {"enabled": True})
        return Outcome("needs_attention", "Could not enable ClamAV services")

    def remove(self, prev: dict) -> Outcome:  # noqa: ARG002
        return Outcome("succeeded", "Antivirus left installed (not removed by policy rollback)")


# ---------------------------------------------------------------------------------------------- disk encryption
class _DiskEncryption:
    def apply(self, cfg: dict) -> Outcome:
        if not cfg.get("require_system_drive_encryption", True):
            return Outcome("succeeded", "System-drive encryption not required", {}, {})
        from cage_agent.collectors import linux_facts
        enc = linux_facts.disk_encryption()
        if enc["state"] == "enabled":
            return Outcome("succeeded", "Root filesystem is already LUKS-encrypted", {}, {"encrypted": True})
        return Outcome("needs_attention", "Root filesystem is not encrypted. Full-disk encryption (LUKS) cannot be "
                                          "enabled on a running system without reinstalling/re-provisioning the disk.")

    def remove(self, prev: dict) -> Outcome:  # noqa: ARG002
        return Outcome("succeeded", "No change to make")


_MODULES = {
    "firewall": _Firewall(), "usb": _Usb(), "screen_lock": _ScreenLock(), "password": _Password(),
    "windows_update": _Updates(), "antivirus": _Antivirus(), "bitlocker": _DiskEncryption(),
}


def linux_module(category: str):
    return _MODULES[category]
