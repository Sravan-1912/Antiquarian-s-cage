"""Security configuration *reporting* (no changes). Every check returns an explicit state; anything the agent
cannot determine — including checks that need elevation it does not have — is reported as "unknown", never as
enabled/compliant. Interpretation into PASS/FAIL happens server-side in the Phase 3 compliance engine."""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import sys

from cage_agent.collectors import powershell


def _unknown(detail: str) -> dict:
    return {"state": "unknown", "detail": detail[:512], "data": {}}


def _query(name: str, errors: list[str]):
    try:
        return powershell.run(name), None
    except powershell.QueryError as e:
        msg = str(e)
        if "Access" in msg or "denied" in msg.lower() or "privilege" in msg.lower() or "elevat" in msg.lower():
            return None, "requires elevation (collector runs with least privilege)"
        errors.append(msg)
        return None, msg


def firewall(errors) -> dict:
    data, err = _query("firewall", errors)
    if err or not data:
        return _unknown(err or "no data")
    profiles = data if isinstance(data, list) else [data]
    flags = {str(p.get("Name", "?")).lower(): bool(p.get("Enabled")) for p in profiles}
    on = sum(flags.values())
    state = "enabled" if on == len(flags) else "disabled" if on == 0 else "partial"
    return {"state": state, "detail": None, "data": flags}


def defender(errors) -> dict:
    data, err = _query("defender", errors)
    if err or not data:
        return _unknown(err or "Microsoft Defender status unavailable (third-party AV or service stopped)")
    rtp = data.get("RealTimeProtectionEnabled")
    av = data.get("AntivirusEnabled")
    state = "enabled" if rtp and av else "disabled" if rtp is False or av is False else "unknown"
    return {"state": state, "detail": None, "data": {
        "antivirus_enabled": av, "real_time_protection": rtp, "service_enabled": data.get("AMServiceEnabled"),
        "signature_age_days": data.get("SignatureAge"), "signature_version": str(data.get("AntivirusSignatureVersion"))[:64],
    }}


def secure_boot(errors) -> dict:
    data, err = _query("secure_boot", errors)
    if err:
        if "not supported" in err.lower():
            return {"state": "not_applicable", "detail": "Legacy BIOS boot (Secure Boot not supported)", "data": {}}
        return _unknown(err)
    return {"state": "enabled" if data is True else "disabled", "detail": None, "data": {}}


def bitlocker(errors) -> dict:
    data, err = _query("bitlocker", errors)
    if err or not data:
        return _unknown(err or "BitLocker cmdlets unavailable (e.g. Windows Home edition)")
    prot = str(data.get("ProtectionStatus"))
    return {"state": "enabled" if prot == "On" else "disabled", "detail": None,
            "data": {"mount_point": str(data.get("MountPoint"))[:16], "volume_status": str(data.get("VolumeStatus"))[:64],
                     "encryption_percentage": data.get("EncryptionPercentage")}}


def guest_account(errors) -> dict:
    data, err = _query("guest_account", errors)
    if err or data is None:
        return _unknown(err or "guest account not found")
    return {"state": "enabled" if data.get("Enabled") else "disabled", "detail": None,
            "data": {"name": str(data.get("Name"))[:64]}}


def smb1(errors) -> dict:
    data, err = _query("smb1", errors)
    if err or not data:
        return _unknown(err or "no data")
    return {"state": "enabled" if data.get("EnableSMB1Protocol") else "disabled", "detail": None, "data": {}}


def remote_desktop(errors) -> dict:
    if sys.platform != "win32":
        return _unknown("not Windows")
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server") as k:
            deny = winreg.QueryValueEx(k, "fDenyTSConnections")[0]
        nla = None
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as k:
                nla = bool(winreg.QueryValueEx(k, "UserAuthentication")[0])
        except OSError:
            pass
        return {"state": "disabled" if deny else "enabled", "detail": None, "data": {"nla_required": nla}}
    except OSError as e:
        errors.append(f"remote_desktop: {e.__class__.__name__}")
        return _unknown("registry read failed")


def credential_guard(errors) -> dict:
    data, err = _query("credential_guard", errors)
    if err or data is None:
        return _unknown(err or "Device Guard WMI class unavailable")
    running = data.get("SecurityServicesRunning") or []
    running = running if isinstance(running, list) else [running]
    return {"state": "enabled" if 1 in running else "disabled", "detail": None,
            "data": {"services_running": ",".join(str(x) for x in running)[:64]}}


def screen_lock(errors) -> dict:
    """Machine inactivity limit or a password-protected screen saver policy; per-user settings reported separately."""
    if sys.platform != "win32":
        return _unknown("not Windows")
    from cage_agent.policies import registry as reg
    try:
        machine = reg.read(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs")
        desk = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
        pol_secure, pol_timeout = reg.read(desk, "ScreenSaverIsSecure"), reg.read(desk, "ScreenSaveTimeOut")
        user = r"HKCU\Control Panel\Desktop"
        u_active, u_secure = reg.read(user, "ScreenSaveActive"), reg.read(user, "ScreenSaverIsSecure")
        u_timeout = reg.read(user, "ScreenSaveTimeOut")
    except OSError as e:
        errors.append(f"screen_lock: {e.__class__.__name__}")
        return _unknown("registry read failed")
    data = {"machine_inactivity_seconds": machine.get("value"),
            "policy_screensaver_secure": pol_secure.get("value"), "policy_screensaver_timeout": pol_timeout.get("value"),
            "user_screensaver_active": u_active.get("value"), "user_screensaver_secure": u_secure.get("value"),
            "user_screensaver_timeout": u_timeout.get("value")}
    if isinstance(machine.get("value"), int) and 0 < machine["value"] <= 3600:
        return {"state": "enabled", "detail": "machine inactivity limit", "data": data}
    pt = str(pol_timeout.get("value") or "0")
    if str(pol_secure.get("value")) == "1" and pt.isdigit() and int(pt) > 0:
        return {"state": "enabled", "detail": "screen saver policy with password", "data": data}
    if str(u_active.get("value")) == "1" and str(u_secure.get("value")) == "1":
        return {"state": "enabled", "detail": "per-user screen saver with password (not centrally enforced)",
                "data": data}
    return {"state": "disabled", "detail": "no machine inactivity limit or password-protected screen saver",
            "data": data}


def windows_update(errors) -> dict:
    from datetime import datetime, timezone
    data, err = _query("last_update", errors)
    pending_reboot = None
    if sys.platform == "win32":
        import winreg
        for path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"):
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path).Close()
                pending_reboot = True
                break
            except FileNotFoundError:
                pending_reboot = False
            except OSError:
                pass
    if err or not data or not data.get("InstalledOn"):
        return {**_unknown(err or "no installed update history"), "data": {"pending_reboot": pending_reboot}}
    installed = datetime.fromisoformat(data["InstalledOn"].replace("Z", "+00:00"))
    if installed.tzinfo is None:
        installed = installed.replace(tzinfo=timezone.utc)
    days = (datetime.now(timezone.utc) - installed).days
    return {"state": "enabled", "detail": "last installed update (Win32_QuickFixEngineering)",
            "data": {"days_since_last_update": max(days, 0), "last_update": data["InstalledOn"][:32],
                     "last_hotfix": str(data.get("HotFixID"))[:32], "pending_reboot": pending_reboot}}


def account_policy(errors) -> dict:
    """NetUserModalsGet: locale-independent and readable without elevation."""
    try:
        import win32net
        m0, m3 = win32net.NetUserModalsGet(None, 0), win32net.NetUserModalsGet(None, 3)
    except Exception as e:  # noqa: BLE001
        errors.append(f"account_policy: {e.__class__.__name__}")
        return _unknown("NetUserModalsGet failed")
    thr = m3["lockout_threshold"]
    max_age = m0["max_passwd_age"]
    return {"state": "enabled" if thr > 0 else "disabled", "detail": None, "data": {
        "lockout_threshold": thr, "lockout_duration_minutes": m3["lockout_duration"] // 60,
        "lockout_window_minutes": m3["lockout_observation_window"] // 60,
        "min_password_length": m0["min_passwd_len"],
        "max_password_age_days": max_age // 86400 if 0 < max_age < 2**31 else 0}}


AUDIT_SUBCATEGORIES = {  # locale-independent subcategory GUIDs
    "logon": "{0CCE9215-69AE-11D9-BED3-505054503030}",
    "account_lockout": "{0CCE9217-69AE-11D9-BED3-505054503030}",
    "user_account_management": "{0CCE9235-69AE-11D9-BED3-505054503030}",
    "security_group_management": "{0CCE9237-69AE-11D9-BED3-505054503030}",
}


def audit_policy(errors) -> dict:
    import csv
    import io as _io
    import subprocess
    data = {}
    for key, guid in AUDIT_SUBCATEGORIES.items():
        try:
            r = subprocess.run([exe("auditpol.exe"), "/get", f"/subcategory:{guid}", "/r"], capture_output=True, text=True,
                               timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as e:
            errors.append(f"audit_policy: {e.__class__.__name__}")
            return _unknown("auditpol unavailable")
        if r.returncode != 0:
            return _unknown("requires elevation (collector runs with least privilege)")
        rows = [row for row in csv.reader(_io.StringIO(r.stdout.strip())) if row]
        if len(rows) < 2:
            return _unknown("unexpected auditpol output")
        # "Inclusion Setting" text is localized; the numeric "Setting Value" column is not.
        header = [h.strip().lower() for h in rows[0]]
        if "setting value" not in header:
            return _unknown("auditpol output lacks numeric setting value")
        val = rows[1][header.index("setting value")].strip()
        data[key] = {"0": "no_auditing", "1": "success", "2": "failure", "3": "success_and_failure"}.get(val, "unknown")
    state = "enabled" if all(v not in ("no_auditing", "unknown") for v in data.values()) else "partial"
    return {"state": state, "detail": None, "data": data}


def usb_storage(errors) -> dict:
    data, err = _query("usb_storage", errors)
    if err:
        return _unknown(err)
    rows = data if isinstance(data, list) else ([data] if data else [])
    from cage_agent.policies import registry as reg
    start = reg.read(r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "Start").get("value")
    wp = reg.read(r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies", "WriteProtect").get("value")
    out = {f"dev{i}": str(r.get("FriendlyName") or r.get("InstanceId"))[:128] for i, r in enumerate(rows[:20])}
    out |= {"connected_count": len(rows), "usbstor_start": start, "write_protect": wp}
    return {"state": "disabled" if start == 4 else "partial" if wp == 1 else "enabled",
            "detail": "USB mass storage driver state (enabled = storage allowed)", "data": out}


CHECKS = {
    "firewall": firewall, "defender": defender, "secure_boot": secure_boot, "bitlocker": bitlocker,
    "guest_account": guest_account, "smb1": smb1, "remote_desktop": remote_desktop,
    "credential_guard": credential_guard, "screen_lock": screen_lock, "windows_update": windows_update,
    "account_policy": account_policy, "audit_policy": audit_policy, "usb_storage": usb_storage,
}


def collect_security(errors: list[str]) -> dict:
    return {name: fn(errors) for name, fn in CHECKS.items()}
