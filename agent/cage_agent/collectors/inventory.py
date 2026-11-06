"""Hardware, OS, disk and network collection. Read-only, works without elevation."""
from __future__ import annotations

import platform
import socket
import sys
from datetime import datetime, timezone

import psutil

from cage_agent.collectors import powershell
from cage_agent.collectors.security import collect_security


def _clip(v, n: int = 128):
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] or None


def collect_os(errors: list[str]) -> dict:
    info = {"name": None, "version": platform.version()[:64], "build": None, "edition": None,
            "architecture": platform.machine()[:64], "install_date": None, "last_boot": None}
    try:
        o = powershell.run("operating_system") or {}
        info.update(name=_clip(o.get("Caption")), version=_clip(o.get("Version"), 64),
                    build=_clip(o.get("BuildNumber"), 64), architecture=_clip(o.get("OSArchitecture"), 64),
                    install_date=_clip(o.get("InstallDate"), 64), last_boot=_clip(o.get("LastBootUpTime"), 64))
    except powershell.QueryError as e:
        errors.append(str(e))
        info["name"] = f"{platform.system()} {platform.release()}"
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
                info["edition"] = _clip(winreg.QueryValueEx(k, "EditionID")[0])
                ubr = winreg.QueryValueEx(k, "UBR")[0]
                if info["build"]:
                    info["build"] = f"{info['build']}.{ubr}"
        except OSError as e:
            errors.append(f"registry: {e.__class__.__name__}")
    return info


def collect_hardware(errors: list[str]) -> tuple[dict, dict, int | None]:
    hw = {"manufacturer": None, "model": None, "serial_number": None, "bios_version": None}
    cpu = {"name": _clip(platform.processor()), "manufacturer": None,
           "physical_cores": psutil.cpu_count(logical=False), "logical_processors": psutil.cpu_count(),
           "max_clock_mhz": None}
    memory = psutil.virtual_memory().total
    try:
        cs = powershell.run("computer_system") or {}
        hw.update(manufacturer=_clip(cs.get("Manufacturer")), model=_clip(cs.get("Model")))
    except powershell.QueryError as e:
        errors.append(str(e))
    try:
        b = powershell.run("bios") or {}
        hw.update(serial_number=_clip(b.get("SerialNumber")), bios_version=_clip(b.get("SMBIOSBIOSVersion")))
    except powershell.QueryError as e:
        errors.append(str(e))
    try:
        p = powershell.run("processor") or {}
        if isinstance(p, list):
            p = p[0]
        cpu.update(name=_clip(p.get("Name")), manufacturer=_clip(p.get("Manufacturer")),
                   physical_cores=p.get("NumberOfCores") or cpu["physical_cores"],
                   logical_processors=p.get("NumberOfLogicalProcessors") or cpu["logical_processors"],
                   max_clock_mhz=p.get("MaxClockSpeed"))
    except powershell.QueryError as e:
        errors.append(str(e))
    return hw, cpu, memory


def collect_disks(errors: list[str]) -> list[dict]:
    disks = []
    for part in psutil.disk_partitions(all=False)[:64]:
        if "cdrom" in part.opts or not part.fstype:
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
        except OSError as e:
            errors.append(f"disk {part.mountpoint}: {e.__class__.__name__}")
            continue
        disks.append({"device": part.device[:64], "mountpoint": part.mountpoint[:64], "filesystem": part.fstype[:64],
                      "total_bytes": u.total, "used_bytes": u.used, "free_bytes": u.free})
    return disks


def collect_network() -> list[dict]:
    stats = psutil.net_if_stats()
    out = []
    for name, addrs in list(psutil.net_if_addrs().items())[:64]:
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
        if mac and (len(mac) != 17 or mac in ("00-00-00-00-00-00", "00:00:00:00:00:00")):
            mac = None
        ipv4 = [a.address for a in addrs if a.family == socket.AF_INET][:16]
        ipv6 = [a.address.split("%")[0] for a in addrs if a.family == socket.AF_INET6][:16]
        if name.lower().startswith("loopback") or (not ipv4 and not mac):
            continue
        st = stats.get(name)
        out.append({"name": name[:128], "mac_address": mac, "ipv4": ipv4, "ipv6": ipv6,
                    "is_up": st.isup if st else None, "speed_mbps": st.speed if st and st.speed else None})
    return out


def collect_all(agent_version: str) -> dict:
    errors: list[str] = []
    os_info = collect_os(errors)
    hw, cpu, memory = collect_hardware(errors)
    return {
        "agent_version": agent_version,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname()[:63],
        "os": os_info,
        "hardware": hw,
        "cpu": cpu,
        "memory_bytes": memory,
        "disks": collect_disks(errors),
        "network_interfaces": collect_network(),
        "security": collect_security(errors),
        "collection_errors": [e[:256] for e in errors][:32],
    }
