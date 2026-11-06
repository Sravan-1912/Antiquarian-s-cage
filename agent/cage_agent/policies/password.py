"""Local password & lockout policy via NetUserModalsGet/Set (locale-independent) and secedit for complexity.
Applies to local accounts only; domain-joined machines are governed by domain policy (reported, not fought)."""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import os
import re
import subprocess
import tempfile
from pathlib import Path

from cage_agent.policies import ElevationRequired, Outcome


def _modals():
    import win32net
    return win32net


def read_state() -> dict:
    net = _modals()
    m0, m3 = net.NetUserModalsGet(None, 0), net.NetUserModalsGet(None, 3)
    return {"min_length": m0["min_passwd_len"], "lockout_threshold": m3["lockout_threshold"],
            "lockout_duration_minutes": m3["lockout_duration"] // 60,
            "lockout_window_minutes": m3["lockout_observation_window"] // 60,
            "complexity_enabled": _read_complexity()}


def _secedit(args: list[str]) -> subprocess.CompletedProcess:
    r = subprocess.run([exe("secedit.exe"), *args], capture_output=True, text=True, timeout=120,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        out = (r.stdout + r.stderr).lower()
        if "access" in out or "denied" in out or "privilege" in out:
            raise ElevationRequired("secedit requires administrator rights")
        raise RuntimeError(f"secedit failed ({r.returncode})")
    return r


def _read_complexity() -> bool | None:
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "export.inf"
        try:
            _secedit(["/export", "/cfg", str(cfg), "/areas", "SECURITYPOLICY", "/quiet"])
        except (ElevationRequired, RuntimeError):
            return None
        text = cfg.read_text(encoding="utf-16", errors="replace")
        m = re.search(r"^PasswordComplexity\s*=\s*(\d)", text, re.M)
        return bool(int(m.group(1))) if m else None


def _set_complexity(enabled: bool) -> None:
    with tempfile.TemporaryDirectory() as d:
        inf, db = Path(d) / "cage.inf", Path(d) / "cage.sdb"
        inf.write_text("[Unicode]\nUnicode=yes\n[System Access]\nPasswordComplexity = %d\n[Version]\n"
                       'signature="$CHICAGO$"\nRevision=1\n' % int(enabled), encoding="utf-16")
        _secedit(["/configure", "/db", str(db), "/cfg", str(inf), "/areas", "SECURITYPOLICY", "/quiet"])


def _write(state: dict) -> None:
    net = _modals()
    m0, m3 = net.NetUserModalsGet(None, 0), net.NetUserModalsGet(None, 3)
    m0["min_passwd_len"] = state["min_length"]
    m3.update(lockout_threshold=state["lockout_threshold"], lockout_duration=state["lockout_duration_minutes"] * 60,
              lockout_observation_window=state["lockout_window_minutes"] * 60)
    try:
        net.NetUserModalsSet(None, 0, m0)
        net.NetUserModalsSet(None, 3, m3)
    except Exception as exc:  # pywintypes.error
        if getattr(exc, "winerror", None) == 5:
            raise ElevationRequired("changing account policy requires administrator rights") from exc
        raise


def _domain_joined() -> bool:
    return os.environ.get("USERDOMAIN", "").upper() != os.environ.get("COMPUTERNAME", "").upper()


def apply(cfg: dict) -> Outcome:
    before = read_state()
    keys = ("min_length", "lockout_threshold", "lockout_duration_minutes", "lockout_window_minutes")
    target = {k: cfg[k] for k in keys}
    note = " (domain-joined: domain policy may override)" if _domain_joined() else ""
    if all(before[k] == target[k] for k in keys) and before["complexity_enabled"] == cfg["complexity_enabled"]:
        return Outcome("succeeded", "Already compliant" + note, {}, before)
    _write(target)
    if before["complexity_enabled"] != cfg["complexity_enabled"]:
        _set_complexity(cfg["complexity_enabled"])
    after = read_state()
    ok = all(after[k] == target[k] for k in keys)
    return Outcome("succeeded" if ok else "failed", "Local password/lockout policy applied" + note,
                   {"password_policy": before}, after)


def remove(previous: dict) -> Outcome:
    prev = previous.get("password_policy")
    if not prev:
        return Outcome("succeeded", "Nothing to roll back")
    _write(prev)
    if prev.get("complexity_enabled") is not None:
        _set_complexity(prev["complexity_enabled"])
    return Outcome("succeeded", "Restored previous password/lockout policy", {}, read_state())
