"""Policy modules, executed ONLY inside the privileged broker after independent signature validation.

Each module exposes:
    apply(config) -> Outcome      captures previous state, applies, reports current state
    remove(previous_state) -> Outcome   restores exactly what apply() recorded (rollback)
Outcome.status: succeeded | failed | needs_attention. Nothing is changed when the device already complies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CATEGORIES = ("firewall", "bitlocker", "usb", "antivirus", "screen_lock", "windows_update", "password")


@dataclass
class Outcome:
    status: str
    detail: str
    previous_state: dict = field(default_factory=dict)
    current_state: dict = field(default_factory=dict)


class ElevationRequired(Exception):
    pass


_DEVICE_ID = re.compile(r"^(USB|USBSTOR)\\[A-Za-z0-9_&\\.\-]{3,200}$")


def _int(cfg: dict, k: str, lo: int, hi: int) -> int:
    v = cfg.get(k)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ValueError(f"{k} must be an integer in [{lo}, {hi}]")
    return v


def _bool(cfg: dict, k: str) -> bool:
    if not isinstance(cfg.get(k), bool):
        raise ValueError(f"{k} must be a boolean")
    return cfg[k]


def validate_policy_config(category: str, cfg) -> dict:
    """Independent local re-validation (defence in depth; mirrors backend/app/schemas/policies.py)."""
    if not isinstance(cfg, dict):
        raise ValueError("configuration must be an object")
    allowed = {
        "firewall": {"profiles", "enforce"},
        "bitlocker": {"require_system_drive_encryption", "allowed_methods"},
        "usb": {"mode", "allowlist", "monitor_connections"},
        "antivirus": {"require_real_time_protection", "max_signature_age_days", "enforce"},
        "screen_lock": {"inactivity_timeout_seconds", "require_password_on_resume"},
        "windows_update": {"max_days_since_last_update", "configure_automatic_updates", "scheduled_install_day",
                           "scheduled_install_hour"},
        "password": {"min_length", "complexity_enabled", "lockout_threshold", "lockout_duration_minutes",
                     "lockout_window_minutes"},
    }[category]
    if set(cfg) - allowed:
        raise ValueError(f"unexpected keys: {sorted(set(cfg) - allowed)}")
    if category == "firewall":
        profs = cfg.get("profiles")
        if not isinstance(profs, list) or not profs or not set(profs) <= {"domain", "private", "public"}:
            raise ValueError("invalid firewall profiles")
        _bool(cfg, "enforce")
    elif category == "usb":
        if cfg.get("mode") not in ("allow", "read_only", "block_storage"):
            raise ValueError("invalid usb mode")
        al = cfg.get("allowlist", [])
        if not isinstance(al, list) or len(al) > 100 or not all(isinstance(x, str) and _DEVICE_ID.match(x) for x in al):
            raise ValueError("invalid usb allowlist")
    elif category == "antivirus":
        _int(cfg, "max_signature_age_days", 0, 30)
        _bool(cfg, "enforce")
        _bool(cfg, "require_real_time_protection")
    elif category == "screen_lock":
        _int(cfg, "inactivity_timeout_seconds", 60, 3600)
        _bool(cfg, "require_password_on_resume")
    elif category == "windows_update":
        _int(cfg, "max_days_since_last_update", 7, 120)
        _int(cfg, "scheduled_install_day", 0, 7)
        _int(cfg, "scheduled_install_hour", 0, 23)
        _bool(cfg, "configure_automatic_updates")
    elif category == "password":
        _int(cfg, "min_length", 8, 14)
        _int(cfg, "lockout_threshold", 3, 50)
        d = _int(cfg, "lockout_duration_minutes", 5, 1440)
        if _int(cfg, "lockout_window_minutes", 5, 1440) > d:
            raise ValueError("lockout window exceeds duration")
        _bool(cfg, "complexity_enabled")
    elif category == "bitlocker":
        _bool(cfg, "require_system_drive_encryption")
    return cfg


def module(category: str):
    from cage_agent.policies import (antivirus, bitlocker, firewall, password, screen_lock, usb,
                                     windows_update)
    return {"firewall": firewall, "bitlocker": bitlocker, "usb": usb, "antivirus": antivirus,
            "screen_lock": screen_lock, "windows_update": windows_update, "password": password}[category]
