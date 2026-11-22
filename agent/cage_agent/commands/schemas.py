"""Local parameter validation for non-policy commands (defence in depth; mirrors backend/app/schemas/remote.py)."""
from __future__ import annotations

import re
import uuid

USERNAME = re.compile(r"^[A-Za-z0-9._\- ]{1,20}$")

# Where each command runs. "agent" = unprivileged agent / user session; "broker" = privileged broker.
ROUTE = {
    "policy.apply": "broker", "policy.remove": "broker",
    "device.inspect": "agent", "device.lock": "agent", "device.restart": "broker", "device.restart_cancel": "broker",
    "device.shutdown": "broker", "device.logoff": "broker",
    "account.disable": "broker", "account.enable": "broker", "account.remove_admin": "broker",
    "device.isolate": "broker", "device.release": "broker",
    "assist.start": "agent", "assist.end": "agent",
    "rdp.start": "agent", "rdp.end": "agent",
    "shell.start": "agent", "shell.end": "agent",
    "script.run": "agent",  # scripts library: run a saved script in the agent's context, report its output
}
ALLOWED_COMMANDS = set(ROUTE)
COMMON = {"reason", "requested_by"}


def _str(p: dict, k: str, max_len: int) -> str:
    v = p.get(k)
    if not isinstance(v, str) or len(v) > max_len or any(ord(c) < 32 for c in v):
        raise ValueError(f"{k} invalid")
    return v


def _keys(p: dict, allowed: set[str]) -> None:
    extra = set(p) - allowed - COMMON
    if extra:
        raise ValueError(f"unexpected parameters: {sorted(extra)}")


def validate_command_params(command: str, p) -> dict:
    if not isinstance(p, dict):
        raise ValueError("parameters must be an object")
    for k in COMMON & set(p):
        _str(p, k, 500)
    if command in ("device.inspect", "device.lock", "device.restart_cancel", "device.logoff", "device.release"):
        _keys(p, set())
    elif command == "device.isolate":
        _keys(p, {"server_host"})
        _str(p, "server_host", 255)  # backend host to keep reachable so the endpoint can be released
    elif command in ("device.restart", "device.shutdown"):
        _keys(p, {"delay_seconds", "message"})
        d = p.get("delay_seconds")
        if not isinstance(d, int) or isinstance(d, bool) or not 60 <= d <= 3600:
            raise ValueError("delay_seconds must be 60..3600")
        if '"' in _str(p, "message", 200):
            raise ValueError("message must not contain quotes")
    elif command.startswith("account."):
        _keys(p, {"username"})
        if not USERNAME.match(_str(p, "username", 20)):
            raise ValueError("invalid username")
    elif command == "assist.start":
        _keys(p, {"session_id", "max_minutes", "require_consent", "consent_timeout_seconds"})
        uuid.UUID(_str(p, "session_id", 36))
        m = p.get("max_minutes")
        if not isinstance(m, int) or not 5 <= m <= 120:
            raise ValueError("max_minutes must be 5..120")
        if not isinstance(p.get("require_consent"), bool):
            raise ValueError("require_consent must be boolean")
        t = p.get("consent_timeout_seconds")
        if not isinstance(t, int) or not 30 <= t <= 300:
            raise ValueError("consent_timeout_seconds must be 30..300")
    elif command == "assist.end":
        _keys(p, {"session_id"})
        uuid.UUID(_str(p, "session_id", 36))
    elif command == "rdp.start":
        _keys(p, {"session_id", "max_minutes", "tunnel_token"})
        uuid.UUID(_str(p, "session_id", 36))
        m = p.get("max_minutes")
        if not isinstance(m, int) or not 5 <= m <= 120:
            raise ValueError("max_minutes must be 5..120")
        _str(p, "tunnel_token", 256)
    elif command == "rdp.end":
        _keys(p, {"session_id"})
        uuid.UUID(_str(p, "session_id", 36))
    elif command == "shell.start":
        _keys(p, {"session_id", "max_minutes", "tunnel_token", "elevated"})
        uuid.UUID(_str(p, "session_id", 36))
        m = p.get("max_minutes")
        if not isinstance(m, int) or not 5 <= m <= 120:
            raise ValueError("max_minutes must be 5..120")
        _str(p, "tunnel_token", 256)
        if not isinstance(p.get("elevated", False), bool):
            raise ValueError("elevated must be a boolean")
    elif command == "shell.end":
        _keys(p, {"session_id"})
        uuid.UUID(_str(p, "session_id", 36))
    elif command == "script.run":
        _keys(p, {"run_id", "interpreter", "content", "timeout_seconds"})
        uuid.UUID(_str(p, "run_id", 36))
        if p.get("interpreter") not in ("powershell", "cmd", "bash"):
            raise ValueError("interpreter must be powershell, cmd or bash")
        c = p.get("content")
        if not isinstance(c, str) or not 1 <= len(c) <= 65_536:
            raise ValueError("content must be 1..65536 chars")
        t = p.get("timeout_seconds")
        if not isinstance(t, int) or isinstance(t, bool) or not 5 <= t <= 3600:
            raise ValueError("timeout_seconds must be 5..3600")
    else:
        raise ValueError("unknown command")
    return p
