"""Fixed PowerShell scripts for policy enforcement. Arguments are passed through environment variables, never by
string interpolation, and are already validated (enums/integers) before reaching here."""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import json
import os
import subprocess

from cage_agent.policies import ElevationRequired


class PSError(Exception):
    pass


def run(script: str, env: dict[str, str] | None = None, timeout: int = 120):
    cmd = [exe("powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
           f"$ErrorActionPreference='Stop'; $r = & {{ {script} }}; if ($null -ne $r) {{ $r | ConvertTo-Json -Depth 4 -Compress }}"]
    full_env = {**os.environ, **{f"CAGE_ARG_{k}": str(v) for k, v in (env or {}).items()}}
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=full_env,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise PSError("timed out") from exc
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip()
        first = msg.splitlines()[0][:300] if msg else "failed"
        low = msg.lower()
        if "access is denied" in low or "access denied" in low or "requires elevation" in low or "0x80070005" in low \
                or "administrator" in low or "permission" in low:
            raise ElevationRequired(first)
        raise PSError(first)
    out = res.stdout.strip()
    return json.loads(out) if out else None
