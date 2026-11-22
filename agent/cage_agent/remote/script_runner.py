"""Run an operator-authored script (from the console scripts library) and return its exit code + captured output.

The script body arrives inside a signed, allowlisted `script.run` command envelope (validated upstream), so there is
no arbitrary ad-hoc command path — only saved, audited library scripts reach here. The script is written to a private
temp file, run with the requested interpreter under a hard timeout, and its stdout/stderr are captured and capped. The
script runs in the agent's own context (unprivileged agent / service account); it is never auto-elevated.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile

from cage_agent.policies import Outcome

log = logging.getLogger("cage_agent.scripts")
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_OUT_CAP = 20_000  # characters kept per stream


def _cap(text: str) -> str:
    text = text or ""
    return text if len(text) <= _OUT_CAP else text[:_OUT_CAP] + f"\n…[truncated, {len(text)} chars total]"


def _command(interpreter: str, path: str) -> list[str] | None:
    if interpreter == "powershell":
        if sys.platform != "win32":
            return None
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]
    if interpreter == "cmd":
        if sys.platform != "win32":
            return None
        return ["cmd.exe", "/c", path]
    if interpreter == "bash":
        if sys.platform == "win32":
            return None
        return ["/bin/bash", path]
    return None


def _suffix(interpreter: str) -> str:
    return {"powershell": ".ps1", "cmd": ".bat", "bash": ".sh"}.get(interpreter, ".txt")


def run_script(p: dict) -> Outcome:
    interpreter = str(p.get("interpreter") or "")
    content = str(p.get("content") or "")
    timeout = int(p.get("timeout_seconds") or 300)
    argv = _command(interpreter, "")
    if argv is None:
        return Outcome("failed", f"Interpreter {interpreter!r} is not available on this OS",
                       {}, {"exit_code": None, "stdout": "", "stderr": f"interpreter {interpreter} unsupported here"})
    fd, path = tempfile.mkstemp(suffix=_suffix(interpreter), prefix="cage-script-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        argv = _command(interpreter, path)
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, creationflags=_NO_WINDOW)
        except subprocess.TimeoutExpired as exc:
            return Outcome("failed", f"Script timed out after {timeout}s",
                           {}, {"exit_code": None, "stdout": _cap(exc.stdout or ""),
                                "stderr": _cap((exc.stderr or "") + f"\n[timed out after {timeout}s]")})
        state = {"exit_code": r.returncode, "stdout": _cap(r.stdout), "stderr": _cap(r.stderr),
                 "interpreter": interpreter}
        if r.returncode == 0:
            return Outcome("succeeded", "Script completed (exit 0)", {}, state)
        return Outcome("failed", f"Script exited {r.returncode}", {}, state)
    except Exception as exc:  # noqa: BLE001 — reported, never swallowed
        log.exception("script.run failed")
        return Outcome("failed", f"{exc.__class__.__name__}: {str(exc)[:300]}",
                       {}, {"exit_code": None, "stdout": "", "stderr": str(exc)[:_OUT_CAP]})
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
