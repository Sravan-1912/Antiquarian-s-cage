"""Absolute paths for Windows system tools.

Starting "powershell.exe" by bare name lets Windows search the application directory and the current directory
before System32 — a binary-planting risk, especially for the SYSTEM-level broker. Every subprocess in the agent and
broker therefore uses the real System32 path obtained from GetSystemDirectoryW (not from environment variables,
which a caller could influence)."""
from __future__ import annotations

import ctypes
import os
import sys
from functools import lru_cache


@lru_cache(maxsize=1)
def system32() -> str:
    if sys.platform != "win32":
        return "/usr/bin"
    buf = ctypes.create_unicode_buffer(260)
    n = ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260)
    if not n:
        raise OSError("GetSystemDirectoryW failed")
    return buf.value


TOOLS = {
    "powershell.exe": r"WindowsPowerShell\v1.0\powershell.exe",
    "shutdown.exe": "shutdown.exe", "taskkill.exe": "taskkill.exe", "tasklist.exe": "tasklist.exe",
    "icacls.exe": "icacls.exe", "secedit.exe": "secedit.exe", "auditpol.exe": "auditpol.exe",
}


def exe(name: str) -> str:
    """Absolute path of an allowlisted system tool; raises KeyError for anything else."""
    if name == "explorer.exe":  # lives in %WINDIR%, the parent of System32
        return os.path.join(os.path.dirname(system32()), "explorer.exe")
    return os.path.join(system32(), TOOLS[name])
