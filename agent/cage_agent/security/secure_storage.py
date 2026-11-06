"""Protect the device private key at rest with Windows DPAPI (CryptProtectData) via ctypes.

Scope:
* "machine" (default when installed as a service): decryptable by any process on this machine that can read the
  file, so the file ACL (SYSTEM, Administrators and the agent's service SID only) is the real boundary.
* "user": bound to the Windows account running the agent (development / interactive runs).
The key never leaves the endpoint; only the public key (CSR) is sent to the server.
"""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4
_ENTROPY = b"AntiquariansCage/device-key/v1"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("DPAPI key protection is only available on Windows")


def protect(data: bytes, scope: str = "machine") -> bytes:
    _require_windows()
    flags = CRYPTPROTECT_UI_FORBIDDEN | (CRYPTPROTECT_LOCAL_MACHINE if scope == "machine" else 0)
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(_blob(data)), "cage-device-key", ctypes.byref(_blob(_ENTROPY)),
                                                  None, None, flags, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def unprotect(data: bytes) -> bytes:
    _require_windows()
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(_blob(data)), None, ctypes.byref(_blob(_ENTROPY)),
                                                    None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def restrict_acl(path: Path, extra_principal: str | None = None) -> None:
    """Remove inherited permissions; grant full control only to SYSTEM, Administrators (and the service SID).
    Failures are raised, never ignored: an unprotected key file is a security failure."""
    if sys.platform != "win32":
        return
    grants = ["*S-1-5-18:F", "*S-1-5-32-544:F"]  # SYSTEM, BUILTIN\Administrators (SIDs: locale independent)
    if extra_principal:
        grants.append(f"{extra_principal}:F")
    else:
        grants.append(f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}:F".lstrip("\\"))
    cmd = [exe("icacls.exe"), str(path), "/inheritance:r"]
    for g in grants:
        cmd += ["/grant:r", g]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        raise PermissionError(f"Could not restrict ACL on {path}: {res.stdout.strip()} {res.stderr.strip()}")
