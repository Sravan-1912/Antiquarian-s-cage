"""Protect the device private key at rest.

Windows: DPAPI (CryptProtectData) via ctypes, with the file ACL (SYSTEM, Administrators and the agent's service SID)
as the real boundary for machine scope.

Linux: there is no DPAPI, so the key file is (a) wrapped with AES-256-GCM using a key derived from the host's
``/etc/machine-id`` (so a key copied off the box is useless elsewhere) and (b) written ``0600`` owned by the agent
user — the file mode is the boundary, exactly as the ACL is on Windows. For "machine" scope the agent normally runs
as root/a system user; for "user" scope the file lives under the invoking user's home.

Either way the private key never leaves the endpoint; only the public key (CSR) is sent to the server.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ENTROPY = b"AntiquariansCage/device-key/v1"


# ------------------------------------------------------------------------------------------------- Windows (DPAPI)
if sys.platform == "win32":
    import ctypes
    import subprocess
    from ctypes import wintypes

    from cage_agent.sysexe import exe  # absolute System32 paths

    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(data: bytes) -> "DATA_BLOB":
        buf = ctypes.create_string_buffer(data, len(data))
        return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def protect(data: bytes, scope: str = "machine") -> bytes:
        flags = CRYPTPROTECT_UI_FORBIDDEN | (CRYPTPROTECT_LOCAL_MACHINE if scope == "machine" else 0)
        out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(_blob(data)), "cage-device-key",
                                                      ctypes.byref(_blob(_ENTROPY)), None, None, flags, ctypes.byref(out)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    def unprotect(data: bytes) -> bytes:
        out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(_blob(data)), None, ctypes.byref(_blob(_ENTROPY)),
                                                        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    def restrict_acl(path: Path, extra_principal: str | None = None) -> None:
        """Remove inherited permissions; grant full control only to SYSTEM, Administrators (and the service SID)."""
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


# ----------------------------------------------------------------------------------------------- Linux / other POSIX
else:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _MAGIC = b"CAGEk1"  # format tag: magic(6) | nonce(12) | ciphertext

    def _machine_secret() -> bytes:
        """A stable per-host secret. /etc/machine-id is present on systemd systems and is not world-secret, so it is
        combined with a fixed app salt via HKDF; the real boundary remains the 0600 file mode. Falls back to the
        D-Bus machine id, then to a host-derived value so the agent still runs on minimal systems."""
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                mid = Path(p).read_text(encoding="utf-8").strip()
                if mid:
                    return mid.encode()
            except OSError:
                continue
        # Last resort: derive from hostname + a root-only path's identity. Weaker, but never world-readable material.
        import socket
        return (socket.gethostname() + "|" + str(os.stat("/").st_ino)).encode()

    def _wrap_key() -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=_ENTROPY,
                    info=b"cage-device-key-wrap").derive(_machine_secret())

    def protect(data: bytes, scope: str = "machine") -> bytes:  # noqa: ARG001 - scope is for API parity with Windows
        nonce = os.urandom(12)
        ct = AESGCM(_wrap_key()).encrypt(nonce, data, _ENTROPY)
        return _MAGIC + nonce + ct

    def unprotect(data: bytes) -> bytes:
        if not data.startswith(_MAGIC):
            raise ValueError("device key file is not in the expected format")
        nonce, ct = data[6:18], data[18:]
        return AESGCM(_wrap_key()).decrypt(nonce, ct, _ENTROPY)

    def restrict_acl(path: Path, extra_principal: str | None = None) -> None:  # noqa: ARG001 - parity with Windows
        """The file mode is the boundary: owner-only read/write, no group/other access. Failures are raised, never
        ignored — an over-permissive key file is a security failure."""
        try:
            os.chmod(path, 0o600)
        except OSError as e:
            raise PermissionError(f"Could not restrict permissions on {path}: {e}") from e
