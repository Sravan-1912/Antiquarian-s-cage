"""RFC 6238 TOTP with replay protection (a code's time-step can be used only once)."""
from __future__ import annotations

import time

import pyotp

STEP = 30


def new_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def verify(secret: str, code: str, last_used_step: int | None) -> int | None:
    """Return the matched time-step if `code` is valid and unused, otherwise None."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // STEP
    for step in (now_step - 1, now_step, now_step + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if totp.verify(code, for_time=step * STEP):
            return step
    return None
