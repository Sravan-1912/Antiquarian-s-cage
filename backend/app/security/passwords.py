"""Password hashing and policy.

PBKDF2-HMAC-SHA256 from the standard library: no native dependency (so it freezes cleanly into the
desktop exe), constant-time verification, and a stored format that carries its own parameters so the
work factor can be raised later without invalidating old hashes.

    pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string

from app.core.config import get_settings

_ITERATIONS = 600_000
_SALT_BYTES = 16
_DKLEN = 32


class PasswordPolicyError(ValueError):
    """Raised when a chosen password does not meet the policy."""


def hash_password(raw: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), salt, _ITERATIONS, _DKLEN)
    return f"pbkdf2_sha256${_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(raw: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        scheme, iters, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), salt, int(iters), len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def validate_strength(raw: str) -> None:
    """Enforce the password policy; raise PasswordPolicyError with a user-facing message on failure."""
    min_len = get_settings().password_min_length
    if len(raw) < min_len:
        raise PasswordPolicyError(f"Password must be at least {min_len} characters.")
    if len(raw) > 200:
        raise PasswordPolicyError("Password must be at most 200 characters.")
    classes = sum((any(c.islower() for c in raw), any(c.isupper() for c in raw),
                   any(c.isdigit() for c in raw), any(not c.isalnum() for c in raw)))
    if classes < 3:
        raise PasswordPolicyError("Use at least three of: lowercase, uppercase, digits, symbols.")


def generate_temporary() -> str:
    """A strong temporary password a Super Admin hands to a new admin (who must then change it)."""
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(16))
        try:
            validate_strength(pw)
            return pw
        except PasswordPolicyError:
            continue
