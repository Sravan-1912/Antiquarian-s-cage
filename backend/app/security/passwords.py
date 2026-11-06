"""Argon2id password hashing and password-strength policy."""
from __future__ import annotations

import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings

# OWASP-recommended Argon2id parameters (m=64 MiB, t=3, p=4).
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32, salt_len=16)

# A pre-computed hash used to equalise timing when the account does not exist.
_DUMMY_HASH = _hasher.hash("antiquarian-dummy-password-for-timing")

_COMMON = {
    "password", "password1", "123456", "12345678", "123456789", "qwerty", "letmein", "welcome",
    "admin", "administrator", "iloveyou", "monkey", "dragon", "passw0rd", "changeme", "football",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, *, email: str | None = None, full_name: str | None = None) -> list[str]:
    """Return a list of human-readable reasons the password is unacceptable (empty list = OK)."""
    s = get_settings()
    problems: list[str] = []
    if len(password) < s.password_min_length:
        problems.append(f"Must be at least {s.password_min_length} characters.")
    if len(password) > 256:
        problems.append("Must be at most 256 characters.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        problems.append("Must contain at least three of: lowercase, uppercase, digit, symbol.")
    lowered = password.lower()
    if lowered in _COMMON or re.sub(r"[\d!@#$%^&*]+$", "", lowered) in _COMMON:
        problems.append("Is a commonly used password.")
    if re.search(r"(.)\1{3,}", password):
        problems.append("Must not repeat the same character four or more times.")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            problems.append("Must not contain your email address.")
    if full_name:
        for part in full_name.lower().split():
            if len(part) >= 4 and part in lowered:
                problems.append("Must not contain your name.")
                break
    return problems
