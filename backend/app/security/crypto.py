"""AES-256-GCM encryption for sensitive values at rest (e.g. TOTP secrets)."""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

_VERSION = b"\x01"


def encrypt(plaintext: str, associated_data: str) -> str:
    """Encrypt and bind the ciphertext to `associated_data` (e.g. the owning row's id)."""
    nonce = os.urandom(12)
    ct = AESGCM(get_settings().data_key_bytes).encrypt(nonce, plaintext.encode(), associated_data.encode())
    return base64.b64encode(_VERSION + nonce + ct).decode()


def decrypt(token: str, associated_data: str) -> str:
    raw = base64.b64decode(token)
    if raw[:1] != _VERSION:
        raise ValueError("unsupported ciphertext version")
    nonce, ct = raw[1:13], raw[13:]
    return AESGCM(get_settings().data_key_bytes).decrypt(nonce, ct, associated_data.encode()).decode()
