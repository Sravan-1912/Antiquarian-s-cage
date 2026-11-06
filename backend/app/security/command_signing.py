"""Ed25519 signing of command envelopes.

The command-signing key is deliberately separate from the device CA and from the audit HMAC key. Agents pin its
public key (by key id) and refuse any command that is unsigned, signed by another key, expired, addressed to another
device, replayed, or not on their own allowlist. In production keep this key offline/HSM-backed and sign through a
narrow service; the API host holding it is the main residual risk (documented in SECURITY.md)."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.config import get_settings


class SigningError(Exception):
    pass


@dataclass
class SigningKey:
    key: Ed25519PrivateKey
    key_id: str

    @property
    def public_key_b64(self) -> str:
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()


_lock = threading.Lock()
_key: SigningKey | None = None


def _key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "cmd-" + hashlib.sha256(raw).hexdigest()[:16]


def get_signing_key() -> SigningKey:
    global _key
    with _lock:
        if _key:
            return _key
        s = get_settings()
        path = Path(s.device_ca_dir) / "command-signing.key"
        passphrase = s.device_ca_key_passphrase.encode()
        if not path.exists():
            if s.environment == "production":
                raise SigningError("Command signing key not found; create it offline (see SECURITY.md)")
            path.parent.mkdir(parents=True, exist_ok=True)
            k = Ed25519PrivateKey.generate()
            path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.BestAvailableEncryption(passphrase)))
        else:
            k = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
            if not isinstance(k, Ed25519PrivateKey):
                raise SigningError("command signing key must be Ed25519")
        _key = SigningKey(k, _key_id(k.public_key()))
        return _key


def reset_cache() -> None:
    global _key
    with _lock:
        _key = None


def canonical(envelope: dict) -> bytes:
    """Deterministic JSON (sorted keys, no whitespace, UTF-8). Must match agent/cage_agent/commands/validator.py."""
    body = {k: v for k, v in envelope.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(envelope: dict) -> tuple[str, str]:
    k = get_signing_key()
    return k.key_id, base64.b64encode(k.key.sign(canonical(envelope))).decode()


def verify(envelope: dict, public_key_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(envelope["signature"]), canonical(envelope))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
