"""RS256 signing key for OIDC ID/access tokens (separate from the device CA, command and audit keys).

Development auto-creates it (passphrase-encrypted) under DEVICE_CA_DIR; production requires it to exist."""
from __future__ import annotations

import base64
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import get_settings


@dataclass
class OIDCKey:
    private_key: rsa.RSAPrivateKey
    kid: str

    def jwk(self) -> dict:
        n = self.private_key.public_key().public_numbers()

        def b64(i: int) -> str:
            return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": b64(n.n), "e": b64(n.e)}


_lock = threading.Lock()
_key: OIDCKey | None = None


def get_oidc_key() -> OIDCKey:
    global _key
    with _lock:
        if _key:
            return _key
        s = get_settings()
        path = Path(s.device_ca_dir) / "oidc-signing.key"
        pw = s.device_ca_key_passphrase.encode()
        if not path.exists():
            if s.environment == "production":
                raise RuntimeError("OIDC signing key not found; create it offline before starting in production")
            path.parent.mkdir(parents=True, exist_ok=True)
            k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.BestAvailableEncryption(pw)))
        else:
            k = serialization.load_pem_private_key(path.read_bytes(), password=pw)
            if not isinstance(k, rsa.RSAPrivateKey):
                raise RuntimeError(f"{path} does not contain an RSA private key")
        der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        _key = OIDCKey(k, "oidc-" + hashlib.sha256(der).hexdigest()[:16])
        return _key


def reset_cache() -> None:
    global _key
    with _lock:
        _key = None
