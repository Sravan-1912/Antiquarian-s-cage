"""Request signing. The canonical form MUST match backend/app/security/pki.py::canonical_request."""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_request(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return "\n".join([
        "CAGE-AGENT-V1", method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest(),
    ]).encode()


def sign_headers(key: ec.EllipticCurvePrivateKey, device_id: str, method: str, path: str, body: bytes) -> dict[str, str]:
    ts = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_hex(16)
    sig = key.sign(canonical_request(method, path, ts, nonce, body), ec.ECDSA(hashes.SHA256()))
    return {
        "X-Cage-Device": device_id,
        "X-Cage-Timestamp": ts,
        "X-Cage-Nonce": nonce,
        "X-Cage-Signature": base64.b64encode(sig).decode(),
    }
