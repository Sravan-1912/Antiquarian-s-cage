"""Internal device certificate authority and agent request-signature verification.

* The CA key is ECDSA P-256, stored PEM-encrypted (PKCS#8, AES-256) with DEVICE_CA_KEY_PASSPHRASE.
  In development the CA is created automatically under DEVICE_CA_DIR; in production it must already exist
  (create it offline with infrastructure/scripts/create_device_ca.py and keep the key off the API host if an
  HSM/KMS signer is available).
* Device certificates: CN = device UUID, clientAuth EKU, short lifetime (DEVICE_CERT_DAYS).
* Agent requests are signed with the device key; the canonical string is defined in `canonical_request`.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core.config import get_settings
from app.core.database import utcnow


class PKIError(Exception):
    pass


@dataclass
class CA:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()


_lock = threading.Lock()
_ca: CA | None = None


def _paths() -> tuple[Path, Path]:
    d = Path(get_settings().device_ca_dir)
    return d / "device-ca.crt", d / "device-ca.key"


def create_ca(directory: Path, passphrase: bytes, org_name: str = "Antiquarian's Cage") -> CA:
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, "Antiquarian's Cage Device CA"),
    ])
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    crt_path, key_path = directory / "device-ca.crt", directory / "device-ca.key"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.BestAvailableEncryption(passphrase)))
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return CA(key, cert)


def get_ca() -> CA:
    global _ca
    with _lock:
        if _ca is not None:
            return _ca
        s = get_settings()
        crt_path, key_path = _paths()
        passphrase = s.device_ca_key_passphrase.encode()
        if not crt_path.exists() or not key_path.exists():
            if s.environment == "production":
                raise PKIError("Device CA not found; create it with infrastructure/scripts/create_device_ca.py")
            _ca = create_ca(crt_path.parent, passphrase)
            return _ca
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=passphrase)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise PKIError("Device CA key must be ECDSA")
        _ca = CA(key, x509.load_pem_x509_certificate(crt_path.read_bytes()))
        return _ca


def reset_ca_cache() -> None:
    global _ca
    with _lock:
        _ca = None


@dataclass
class IssuedCert:
    serial: str
    fingerprint: str
    certificate_pem: str
    public_key_pem: str
    not_before: datetime
    not_after: datetime


def sign_csr(csr_pem: str, device_id: uuid.UUID) -> IssuedCert:
    """Validate a CSR (proof of possession, key type) and issue a client certificate for `device_id`.
    The subject requested by the agent is ignored — identity is assigned by the server."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except ValueError as exc:
        raise PKIError("Malformed certificate signing request") from exc
    if not csr.is_signature_valid:
        raise PKIError("CSR signature invalid (no proof of key possession)")
    pub = csr.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise PKIError("Device keys must be ECDSA P-256")

    ca = get_ca()
    now = utcnow()
    days = get_settings().device_cert_days
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(device_id)),
                                 x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "endpoints")]))
        .issuer_name(ca.cert.subject).public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"urn:uuid:{device_id}")]),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
        .sign(ca.key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return IssuedCert(
        serial=format(cert.serial_number, "x"),
        fingerprint=hashlib.sha256(der).hexdigest(),
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        public_key_pem=pub.public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(days=days),
    )


def canonical_request(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """Exactly what the agent signs. Must match agent/security/signatures.py."""
    return "\n".join([
        "CAGE-AGENT-V1", method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest(),
    ]).encode()


def verify_signature(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        pub.verify(base64.b64decode(signature_b64, validate=True), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def new_enrollment_secret() -> str:
    # Human-transcribable: 5 groups of 5 from an unambiguous alphabet (~124 bits).
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(25))
    return "-".join(raw[i:i + 5] for i in range(0, 25, 5))
