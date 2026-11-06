"""Device identity: P-256 key generation, CSR creation, protected key storage."""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cage_agent.core.configuration import AgentPaths
from cage_agent.security import secure_storage


def generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def make_csr(key: ec.EllipticCurvePrivateKey, hostname: str) -> str:
    # The server ignores the requested subject and assigns CN=<device uuid>; the CSR proves key possession.
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM).decode())


def store_key(paths: AgentPaths, key: ec.EllipticCurvePrivateKey, scope: str, service_principal: str | None = None) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    tmp = paths.key.with_suffix(".tmp")
    tmp.write_bytes(secure_storage.protect(pem, scope))
    secure_storage.restrict_acl(tmp, service_principal)
    tmp.replace(paths.key)


def load_key(paths: AgentPaths) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(secure_storage.unprotect(paths.key.read_bytes()), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("device key has unexpected type")
    return key


def certificate_not_after(paths: AgentPaths):
    if not paths.cert.exists():
        return None
    return x509.load_pem_x509_certificate(paths.cert.read_bytes()).not_valid_after_utc
