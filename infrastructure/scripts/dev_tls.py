"""Development-only TLS for testing agents on other machines in the LAN.

    python infrastructure/scripts/dev_tls.py 192.168.0.100

Creates backend/var/tls/dev-ca.crt (give this to the test endpoint as --ca-bundle), dev-ca.key, server.crt and
server.key (certificate for the given IP + localhost, 90 days). The agent refuses plain http outside localhost,
because the Windows-unlock key travels in a response; this keeps that path encrypted without weakening the agent.
Never use these files in production (use real certificates behind Nginx).
"""
from __future__ import annotations

import ipaddress
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parents[2] / "backend" / "var" / "tls"


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))


def main(ip: str) -> None:
    ipaddress.ip_address(ip)
    OUT.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_path = OUT / "dev-ca.crt"
    if ca_path.exists():
        ca_key = serialization.load_pem_private_key((OUT / "dev-ca.key").read_bytes(), None)
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Antiquarian's Cage DEV CA (testing only)")])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
              .not_valid_after(now + timedelta(days=365))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))
        _write_key(OUT / "dev-ca.key", ca_key)
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    key = ec.generate_private_key(ec.SECP256R1())
    san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip)),
                                       x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")])
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write_key(OUT / "server.key", key)
    (OUT / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"dev CA: {ca_path}\nserver certificate for {ip} (+localhost): {OUT / 'server.crt'} (valid 90 days)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
