"""Create the production key material offline: device CA + command-signing key.

    DEVICE_CA_KEY_PASSPHRASE=... python infrastructure/scripts/create_device_ca.py ./pki "Acme Corp"

Copy device-ca.crt to the Nginx agent listener (ssl_client_certificate) and give the API read access to both files
(DEVICE_CA_DIR). Also creates command-signing.key (Ed25519, encrypted with the same passphrase), which the API
requires in production. Keep offline backups of both encrypted keys (cage_backup.py includes them); losing the CA
means every device must re-enrol, losing the signing key means every agent must re-pin."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("DATA_ENCRYPTION_KEY", "A" * 43 + "=")
os.environ.setdefault("AUDIT_HMAC_KEY", "B" * 43 + "=")

from app.security.pki import create_ca  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    passphrase = os.environ.get("DEVICE_CA_KEY_PASSPHRASE", "")
    if len(passphrase) < 24:
        sys.exit("Set DEVICE_CA_KEY_PASSPHRASE (at least 24 characters)")
    target = Path(sys.argv[1])
    if (target / "device-ca.key").exists():
        sys.exit(f"{target / 'device-ca.key'} already exists; refusing to overwrite")
    ca = create_ca(target, passphrase.encode(), sys.argv[2] if len(sys.argv) > 2 else "Antiquarian's Cage")
    print(f"Device CA created in {target} (valid until {ca.cert.not_valid_after_utc:%Y-%m-%d})")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    signing = target / "command-signing.key"
    if signing.exists():
        print(f"{signing} already exists; left unchanged")
    else:
        k = Ed25519PrivateKey.generate()
        signing.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.BestAvailableEncryption(passphrase.encode())))
        print(f"Command-signing key created: {signing}")
