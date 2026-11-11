"""Test harness. Uses SQLite by default; set TEST_DATABASE_URL to an empty PostgreSQL database to run the
same suite against PostgreSQL (recommended in CI). The schema is built with the real Alembic migration."""
from __future__ import annotations

import base64
import email
import hashlib
import json
import os
import re
import struct
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ORIGIN, RP_ID = "http://localhost:5173", "localhost"

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATA_ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("AUDIT_HMAC_KEY", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("DATABASE_URL", "sqlite://")  # replaced per test below

BACKEND = Path(__file__).resolve().parents[1]


@pytest.fixture()
def outbox(tmp_path: Path) -> Path:
    return tmp_path / "outbox"


@pytest.fixture()
def client(tmp_path: Path, outbox: Path, monkeypatch: pytest.MonkeyPatch):
    from alembic import command
    from alembic.config import Config

    import app.core.database as database
    import app.core.rate_limit as rl
    from app.core.config import get_settings

    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    # Migrate as the schema owner (if given), exercise the API as the least-privilege role. Always set explicitly
    # so a developer's backend/.env can never point the test run at a real database.
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ.get("TEST_MIGRATION_DATABASE_URL") or url)
    monkeypatch.setenv("DEV_OUTBOX_DIR", str(outbox))
    monkeypatch.setenv("DEVICE_CA_DIR", str(tmp_path / "pki"))
    monkeypatch.setenv("AUDIT_ANCHOR_DIR", str(tmp_path / "anchors"))
    get_settings.cache_clear()
    import app.security.pki as pki
    pki.reset_ca_cache()
    import app.security.command_signing as cs
    cs.reset_cache()
    import app.security.oidc_keys as ok
    ok.reset_cache()
    import app.services.audit_anchor as aa
    aa.reset_cache()
    database._engine = None
    database._SessionLocal = None
    rl._limiter = None

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    command.upgrade(cfg, "head")

    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(), base_url="http://testserver") as c:
        c._cage_authn = {}  # email -> SoftAuthenticator, so login() can replay each account's passkey
        yield c

    if os.environ.get("TEST_DATABASE_URL"):
        command.downgrade(cfg, "base")
    database.get_engine().dispose()


def last_token(outbox: Path, path: str) -> str:
    files = sorted(outbox.glob("*.eml"), key=lambda p: p.stat().st_mtime_ns)
    for f in reversed(files):
        body = email.message_from_bytes(f.read_bytes()).get_payload(decode=True).decode()
        m = re.search(re.escape(path) + r"\?token=([A-Za-z0-9_\-]+)", body)
        if m:
            return m.group(1)
    raise AssertionError(f"no email containing {path}")


STRONG = "Correct-Horse-Battery-9"  # retained only for the few tests that still type a literal; not a login secret


def csrf(client) -> dict[str, str]:
    # Tolerant of duplicate cage_csrf cookies across domains/paths (httpx .get() would raise CookieConflict).
    value = next((c.value for c in client.cookies.jar if c.name == "cage_csrf"), "")
    return {"X-CSRF-Token": value}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """Software WebAuthn platform authenticator (ES256, 'none' attestation, UV performed). Real py_webauthn verifies
    its output, so passkey sign-in is exercised end to end without a device."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0
        self.user_handle = b""

    def _auth_data(self, flags: int, attested: bytes = b"") -> bytes:
        self.count += 1
        return hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + struct.pack(">I", self.count) + attested

    def create(self, options: dict, origin: str = ORIGIN) -> dict:
        self.user_handle = _unb64u(options["user"]["id"])
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        attested = bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose
        auth_data = self._auth_data(0x01 | 0x04 | 0x40, attested)  # UP | UV | AT
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}).encode()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": _b64u(self.cred_id), "rawId": _b64u(self.cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": _b64u(client), "attestationObject": _b64u(att), "transports": ["internal"]}}

    def get(self, options: dict, origin: str = ORIGIN, uv: bool = True) -> dict:
        auth_data = self._auth_data(0x01 | (0x04 if uv else 0))
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        sig = self.key.sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": _b64u(self.cred_id), "rawId": _b64u(self.cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": _b64u(client), "authenticatorData": _b64u(auth_data),
                             "signature": _b64u(sig), "userHandle": _b64u(self.user_handle)}}


def enrol_passkey(client, token: str, email_addr: str, name: str = "Test device") -> SoftAuthenticator:
    """Register a passkey via a single-use enrol/invite/recovery token and remember it for login()."""
    authn = SoftAuthenticator()
    o = client.post("/api/v1/auth/enroll/options", json={"token": token})
    assert o.status_code == 200, o.text
    opts = o.json()
    r = client.post("/api/v1/auth/enroll/verify", json={
        "token": token, "challenge_id": opts["challenge_id"], "credential": authn.create(opts["options"]), "name": name})
    assert r.status_code == 200, r.text
    client._cage_authn[email_addr] = authn
    return authn


def bootstrap_admin(client, outbox: Path, email_addr: str = "root@example.com") -> None:
    """Passwordless first-run: create the org + Super Admin and register their passkey. Leaves the client signed in."""
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme Corp", "full_name": "Ada Root", "email": email_addr})
    assert r.status_code == 201, r.text
    enrol_passkey(client, r.json()["enroll_token"], email_addr, "Root device")


def invite_and_accept(client, outbox: Path, email_addr: str, role: str, full_name: str = "Some Body") -> None:
    """Invite an administrator and enrol their passkey, WITHOUT changing the current session (the inviter stays
    signed in). Afterwards login(client, email_addr) signs in as the new user."""
    r = client.post("/api/v1/users", json={"email": email_addr, "full_name": full_name, "role": role},
                    headers=csrf(client))
    assert r.status_code == 201, r.text
    token = last_token(outbox, "/accept-invite")
    saved = [(c.name, c.value, c.domain, c.path) for c in client.cookies.jar]  # keep domain/path to avoid conflicts
    client.cookies.clear()
    enrol_passkey(client, token, email_addr, "Invited device")  # sets the invitee's session
    client.cookies.clear()
    for name, value, domain, path in saved:
        client.cookies.set(name, value, domain=domain, path=path)  # restore the inviter's session


def step_up(client, email_addr: str) -> dict:
    """A fresh passkey assertion confirming a sensitive action (remote commands), for the signed-in account."""
    authn = client._cage_authn[email_addr]
    o = client.post("/api/v1/auth/step-up/options", headers=csrf(client)).json()
    return {"challenge_id": o["challenge_id"], "credential": authn.get(o["options"])}


def login(client, email_addr: str, password: str | None = None) -> dict:
    """Passkey sign-in using the account's remembered authenticator (bootstrap/invite/enrol registered it)."""
    authn = client._cage_authn[email_addr]
    o = client.post("/api/v1/auth/passkeys/login/options").json()
    r = client.post("/api/v1/auth/passkeys/login/verify",
                    json={"challenge_id": o["challenge_id"], "credential": authn.get(o["options"])})
    assert r.status_code == 200, r.text
    return r.json()
