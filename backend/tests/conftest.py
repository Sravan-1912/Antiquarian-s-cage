"""Test harness. Uses SQLite by default; set TEST_DATABASE_URL to an empty PostgreSQL database to run the
same suite against PostgreSQL (recommended in CI). The schema is built with the real Alembic migration."""
from __future__ import annotations

import base64
import email
import os
import re
from pathlib import Path

import pytest

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


STRONG = "Correct-Horse-Battery-9"


def csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("cage_csrf", "")}


def bootstrap_admin(client, outbox: Path, email_addr: str = "root@example.com") -> None:
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme Corp", "full_name": "Ada Root", "email": email_addr, "password": STRONG})
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/auth/verify-email", json={"token": last_token(outbox, "/verify-email")})
    assert r.status_code == 200, r.text


def login(client, email_addr: str, password: str = STRONG) -> dict:
    r = client.post("/api/v1/auth/login", json={"email": email_addr, "password": password})
    assert r.status_code == 200, r.text
    return r.json()
