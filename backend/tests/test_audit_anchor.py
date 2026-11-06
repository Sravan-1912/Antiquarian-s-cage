"""Audit anchoring: tail truncation and anchor tampering are detected, external-write failures are never silent."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text

from tests.conftest import bootstrap_admin, csrf, login

EMP = {"employee_number": "E-2001", "full_name": "Ada Lovelace", "email": "ada@example.com",
       "department": "Engineering", "job_title": "Engineer"}
ROOT = Path(__file__).resolve().parents[2]


def _as_owner(sql: str, table: str) -> None:
    """Simulate an attacker with schema-owner rights: on PostgreSQL they must first disable the append-only trigger."""
    url = os.environ["MIGRATION_DATABASE_URL"]
    eng = create_engine(url)
    with eng.begin() as c:
        pg = c.dialect.name == "postgresql"
        trig = f"{table}_no_update_delete"
        if pg:
            c.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER {trig}"))
        c.execute(text(sql))
        if pg:
            c.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER {trig}"))
    eng.dispose()


def _setup(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    client.post("/api/v1/employees", json=EMP, headers=csrf(client))


def _anchor_file() -> Path:
    files = list(Path(os.environ["AUDIT_ANCHOR_DIR"]).glob("*.jsonl"))
    assert len(files) == 1
    return files[0]


def test_anchor_created_signed_and_offline_verifiable(client, outbox):
    _setup(client, outbox)
    a = client.post("/api/v1/audit/anchors", headers=csrf(client)).json()
    assert a["external_written"] is True and a["seq"] >= 3
    line = json.loads(_anchor_file().read_text().splitlines()[-1])
    assert line["seq"] == a["seq"] and line["hash"] == a["hash"]

    r = client.post("/api/v1/audit/verify", headers=csrf(client)).json()
    assert r["valid"] is True and r["anchors"]["valid"] is True and r["anchors"]["anchors_checked"] == 1

    # The offline verifier needs only the public key and the file.
    pem = client.get("/api/v1/audit/anchors/public-key").text
    key = Path(os.environ["AUDIT_ANCHOR_DIR"]) / "anchor-public.pem"
    key.write_text(pem)
    script = ROOT / "infrastructure" / "scripts" / "verify_audit_anchors.py"
    ok = subprocess.run([sys.executable, str(script), str(_anchor_file()), str(key)], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    lines = _anchor_file().read_text().splitlines()
    forged = json.loads(lines[-1]) | {"seq": 999}
    _anchor_file().write_text("\n".join(lines + [json.dumps(forged)]) + "\n")
    bad = subprocess.run([sys.executable, str(script), str(_anchor_file()), str(key)], capture_output=True, text=True)
    assert bad.returncode == 1 and "INVALID" in bad.stdout


def test_tail_truncation_detected_and_alerted(client, outbox):
    _setup(client, outbox)
    a = client.post("/api/v1/audit/anchors", headers=csrf(client)).json()
    # Attacker removes the newest records (including the anchored one). The chain itself still verifies...
    _as_owner(f"DELETE FROM audit_logs WHERE seq >= {a['seq']}", "audit_logs")
    r = client.post("/api/v1/audit/verify", headers=csrf(client)).json()
    # ...but the anchor exposes it.
    assert r["valid"] is False
    assert any("truncated" in p for p in r["anchors"]["problems"])

    # Refuses to anchor the tampered chain, and the scheduler raises a critical alert without anyone asking.
    assert client.post("/api/v1/audit/anchors", headers=csrf(client)).status_code == 409
    from app.core.database import session_factory
    from app.models import SecurityAlert
    from app.workers.tasks import run_cycle
    with session_factory()() as db:
        run_cycle(db)
        alert = db.scalar(select(SecurityAlert).where(SecurityAlert.rule_key == "audit_integrity"))
        assert alert is not None and alert.severity == "critical"


def test_anchor_removed_from_database_detected(client, outbox):
    _setup(client, outbox)
    client.post("/api/v1/audit/anchors", headers=csrf(client))
    _as_owner("DELETE FROM audit_anchors", "audit_anchors")
    r = client.post("/api/v1/audit/verify", headers=csrf(client)).json()
    assert r["valid"] is False
    assert any("removed from the database" in p for p in r["anchors"]["problems"])


def test_external_file_deleted_detected(client, outbox):
    _setup(client, outbox)
    client.post("/api/v1/audit/anchors", headers=csrf(client))
    _anchor_file().unlink()
    r = client.post("/api/v1/audit/verify", headers=csrf(client)).json()
    assert r["valid"] is False and any("external anchor file" in p for p in r["anchors"]["problems"])


def test_external_write_failure_is_not_silent(client, outbox, monkeypatch):
    _setup(client, outbox)
    blocker = Path(os.environ["AUDIT_ANCHOR_DIR"]).parent / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setenv("AUDIT_ANCHOR_DIR", str(blocker))
    from app.core.config import get_settings
    get_settings.cache_clear()
    a = client.post("/api/v1/audit/anchors", headers=csrf(client)).json()
    assert a["external_written"] is False and a["external_error"]
    from app.core.database import session_factory
    from app.models import SecurityAlert
    with session_factory()() as db:
        alert = db.scalar(select(SecurityAlert).where(SecurityAlert.rule_key == "audit_anchor_failed"))
        assert alert is not None and alert.severity == "high"


def test_anchors_append_only_on_postgres(client, outbox):
    _setup(client, outbox)
    client.post("/api/v1/audit/anchors", headers=csrf(client))
    from sqlalchemy.exc import DBAPIError

    from app.core.database import session_factory
    with session_factory()() as db:
        if db.bind.dialect.name != "postgresql":
            pytest.skip("trigger exists only on PostgreSQL")
        with pytest.raises(DBAPIError):
            db.execute(text("DELETE FROM audit_anchors"))
            db.commit()
