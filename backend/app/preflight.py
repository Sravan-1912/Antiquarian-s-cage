"""Deployment preflight: `python -m app.preflight` (exit code 1 if any check FAILs).

Validates the live deployment, not just the configuration file: the API's database role really is least-privilege,
the append-only triggers exist, migrations are at head, keys load with the configured passphrase, anchor storage is
writable, and Redis / SMTP are reachable. Run it after every deploy and before go-live; paste the output into the
change record.
"""
from __future__ import annotations

import os
import socket
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

results: list[tuple[str, str, str]] = []


def check(name: str):
    def deco(fn):
        try:
            status, detail = fn()
        except Exception as exc:  # noqa: BLE001 - every failure is reported, never swallowed
            status, detail = "FAIL", f"{exc.__class__.__name__}: {exc}"
        results.append((status, name, detail))
        return fn
    return deco


def main() -> int:
    try:
        from app.core.config import get_settings
        s = get_settings()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL  configuration         {exc}")
        return 1
    prod = s.environment == "production"
    results.append(("PASS", "configuration", f"environment={s.environment}; production guards passed" if prod
                    else f"environment={s.environment} (production guards not enforced)"))

    from sqlalchemy import text

    from app.core.database import session_factory

    @check("database connection")
    def _db():
        with session_factory()() as db:
            user = db.execute(text("select current_user")).scalar()
            dialect = db.bind.dialect.name
        return ("PASS" if dialect == "postgresql" else ("FAIL" if prod else "WARN")), f"{dialect} as {user}"

    @check("least-privilege API role")
    def _priv():
        with session_factory()() as db:
            if db.bind.dialect.name != "postgresql":
                return "WARN", "not PostgreSQL - role checks skipped"
            bad = []
            for table in ("audit_logs", "audit_anchors"):
                for priv in ("UPDATE", "DELETE", "TRUNCATE"):
                    if db.execute(text("select has_table_privilege(current_user, :t, :p)"),
                                  {"t": table, "p": priv}).scalar():
                        bad.append(f"{priv} on {table}")
            owner = db.execute(text("select tableowner = current_user from pg_tables where tablename='audit_logs'")).scalar()
            superuser = db.execute(text("select rolsuper from pg_roles where rolname = current_user")).scalar()
        if superuser or owner:
            return "FAIL", "API connects as a superuser or the schema owner"
        return ("FAIL", "API role can " + ", ".join(bad)) if bad else ("PASS", "no UPDATE/DELETE/TRUNCATE on audit tables")

    @check("append-only triggers")
    def _trig():
        with session_factory()() as db:
            if db.bind.dialect.name != "postgresql":
                return "WARN", "not PostgreSQL"
            names = set(db.execute(text("select tgname from pg_trigger where not tgisinternal and tgenabled <> 'D'"))
                        .scalars())
        need = {"audit_logs_no_update_delete", "audit_anchors_no_update_delete"}
        missing = need - names
        return ("FAIL", f"missing or disabled: {sorted(missing)}") if missing else ("PASS", "enabled on audit_logs, audit_anchors")

    @check("migrations at head")
    def _mig():
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        here = Path(__file__).resolve().parents[1]
        cfg = Config(str(here / "alembic.ini"))
        cfg.set_main_option("script_location", str(here / "migrations"))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        with session_factory()() as db:
            cur = db.execute(text("select version_num from alembic_version")).scalar()
        return ("PASS", f"{cur}") if cur == head else ("FAIL", f"database at {cur}, code expects {head}")

    @check("device CA + command-signing key")
    def _keys():
        from app.security.command_signing import get_signing_key
        from app.security.pki import get_ca
        ca, key = get_ca(), get_signing_key()
        d = Path(s.device_ca_dir)
        loose = []
        if os.name != "nt":
            loose = [p.name for p in d.glob("*.key") if p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)]
        if loose:
            return "FAIL", f"key files readable by group/others: {loose}"
        return "PASS", f"CA valid until {ca.cert.not_valid_after_utc:%Y-%m-%d}; signing key {key.key_id}"

    @check("audit anchor storage")
    def _anchors():
        d = Path(s.audit_anchor_dir)
        d.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=d, prefix=".preflight-", delete=True) as f:
            f.write(b"ok")
            f.flush()
        n = len(list(d.glob("*.jsonl")))
        return "PASS", f"{d.resolve()} writable; {n} organisation anchor file(s)"

    @check("redis")
    def _redis():
        if not s.redis_url:
            return ("FAIL" if prod else "WARN"), "REDIS_URL not set (in-memory rate limiting: single instance only)"
        u = urlparse(s.redis_url)
        socket.create_connection((u.hostname, u.port or 6379), timeout=3).close()
        return "PASS", f"{u.hostname}:{u.port or 6379} reachable"

    @check("smtp")
    def _smtp():
        if not s.smtp_host:
            return ("FAIL" if prod else "WARN"), "SMTP_HOST not set (emails go to the dev outbox)"
        socket.create_connection((s.smtp_host, s.smtp_port), timeout=5).close()
        return "PASS", f"{s.smtp_host}:{s.smtp_port} reachable"

    @check("transport security")
    def _tls():
        issues = []
        if not s.public_base_url.startswith("https://"):
            issues.append("PUBLIC_BASE_URL is not https")
        if not s.cookie_secure:
            issues.append("COOKIE_SECURE is false")
        if not s.agent_require_mtls:
            issues.append("AGENT_REQUIRE_MTLS is false")
        if issues:
            return ("FAIL" if prod else "WARN"), "; ".join(issues)
        return "PASS", "https URLs, secure cookies, agent mTLS required"

    width = max(len(n) for _, n, _ in results)
    for status, name, detail in results:
        print(f"{status:5} {name:{width}}  {detail}")
    fails = sum(1 for st, _, _ in results if st == "FAIL")
    warns = sum(1 for st, _, _ in results if st == "WARN")
    print(f"\n{len(results)} checks: {fails} failed, {warns} warnings")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
