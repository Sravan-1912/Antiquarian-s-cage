"""Encrypted backup, restore and restore drill for Antiquarian's Cage.

    python cage_backup.py backup  --out D:/backups                     # writes cage-<UTC>.cagebak
    python cage_backup.py restore --bundle X.cagebak --target-db NAME --keys-dir DIR
    python cage_backup.py drill   --out D:/backups                     # backup -> restore into a scratch DB -> verify

What a bundle holds (tar, then AES-256-GCM encrypted with a key derived from BACKUP_PASSPHRASE via scrypt):
  database.dump    pg_dump custom format of the whole database (schema owner connection)
  pki/             device CA, command-signing, OIDC and audit-anchor keys  (losing these = re-enrolling every agent)
  anchors/         external audit-anchor files (copy; the primary should live on WORM storage)
  manifest.json    SHA-256 of every member, source DB revision, table row counts, creation time
It deliberately does NOT contain DATA_ENCRYPTION_KEY / AUDIT_HMAC_KEY: keep those in your secret manager. A restore
needs them to decrypt MFA secrets and to verify the audit chain; the drill proves the pair (bundle + secrets) works.

Environment: MIGRATION_DATABASE_URL (owner role), RESTORE_ADMIN_URL (optional DBA role, only for CREATE/DROP
DATABASE during restore), BACKUP_PASSPHRASE (>= 16 chars), PG_BIN (folder with pg_dump /
pg_restore / psql; default: PostgreSQL 16 on Windows), DEVICE_CA_DIR, AUDIT_ANCHOR_DIR (defaults as in the API).
Passwords are passed to PostgreSQL tools through PGPASSWORD, never on the command line.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BACKEND = Path(__file__).resolve().parents[2] / "backend"
MAGIC = b"CAGEBAK1"
TABLES = ["organizations", "users", "employees", "devices", "audit_logs", "audit_anchors", "security_alerts",
          "endpoint_policies", "compliance_evaluations", "applications"]


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if not v:
        sys.exit(f"{name} is not set")
    return v


def _pg(url: str) -> tuple[dict, dict]:
    """Connection args + env for PostgreSQL CLI tools from a SQLAlchemy URL."""
    u = urlparse(url.replace("postgresql+psycopg://", "postgresql://"))
    args = {"host": u.hostname or "localhost", "port": str(u.port or 5432), "user": unquote(u.username or ""),
            "dbname": u.path.lstrip("/")}
    env = {**os.environ, "PGPASSWORD": unquote(u.password or "")}
    return args, env


def _tool(name: str) -> str:
    base = Path(os.environ.get("PG_BIN", r"C:\Program Files\PostgreSQL\16\bin"))
    exe = base / (name + (".exe" if os.name == "nt" else ""))
    if not exe.exists():
        sys.exit(f"{exe} not found (set PG_BIN)")
    return str(exe)


def _run(cmd: list[str], env: dict) -> str:
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{Path(cmd[0]).name} failed ({r.returncode}): {r.stderr.strip()[:2000]}")
    return r.stdout


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 16:
        sys.exit("BACKUP_PASSPHRASE must be at least 16 characters")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _psql(args: dict, env: dict, sql: str) -> str:
    return _run([_tool("psql"), "-h", args["host"], "-p", args["port"], "-U", args["user"], "-d", args["dbname"],
                 "-tAX", "-v", "ON_ERROR_STOP=1", "-c", sql], env).strip()


def _maint(args: dict, env: dict) -> tuple[dict, dict]:
    """Connection for CREATE/DROP DATABASE: RESTORE_ADMIN_URL (a DBA role) if set, else the schema owner."""
    admin = os.environ.get("RESTORE_ADMIN_URL")
    if admin:
        a, e = _pg(admin)
        return {**a, "dbname": "postgres"}, e
    return {**args, "dbname": "postgres"}, env


def _counts(args: dict, env: dict) -> dict[str, int]:
    return {t: int(_psql(args, env, f"SELECT count(*) FROM {t}")) for t in TABLES}


def backup(out_dir: Path) -> Path:
    url = _env("MIGRATION_DATABASE_URL")
    args, env = _pg(url)
    pki = Path(os.environ.get("DEVICE_CA_DIR", BACKEND / "var" / "pki"))
    anchors = Path(os.environ.get("AUDIT_ANCHOR_DIR", BACKEND / "var" / "audit-anchors"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        dump = work / "database.dump"
        _run([_tool("pg_dump"), "-h", args["host"], "-p", args["port"], "-U", args["user"], "-d", args["dbname"],
              "-Fc", "--no-owner", "--no-privileges", "-f", str(dump)], env)
        if pki.exists():
            shutil.copytree(pki, work / "pki")
        else:
            print(f"WARNING: key directory {pki} not found - bundle will not contain keys", file=sys.stderr)
        if anchors.exists():
            shutil.copytree(anchors, work / "anchors")
        files = sorted(p for p in work.rglob("*") if p.is_file())
        manifest = {
            "format": 1, "created_at": stamp, "database": args["dbname"],
            "alembic_revision": _psql(args, env, "SELECT version_num FROM alembic_version"),
            "row_counts": _counts(args, env),
            "files": {p.relative_to(work).as_posix(): _sha(p) for p in files},
        }
        (work / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for p in sorted(work.rglob("*")):
                if p.is_file():
                    tar.add(p, arcname=p.relative_to(work).as_posix())
    salt, nonce = os.urandom(16), os.urandom(12)
    sealed = AESGCM(_key(_env("BACKUP_PASSPHRASE"), salt)).encrypt(nonce, buf.getvalue(), MAGIC)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"cage-{stamp}.cagebak"
    target.write_bytes(MAGIC + salt + nonce + sealed)
    print(f"backup written: {target} ({target.stat().st_size:,} bytes, revision {manifest['alembic_revision']}, "
          f"{manifest['row_counts']['audit_logs']} audit records)")
    return target


def _open_bundle(bundle: Path, into: Path) -> dict:
    raw = bundle.read_bytes()
    if raw[:8] != MAGIC:
        sys.exit("not a Cage backup bundle")
    salt, nonce, sealed = raw[8:24], raw[24:36], raw[36:]
    try:
        plain = AESGCM(_key(_env("BACKUP_PASSPHRASE"), salt)).decrypt(nonce, sealed, MAGIC)
    except Exception:  # noqa: BLE001 - InvalidTag: wrong passphrase or tampered file
        sys.exit("bundle could not be decrypted: wrong BACKUP_PASSPHRASE or the file was modified")
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        tar.extractall(into, filter="data")  # rejects absolute paths, '..' and links outside the target
    manifest = json.loads((into / "manifest.json").read_text(encoding="utf-8"))
    for rel, digest in manifest["files"].items():
        if _sha(into / rel) != digest:
            sys.exit(f"checksum mismatch for {rel}")
    return manifest


def restore(bundle: Path, target_db: str, keys_dir: Path | None, *, allow_existing_keys: bool = False) -> dict:
    url = _env("MIGRATION_DATABASE_URL")
    args, env = _pg(url)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        manifest = _open_bundle(bundle, work)
        maint, menv = _maint(args, env)
        exists = _psql(maint, menv, f"SELECT 1 FROM pg_database WHERE datname = '{target_db}'")
        if exists:
            sys.exit(f"database {target_db} already exists - restore only into a new, empty database")
        _psql(maint, menv, f'CREATE DATABASE "{target_db}" OWNER "{args["user"]}"')
        _run([_tool("pg_restore"), "-h", args["host"], "-p", args["port"], "-U", args["user"], "-d", target_db,
              "--no-owner", "--no-privileges", "--exit-on-error", str(work / "database.dump")], env)
        if keys_dir is not None and (work / "pki").exists():
            if keys_dir.exists() and any(keys_dir.iterdir()) and not allow_existing_keys:
                sys.exit(f"{keys_dir} is not empty - refusing to overwrite live keys")
            shutil.copytree(work / "pki", keys_dir, dirs_exist_ok=True)
        if (work / "anchors").exists():
            shutil.copytree(work / "anchors", (keys_dir or work).parent / "restored-anchors", dirs_exist_ok=True)
    restored = _counts({**args, "dbname": target_db}, env)
    if restored != manifest["row_counts"]:
        sys.exit(f"row counts differ after restore: {restored} vs {manifest['row_counts']}")
    print(f"restored into {target_db}: revision {manifest['alembic_revision']}, row counts match the manifest")
    return manifest


def drill(out_dir: Path) -> None:
    """Full round trip into a throwaway database, then verify the restored data with the application's own code."""
    bundle = backup(out_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    scratch = f"cage_restore_drill_{stamp}"
    args, env = _pg(_env("MIGRATION_DATABASE_URL"))
    with tempfile.TemporaryDirectory() as tmp:
        keys = Path(tmp) / "pki"
        try:
            manifest = restore(bundle, scratch, keys)
            # Verify with the app: audit chain + anchors on the restored DB, using the restored keys.
            u = urlparse(os.environ["MIGRATION_DATABASE_URL"])
            restored_url = os.environ["MIGRATION_DATABASE_URL"].replace(u.path, "/" + scratch, 1)
            code = (
                "from app.core.database import session_factory\n"
                "from app.models import Organization\n"
                "from app.services import audit, audit_anchor\n"
                "from sqlalchemy import select\n"
                "with session_factory()() as db:\n"
                "    for org in db.scalars(select(Organization.id)):\n"
                "        c = audit.verify_chain(db, org); a = audit_anchor.verify_anchors(db, org)\n"
                "        print(f'org {org}: chain valid={c.valid} checked={c.checked}; anchors valid={a.valid} '\n"
                "              f'checked={a.anchors_checked} problems={a.problems}')\n"
                "        assert c.valid and a.valid\n"
            )
            venv_py = BACKEND / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            r = subprocess.run([str(venv_py), "-c", code], cwd=BACKEND, capture_output=True, text=True, env={
                **os.environ, "DATABASE_URL": restored_url, "DEVICE_CA_DIR": str(keys),
                "AUDIT_ANCHOR_DIR": str(Path(tmp) / "restored-anchors"), "SCHEDULER_ENABLED": "false"})
            print(r.stdout.strip())
            if r.returncode != 0:
                sys.exit(f"verification of the restored database FAILED:\n{r.stderr[-3000:]}")
            print(f"DRILL PASSED: {bundle.name} restored into {scratch}; {manifest['row_counts']['audit_logs']} audit "
                  "records, chain and anchors verified with the restored keys")
        finally:
            maint, menv = _maint(args, env)
            _psql(maint, menv, f'DROP DATABASE IF EXISTS "{scratch}"')


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup"); b.add_argument("--out", type=Path, required=True)
    r = sub.add_parser("restore"); r.add_argument("--bundle", type=Path, required=True)
    r.add_argument("--target-db", required=True); r.add_argument("--keys-dir", type=Path)
    d = sub.add_parser("drill"); d.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    if a.cmd == "backup":
        backup(a.out)
    elif a.cmd == "restore":
        restore(a.bundle, a.target_db, a.keys_dir)
    else:
        drill(a.out)


if __name__ == "__main__":
    main()
