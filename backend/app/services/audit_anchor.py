"""Audit-chain anchoring: detect truncation or wholesale rewriting of the audit log.

The hash chain + HMAC (services/audit.py) detects modified or removed records *inside* the chain, but not removal of
the newest records, and not a full re-chain by someone holding the HMAC key. Anchors close that gap:

* Periodically (and on demand) the current chain head `(seq, hash)` is signed with a dedicated Ed25519 key and
  stored twice: in `audit_anchors` (append-only like `audit_logs`) and appended to `<AUDIT_ANCHOR_DIR>/<org>.jsonl`.
* The external file is the part that matters: put it on storage the API host cannot rewrite (WORM bucket, remote
  collector, separate host). Each line is independently verifiable offline with the public key
  (`infrastructure/scripts/verify_audit_anchors.py`).
* Verification checks every anchor (DB and file) against the live chain: an anchored seq that no longer exists means
  the tail was truncated; a different hash means the chain was rewritten. Each anchoring cycle also re-checks the
  previous anchor, so tampering raises a critical alert without anyone pressing "verify".

A failed external write is never ignored: the DB anchor records the error and an operational alert is raised.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import AuditAnchor, AuditLog

log = logging.getLogger("app.audit_anchor")
_lock = threading.Lock()
_key: tuple[Ed25519PrivateKey, str] | None = None


def _key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "anchor-" + hashlib.sha256(raw).hexdigest()[:16]


def get_anchor_key() -> tuple[Ed25519PrivateKey, str]:
    global _key
    with _lock:
        if _key:
            return _key
        s = get_settings()
        path = Path(s.device_ca_dir) / "audit-anchor.key"
        pw = s.device_ca_key_passphrase.encode()
        enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            k = Ed25519PrivateKey.generate()
            path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
        else:
            loaded = serialization.load_pem_private_key(path.read_bytes(), password=pw or None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise RuntimeError(f"{path} must contain an Ed25519 key")
            k = loaded
        _key = (k, _key_id(k.public_key()))
        return _key


def reset_cache() -> None:
    global _key
    with _lock:
        _key = None


def public_key_pem() -> str:
    k, _ = get_anchor_key()
    return k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def canonical(org_id: str, seq: int, digest: str, ts: str, key_id: str) -> bytes:
    """Must match infrastructure/scripts/verify_audit_anchors.py."""
    body = {"v": 1, "org": org_id, "seq": seq, "hash": digest, "ts": ts, "key_id": key_id}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def anchor_file(org_id: uuid.UUID) -> Path:
    return Path(get_settings().audit_anchor_dir) / f"{org_id}.jsonl"


def _verify_sig(org_id: str, seq: int, digest: str, ts: str, key_id: str, sig_b64: str) -> bool:
    k, kid = get_anchor_key()
    if key_id != kid:
        return False
    try:
        k.public_key().verify(base64.b64decode(sig_b64), canonical(org_id, seq, digest, ts, key_id))
        return True
    except (InvalidSignature, ValueError):
        return False


def _ts(a: AuditAnchor) -> str:
    return a.created_at.isoformat(timespec="microseconds")


def _append_external(org_id: uuid.UUID, line: dict) -> None:
    path = anchor_file(org_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def create_anchor(db: Session, org_id: uuid.UUID, *, force: bool = False) -> AuditAnchor | None:
    """Anchor the current chain head if it moved (and, unless forced, the interval elapsed). Caller commits."""
    head = db.execute(select(AuditLog.seq, AuditLog.hash).where(AuditLog.organization_id == org_id)
                      .order_by(AuditLog.seq.desc()).limit(1)).first()
    if head is None:
        return None
    last = db.scalar(select(AuditAnchor).where(AuditAnchor.organization_id == org_id)
                     .order_by(AuditAnchor.seq.desc()).limit(1))
    if last is not None:
        if last.seq == head.seq:
            return None
        interval = timedelta(minutes=get_settings().audit_anchor_interval_minutes)
        if not force and last.created_at > utcnow() - interval:
            return None
    key, kid = get_anchor_key()
    a = AuditAnchor(id=uuid.uuid4(), organization_id=org_id, seq=head.seq, hash=head.hash, created_at=utcnow(),
                    key_id=kid, signature="")
    a.signature = base64.b64encode(key.sign(canonical(str(org_id), a.seq, a.hash, _ts(a), kid))).decode()
    try:
        _append_external(org_id, {"v": 1, "org": str(org_id), "seq": a.seq, "hash": a.hash, "ts": _ts(a),
                                  "key_id": kid, "sig": a.signature})
        a.external_written = True
    except OSError as exc:
        a.external_written, a.external_error = False, str(exc)[:300]
        log.error("audit anchor external write failed: %s", exc)
        from app.services import alerts
        alerts.raise_alert(db, org_id, "audit_anchor_failed", severity="high", dedup_key="audit_anchor_failed",
                           title="Audit anchor could not be written to external storage",
                           description=f"The audit chain head (seq {a.seq}) was anchored in the database only: {exc}. "
                                       "Truncation of the audit log is not detectable from outside until this is fixed.",
                           evidence={"seq": a.seq, "error": str(exc)[:300]}, auto_resolvable=True)
    else:
        from app.services import alerts
        alerts.auto_resolve(db, org_id, "audit_anchor_failed", "external anchor written successfully")
    db.add(a)
    db.flush()
    return a


@dataclass
class AnchorReport:
    valid: bool
    anchors_checked: int
    external_file: str
    external_anchors: int
    last_anchor_seq: int | None
    last_anchor_at: str | None
    problems: list[str] = field(default_factory=list)


def _read_external(org_id: uuid.UUID, problems: list[str]) -> list[dict]:
    path = anchor_file(org_id)
    if not path.exists():
        return []
    out = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            d = json.loads(raw)
            out.append({"seq": int(d["seq"]), "hash": str(d["hash"]), "ts": str(d["ts"]),
                        "key_id": str(d["key_id"]), "sig": str(d["sig"]), "org": str(d["org"]), "line": n})
        except (ValueError, KeyError, TypeError):
            problems.append(f"external anchor file line {n} is malformed")
    return out


def verify_anchors(db: Session, org_id: uuid.UUID) -> AnchorReport:
    problems: list[str] = []
    db_anchors = db.scalars(select(AuditAnchor).where(AuditAnchor.organization_id == org_id)
                            .order_by(AuditAnchor.seq)).all()
    ext = _read_external(org_id, problems)
    if not ext and any(a.external_written for a in db_anchors):
        problems.append("external anchor file is missing or empty although anchors were written to it")

    merged: dict[int, str] = {}
    for a in db_anchors:
        if not _verify_sig(str(org_id), a.seq, a.hash, _ts(a), a.key_id, a.signature):
            problems.append(f"database anchor at seq {a.seq} has an invalid signature")
            continue
        merged[a.seq] = a.hash
    db_seqs = {a.seq for a in db_anchors}
    for e in ext:
        if e["org"] != str(org_id) or not _verify_sig(e["org"], e["seq"], e["hash"], e["ts"], e["key_id"], e["sig"]):
            problems.append(f"external anchor (line {e['line']}) has an invalid signature")
            continue
        if e["seq"] not in db_seqs:
            problems.append(f"anchor at seq {e['seq']} exists externally but was removed from the database")
        if e["seq"] in merged and merged[e["seq"]] != e["hash"]:
            problems.append(f"anchor at seq {e['seq']} differs between database and external file")
        merged.setdefault(e["seq"], e["hash"])

    if merged:
        rows = dict(db.execute(select(AuditLog.seq, AuditLog.hash).where(
            AuditLog.organization_id == org_id, AuditLog.seq.in_(list(merged)))).all())
        for seq in sorted(merged):
            if seq not in rows:
                problems.append(f"audit record {seq} was anchored but no longer exists (log truncated)")
            elif rows[seq] != merged[seq]:
                problems.append(f"audit record {seq} differs from its anchor (chain rewritten)")

    last = db_anchors[-1] if db_anchors else None
    last_seq = max(merged) if merged else None
    return AnchorReport(valid=not problems, anchors_checked=len(merged), external_file=str(anchor_file(org_id)),
                        external_anchors=len(ext), last_anchor_seq=last_seq,
                        last_anchor_at=_ts(last) if last else None, problems=problems)


def check_latest(db: Session, org_id: uuid.UUID) -> str | None:
    """Cheap scheduler check: does the newest anchored record still exist with the anchored hash?"""
    last = db.scalar(select(AuditAnchor).where(AuditAnchor.organization_id == org_id)
                     .order_by(AuditAnchor.seq.desc()).limit(1))
    if last is None:
        return None
    current = db.scalar(select(AuditLog.hash).where(AuditLog.organization_id == org_id, AuditLog.seq == last.seq))
    if current is None:
        return f"audit record {last.seq} was anchored but no longer exists (log truncated)"
    if current != last.hash:
        return f"audit record {last.seq} differs from its anchor (chain rewritten)"
    return None


def cycle(db: Session) -> int:
    """Scheduler entry: re-check the latest anchor, then anchor the new head, for every organisation."""
    from app.models import Organization
    from app.services import alerts
    made = 0
    for org_id in db.scalars(select(Organization.id)).all():
        problem = check_latest(db, org_id)
        if problem:
            alerts.raise_alert(db, org_id, "audit_integrity", severity="critical", dedup_key="audit_integrity",
                               title="Audit log integrity check failed",
                               description=f"{problem}. Investigate database access immediately and compare with the "
                                           "external anchor file and backups.",
                               evidence={"problem": problem})
            continue  # do not anchor a tampered chain
        if create_anchor(db, org_id):
            made += 1
    return made
