"""Periodic maintenance tasks, shared by the in-process scheduler and Celery beat."""
from __future__ import annotations

import logging
import threading
import time

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import session_factory

log = logging.getLogger("app.scheduler")
LOCK_ID = 0x43414745  # "CAGE"


def run_cycle(db: Session, *, purge: bool = False) -> dict:
    """One maintenance pass. Each step commits on its own so one failure cannot block the others."""
    from app.services import alerts, devices, notifications, policies

    out: dict = {}
    try:
        out["expired_jobs"] = policies.expire_jobs(db)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("job expiry failed")
    try:
        out["alerts_raised"] = alerts.sweep(db)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("alert sweep failed")
    try:
        out["emails"] = notifications.deliver_outbox(db)
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("email delivery failed")
    try:
        from app.services import audit_anchor
        out["audit_anchors"] = audit_anchor.cycle(db)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("audit anchoring failed")
    if purge:
        try:
            out["heartbeats_purged"] = devices.purge_old_heartbeats(db)
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("heartbeat purge failed")
    return out


def _locked_cycle(purge: bool) -> None:
    with session_factory()() as db:
        pg = db.bind.dialect.name == "postgresql"
        if pg and not db.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_ID}).scalar():
            return  # another instance is running the scheduler
        try:
            res = run_cycle(db, purge=purge)
            if any(v for v in res.values() if v not in (0, (0, 0))):
                log.info("scheduler cycle", extra={"event": "scheduler", **{"status": str(res)}})
        finally:
            if pg:
                db.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_ID})
                db.commit()


class Scheduler:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="cage-scheduler", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _loop(self) -> None:
        interval = get_settings().scheduler_interval_seconds
        cycles = 0
        while not self.stop.wait(interval):
            cycles += 1
            try:
                _locked_cycle(purge=cycles % 60 == 0)
            except Exception:  # noqa: BLE001
                log.exception("scheduler cycle crashed")

    def shutdown(self) -> None:
        self.stop.set()
