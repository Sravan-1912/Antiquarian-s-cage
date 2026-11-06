"""Celery wiring for production (requires Redis). Set SCHEDULER_ENABLED=false on API instances and run:

    celery -A app.workers.celery_app worker --beat --loglevel=info

NOT verified in this environment (Redis is not installed); the in-process scheduler runs the same cycle."""
from __future__ import annotations

from celery import Celery

from app.core.config import get_settings

app = Celery("antiquarians_cage", broker=get_settings().redis_url or "redis://localhost:6379/0")
app.conf.beat_schedule = {
    "maintenance-cycle": {"task": "cage.maintenance", "schedule": 60.0},
    "retention": {"task": "cage.retention", "schedule": 3600.0},
}
app.conf.task_acks_late = True


@app.task(name="cage.maintenance")
def maintenance() -> None:
    from app.workers.tasks import _locked_cycle
    _locked_cycle(purge=False)


@app.task(name="cage.retention")
def retention() -> None:
    from app.workers.tasks import _locked_cycle
    _locked_cycle(purge=True)
