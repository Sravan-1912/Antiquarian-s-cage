"""Chat alert channels: post security alerts to Slack / Microsoft Teams / Discord / a generic JSON webhook, through a
durable outbox delivered by the scheduler with retries. The webhook URL is AES-256-GCM-encrypted and never returned."""
from __future__ import annotations

import logging
import uuid
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import ChatDelivery, ChatWebhook
from app.security import crypto

log = logging.getLogger("app.chat")
MAX_ATTEMPTS = 6
PLATFORMS = ("slack", "teams", "discord", "generic")
_SEV = ("low", "medium", "high", "critical")
_AAD = "chat-webhook"
_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}


def _rank(sev: str) -> int:
    return _SEV.index(sev) if sev in _SEV else 0


def encrypt_url(url: str) -> str:
    return crypto.encrypt(url, _AAD)


def webhooks(db: Session, org_id: uuid.UUID) -> list[ChatWebhook]:
    return list(db.scalars(select(ChatWebhook).where(ChatWebhook.organization_id == org_id)).all())


def enqueue(db: Session, org_id: uuid.UUID, payload: dict, severity: str = "low") -> int:
    """Queue the alert for every enabled webhook at/above its min severity. Rides the alert transaction (no commit)."""
    n = 0
    for w in webhooks(db, org_id):
        if w.enabled and _rank(severity) >= _rank(w.min_severity):
            db.add(ChatDelivery(id=uuid.uuid4(), webhook_id=w.id, payload=payload))
            n += 1
    return n


def _message(platform: str, p: dict) -> dict:
    sev = str(p.get("severity", "low"))
    emoji = _EMOJI.get(sev, "⚪")
    title = p.get("title", "Security alert")
    desc = p.get("description", "")
    text = f"{emoji} *[{sev.upper()}] {title}*\n{desc}"
    if platform == "discord":
        return {"content": f"{emoji} **[{sev.upper()}] {title}**\n{desc}"[:1900]}
    if platform == "teams":
        return {"text": text}
    if platform == "slack":
        return {"text": f"{emoji} [{sev.upper()}] {title}", "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    return p  # generic: raw alert JSON


def _post(w: ChatWebhook, payload: dict) -> None:
    url = crypto.decrypt(w.url_enc, _AAD)
    httpx.post(url, json=_message(w.platform, payload), timeout=10.0).raise_for_status()


def deliver_outbox(db: Session, batch: int = 20) -> tuple[int, int]:
    """Scheduler hook: deliver due chat posts; exponential backoff; give up after MAX_ATTEMPTS."""
    sent = failed = 0
    due = db.scalars(select(ChatDelivery).where(ChatDelivery.status == "pending",
                                                ChatDelivery.next_attempt_at <= utcnow())
                     .order_by(ChatDelivery.created_at).limit(batch)).all()
    for d in due:
        w = db.get(ChatWebhook, d.webhook_id)
        d.attempts += 1
        if w is None or not w.enabled:
            d.status, d.last_error = "failed", "webhook removed or disabled"
            db.commit(); failed += 1; continue
        try:
            _post(w, d.payload)
            d.status, d.sent_at, d.last_error = "sent", utcnow(), None
            w.last_success_at, w.last_error = utcnow(), None
            sent += 1
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)[:500]
            d.last_error = w.last_error = msg
            if d.attempts >= MAX_ATTEMPTS:
                d.status = "failed"
                log.error("chat delivery permanently failed after %d attempts: %s", d.attempts, msg)
            else:
                d.next_attempt_at = utcnow() + timedelta(minutes=2 ** d.attempts)
            failed += 1
        db.commit()
    return sent, failed


def send_test(db: Session, webhook: ChatWebhook) -> dict:
    try:
        _post(webhook, {"severity": "informational", "title": "Antiquarian's Cage test",
                        "description": "If you can see this, chat alerts are working. 🎉"})
        webhook.last_success_at, webhook.last_error = utcnow(), None
        db.commit()
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        webhook.last_error = str(exc)[:500]
        db.commit()
        return {"ok": False, "error": str(exc)[:300]}
