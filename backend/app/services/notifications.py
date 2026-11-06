"""In-app and email notifications with per-user preferences and a durable email outbox."""
from __future__ import annotations

import logging
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import EmailOutbox, Notification, NotificationPreference, User

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CATEGORIES: dict[str, str] = {
    "security_alerts": "Security alerts",
    "authentication": "Suspicious sign-in activity and account lockouts",
    "endpoint_enrollment": "New endpoint enrollments",
    "compliance": "Non-compliant endpoints",
    "policy_deployments": "Failed policy deployments",
    "agent_communication": "Agents that stopped reporting",
    "employee_offboarding": "Employee offboarding",
    "remote_sessions": "Remote assistance sessions",
    "general": "Other notifications",
}
# Email on by default only where an operator should know without opening the console.
EMAIL_DEFAULT = {"security_alerts", "authentication", "agent_communication"}

KIND_CATEGORY = {
    "security.lockout": "authentication", "security.sessions_revoked": "authentication",
    "employee.offboarded": "employee_offboarding", "device.enrolled": "endpoint_enrollment",
    "device.non_compliant": "compliance", "policy.deployment_failed": "policy_deployments",
    "remote.session_requested": "remote_sessions", "remote.cleanup_incomplete": "remote_sessions",
}


def category_for(kind: str) -> str:
    if kind.startswith("alert.agent_silent"):
        return "agent_communication"
    if kind.startswith("alert."):
        return "security_alerts"
    return KIND_CATEGORY.get(kind, "general")


def preference(db: Session, user_id: uuid.UUID, category: str) -> NotificationPreference:
    p = db.scalar(select(NotificationPreference).where(NotificationPreference.user_id == user_id,
                                                       NotificationPreference.category == category))
    return p or NotificationPreference(user_id=user_id, category=category, in_app=True, min_severity="informational",
                                       email=category in EMAIL_DEFAULT, email_min_severity="high")


def notify_users(db: Session, org_id: uuid.UUID, users: list[User], *, kind: str, title: str, body: str = "",
                 severity: str = "info", link: str | None = None, category: str | None = None) -> None:
    from app.core.config import get_settings

    category = category or category_for(kind)
    sev = SEVERITY_ORDER.get(severity, 0)
    base = get_settings().public_base_url.rstrip("/")
    for u in users:
        pref = preference(db, u.id, category)
        if pref.in_app and sev >= SEVERITY_ORDER.get(pref.min_severity, 0):
            db.add(Notification(organization_id=org_id, user_id=u.id, kind=kind, category=category, title=title,
                                body=body, severity=severity, link=link))
        if pref.email and sev >= SEVERITY_ORDER.get(pref.email_min_severity, 3) and u.status == "active"                 and u.email_verified_at:
            db.add(EmailOutbox(to_address=u.email, subject=f"[{severity.upper()}] {title}"[:255],
                               body=f"{body}\n\n{base + link if link else base}\n\n"
                                    f"You receive this because email is enabled for “{CATEGORIES[category]}”. "
                                    f"Change it under Security settings → Notifications."))


def users_with_permission(db: Session, org_id: uuid.UUID, permission: str) -> list[User]:
    users = db.scalars(select(User).where(User.organization_id == org_id, User.status == "active")).all()
    return [u for u in users if permission in u.permission_keys]


MAX_ATTEMPTS = 6


def deliver_outbox(db: Session, batch: int = 25) -> tuple[int, int]:
    """Send due emails; exponential backoff (2, 4, 8… minutes); give up after MAX_ATTEMPTS and keep the error."""
    from app.services.email import EmailDeliveryError, send_email

    sent = failed = 0
    due = db.scalars(select(EmailOutbox).where(EmailOutbox.status == "pending", EmailOutbox.next_attempt_at <= utcnow())
                     .order_by(EmailOutbox.created_at).limit(batch)).all()
    for m in due:
        m.attempts += 1
        try:
            send_email(m.to_address, m.subject, m.body)
            m.status, m.sent_at, m.last_error = "sent", utcnow(), None
            sent += 1
        except EmailDeliveryError as exc:
            m.last_error = str(exc)[:500]
            if m.attempts >= MAX_ATTEMPTS:
                m.status = "failed"
                log.error("email to %s permanently failed after %d attempts", m.to_address, m.attempts)
            else:
                m.next_attempt_at = utcnow() + timedelta(minutes=2 ** m.attempts)
            failed += 1
        db.commit()
    return sent, failed
