"""Subscription tiers and device-slot quotas.

A plan caps how many endpoints a tenant may have enrolled at once (`max_device_slots`, None = unlimited). Plans are
defined here and synchronised into `subscription_plans` at startup. A `subscriptions` row assigns a plan to a tenant:

  * owner_admin_id set   -> that admin's plan
  * owner_admin_id NULL  -> the organisation-wide default plan (applies to admins without their own subscription)

Resolution at enrolment: the admin's own subscription, then the organisation default, then the built-in DEFAULT_PLAN.
Enrollments owned by the Super Admin directly (owner_admin_id NULL on the device, i.e. no admin tenant) are not
capped. A "used slot" is an enrolled endpoint in status active or suspended; revoked/unenrolled devices free a slot.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.models import Device, Subscription, SubscriptionPlan

# key -> (name, max_device_slots | None for unlimited, monthly price in cents)
PLANS: dict[str, dict] = {
    "trial": {"name": "Trial", "max_device_slots": 5, "monthly_price_cents": 0},
    "starter": {"name": "Starter", "max_device_slots": 25, "monthly_price_cents": 4900},
    "business": {"name": "Business", "max_device_slots": 100, "monthly_price_cents": 14900},
    "enterprise": {"name": "Enterprise", "max_device_slots": 1000, "monthly_price_cents": 49900},
    "unlimited": {"name": "Unlimited", "max_device_slots": None, "monthly_price_cents": 99900},
}
DEFAULT_PLAN = "trial"
COUNTED_STATUSES = ("active", "suspended")


class QuotaExceeded(Exception):
    def __init__(self, used: int, limit: int):
        self.used, self.limit = used, limit
        super().__init__(f"device quota reached ({used}/{limit})")


def sync_plans(db: Session) -> None:
    """Upsert the plan catalogue from PLANS. Existing custom overrides on `subscriptions` are untouched."""
    existing = {p.key: p for p in db.scalars(select(SubscriptionPlan))}
    for key, spec in PLANS.items():
        row = existing.get(key)
        if row is None:
            db.add(SubscriptionPlan(key=key, name=spec["name"], max_device_slots=spec["max_device_slots"],
                                    monthly_price_cents=spec["monthly_price_cents"], is_active=True))
        else:
            row.name, row.max_device_slots = spec["name"], spec["max_device_slots"]
            row.monthly_price_cents, row.is_active = spec["monthly_price_cents"], True
    for key, row in existing.items():
        if key not in PLANS:
            row.is_active = False  # retired plan: keep the row (subscriptions may reference it) but hide it


def _subscription(db: Session, org_id: uuid.UUID, owner_admin_id: uuid.UUID | None) -> Subscription | None:
    return db.scalar(select(Subscription).where(
        Subscription.organization_id == org_id, Subscription.owner_admin_id == owner_admin_id,
        Subscription.status == "active"))


@dataclass
class Resolved:
    plan_key: str
    limit: int | None  # None = unlimited
    source: str  # "admin" | "organization" | "default"


def resolve(db: Session, org_id: uuid.UUID, owner_admin_id: uuid.UUID | None) -> Resolved:
    """The effective plan and slot limit for a tenant (an admin, or the org default when owner_admin_id is None)."""
    if owner_admin_id is not None:
        sub = _subscription(db, org_id, owner_admin_id)
        if sub is not None:
            return Resolved(sub.plan_key, sub.max_device_slots, "admin")
    org_sub = _subscription(db, org_id, None)
    if org_sub is not None:
        return Resolved(org_sub.plan_key, org_sub.max_device_slots, "organization")
    if owner_admin_id is None:
        # Org-level bucket (Super Admin's own enrollments): uncapped unless an explicit org-default plan exists.
        return Resolved("unlimited", None, "default")
    return Resolved(DEFAULT_PLAN, PLANS[DEFAULT_PLAN]["max_device_slots"], "default")


def used_slots(db: Session, org_id: uuid.UUID, owner_admin_id: uuid.UUID | None) -> int:
    return db.scalar(select(func.count()).select_from(Device).where(
        Device.organization_id == org_id, Device.owner_admin_id == owner_admin_id,
        Device.status.in_(COUNTED_STATUSES))) or 0


def usage(db: Session, org_id: uuid.UUID, owner_admin_id: uuid.UUID | None) -> dict:
    r = resolve(db, org_id, owner_admin_id)
    used = used_slots(db, org_id, owner_admin_id)
    return {"plan": r.plan_key, "plan_source": r.source, "used": used, "limit": r.limit,
            "available": None if r.limit is None else max(0, r.limit - used),
            "at_limit": r.limit is not None and used >= r.limit}


def check_can_enroll(db: Session, org_id: uuid.UUID, owner_admin_id: uuid.UUID | None) -> None:
    """Raise QuotaExceeded if this tenant has no free device slot. Org-level (owner_admin_id None) enrollments by the
    Super Admin are not capped unless an explicit organisation-default subscription sets a limit."""
    r = resolve(db, org_id, owner_admin_id)
    if r.limit is None:
        return
    used = used_slots(db, org_id, owner_admin_id)
    if used >= r.limit:
        raise QuotaExceeded(used, r.limit)


def set_subscription(db: Session, org_id: uuid.UUID, owner_admin_id: uuid.UUID | None, plan_key: str,
                     max_device_slots_override: int | None = ..., status: str = "active") -> Subscription:
    """Create or update a tenant's subscription. Super-admin action. Default slot cap comes from the plan unless an
    explicit override is given (use None override for unlimited)."""
    if plan_key not in PLANS:
        raise ValueError(f"unknown plan {plan_key!r}")
    cap = PLANS[plan_key]["max_device_slots"] if max_device_slots_override is ... else max_device_slots_override
    sub = db.scalar(select(Subscription).where(Subscription.organization_id == org_id,
                                               Subscription.owner_admin_id == owner_admin_id))
    if sub is None:
        sub = Subscription(organization_id=org_id, owner_admin_id=owner_admin_id, plan_key=plan_key,
                           status=status, max_device_slots=cap, created_at=utcnow())
        db.add(sub)
    else:
        sub.plan_key, sub.status, sub.max_device_slots = plan_key, status, cap
    db.flush()
    return sub


def plan_catalogue(db: Session) -> list[dict]:
    return [{"key": p.key, "name": p.name, "max_device_slots": p.max_device_slots,
             "monthly_price_cents": p.monthly_price_cents}
            for p in db.scalars(select(SubscriptionPlan).where(SubscriptionPlan.is_active.is_(True))
                                .order_by(SubscriptionPlan.monthly_price_cents))]
