"""Subscriptions and device-slot quotas.

Any admin can view their own plan and usage. Only a Super Admin (org:settings) can assign plans to admins or set the
organisation-wide default plan.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, current_context, require_permission
from app.core.database import get_db
from app.models import Subscription, User
from app.services import audit, subscriptions, tenancy

router = APIRouter(tags=["subscription"])
MANAGE = require_permission("org:settings")


class SetPlan(BaseModel):
    plan_key: str = Field(min_length=1, max_length=32)
    status: str = Field(default="active", pattern="^(active|past_due|cancelled)$")
    # Optional slot override. Omit to use the plan default; null means unlimited.
    max_device_slots: int | None = Field(default=-1, ge=-1, le=1_000_000)


def _apply(db: Session, ctx: AuthContext, owner_admin_id: uuid.UUID | None, body: SetPlan, label: str):
    override = ... if body.max_device_slots == -1 else body.max_device_slots
    try:
        sub = subscriptions.set_subscription(db, ctx.user.organization_id, owner_admin_id, body.plan_key,
                                             max_device_slots_override=override, status=body.status)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    audit.record(db, ctx.user.organization_id, ctx.actor, "subscription.updated",
                 target_type="subscription", target_id=sub.id, target_label=label,
                 metadata={"plan": body.plan_key, "status": body.status, "max_device_slots": sub.max_device_slots})
    db.commit()
    return subscriptions.usage(db, ctx.user.organization_id, owner_admin_id) | {"plan_status": sub.status}


@router.get("/subscription/plans")
def plans(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    return subscriptions.plan_catalogue(db)


@router.get("/subscription")
def my_subscription(ctx: AuthContext = Depends(current_context), db: Session = Depends(get_db)):
    """The caller tenant's effective plan and device-slot usage (an admin sees their own; a Super Admin sees the
    organisation-level default tenant)."""
    return subscriptions.usage(db, ctx.user.organization_id, tenancy.owner_for(ctx))


@router.get("/subscriptions")
def all_subscriptions(ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    """Super Admin: every admin's plan and usage, plus the organisation default."""
    org = ctx.user.organization_id
    out = [{"owner_admin_id": None, "admin_email": None, "scope": "organization",
            **subscriptions.usage(db, org, None)}]
    admins = db.scalars(select(User).where(User.organization_id == org, User.owner_admin_id.is_(None))).all()
    for u in admins:
        if any(r.key == "admin" for r in u.roles):
            out.append({"owner_admin_id": str(u.id), "admin_email": u.email, "scope": "admin",
                        **subscriptions.usage(db, org, u.id)})
    return out


@router.put("/organization/subscription")
def set_org_default(body: SetPlan, ctx: AuthContext = Depends(MANAGE), db: Session = Depends(get_db)):
    return _apply(db, ctx, None, body, "organization default")


@router.put("/admins/{admin_id}/subscription")
def set_admin_subscription(admin_id: uuid.UUID, body: SetPlan, ctx: AuthContext = Depends(MANAGE),
                           db: Session = Depends(get_db)):
    admin = db.get(User, admin_id)
    if admin is None or admin.organization_id != ctx.user.organization_id or not any(r.key == "admin" for r in admin.roles):
        raise HTTPException(404, "Administrator not found")
    return _apply(db, ctx, admin.id, body, admin.email)
