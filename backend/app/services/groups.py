"""Dynamic endpoint groups + bulk actions.

A group stores filter *criteria*; membership is resolved live against the devices the caller can see (same org +
admin isolation + support-owner scoping as the endpoints list). Bulk actions resolve the current members and fan the
operation out through the existing per-device services (scripts.deploy, remote.create_action, devices.transition), so
every bulk operation is individually signed/audited exactly as its single-device form would be.
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import Device, DeviceGroup
from app.services import audit, tenancy
from app.services.audit import Actor
from app.services.policies import PolicyError

if TYPE_CHECKING:
    from app.api.deps import AuthContext

_MAX_MEMBERS = 500
_CONNECTIVITY = ("online", "offline", "never")
_STATUS = ("active", "suspended", "revoked", "unenrolled")
_COMPLIANCE = ("compliant", "non_compliant", "unknown")


def normalize_criteria(raw: dict | None) -> dict:
    """Keep only the recognised, non-empty criteria keys (defence in depth; the schema validates shape first)."""
    raw = raw or {}
    out: dict = {}
    if raw.get("q"):
        out["q"] = str(raw["q"])[:100]
    if raw.get("status") in _STATUS:
        out["status"] = raw["status"]
    if raw.get("connectivity") in _CONNECTIVITY:
        out["connectivity"] = raw["connectivity"]
    if raw.get("os"):
        out["os"] = str(raw["os"])[:64]
    if raw.get("compliance_state") in _COMPLIANCE:
        out["compliance_state"] = raw["compliance_state"]
    return out


def _scoped(ctx: "AuthContext"):
    stmt = select(Device).where(Device.organization_id == ctx.user.organization_id)
    stmt = tenancy.restrict(stmt, Device.owner_admin_id, ctx)  # admin isolation (no-op for Super Admin)
    if "devices:read" not in ctx.permissions:  # IT support: only endpoints assigned to them
        stmt = stmt.where(Device.support_owner_id == ctx.user.id)
    return stmt


def _apply(stmt, criteria: dict):
    if criteria.get("q"):
        like = f"%{criteria['q'].lower()}%"
        stmt = stmt.where(or_(func.lower(Device.hostname).like(like), func.lower(Device.display_name).like(like),
                              func.lower(Device.serial_number).like(like), func.lower(Device.model).like(like)))
    if criteria.get("status"):
        stmt = stmt.where(Device.status == criteria["status"])
    if criteria.get("os"):
        stmt = stmt.where(func.lower(Device.os_name).like(f"%{criteria['os'].lower()}%"))
    if criteria.get("compliance_state"):
        stmt = stmt.where(Device.compliance_state == criteria["compliance_state"])
    if criteria.get("connectivity"):
        cutoff = utcnow() - timedelta(seconds=get_settings().offline_threshold_seconds)
        stmt = stmt.where({"online": Device.last_heartbeat_at >= cutoff,
                           "offline": Device.last_heartbeat_at < cutoff,
                           "never": Device.last_heartbeat_at.is_(None)}[criteria["connectivity"]])
    return stmt


# --------------------------------------------------------------------------------------------- resolution
def members(db: Session, ctx: "AuthContext", criteria: dict, *, limit: int | None = None) -> list[Device]:
    stmt = _apply(_scoped(ctx), normalize_criteria(criteria)).order_by(Device.hostname, Device.id)
    if limit is not None:
        stmt = stmt.limit(limit)
    return list(db.scalars(stmt).all())


def member_count(db: Session, ctx: "AuthContext", criteria: dict) -> int:
    stmt = _apply(_scoped(ctx), normalize_criteria(criteria))
    return db.scalar(select(func.count()).select_from(stmt.subquery())) or 0


# --------------------------------------------------------------------------------------------- CRUD
def create_group(db: Session, org_id: uuid.UUID, actor: Actor, *, name: str, description: str, criteria: dict,
                 owner_admin_id: uuid.UUID | None) -> DeviceGroup:
    if db.scalar(select(DeviceGroup.id).where(DeviceGroup.organization_id == org_id, DeviceGroup.name == name)):
        raise PolicyError(f"A group named {name!r} already exists", 409)
    g = DeviceGroup(organization_id=org_id, owner_admin_id=owner_admin_id, name=name, description=description,
                    criteria=normalize_criteria(criteria), created_by=actor.user_id)
    db.add(g)
    db.flush()
    audit.record(db, org_id, actor, "device_group.created", target_type="device_group", target_id=g.id,
                 target_label=name, metadata={"criteria": g.criteria})
    db.commit()
    return g


def update_group(db: Session, g: DeviceGroup, actor: Actor, *, name: str, description: str, criteria: dict) -> DeviceGroup:
    if name != g.name and db.scalar(select(DeviceGroup.id).where(DeviceGroup.organization_id == g.organization_id,
                                                                 DeviceGroup.name == name)):
        raise PolicyError(f"A group named {name!r} already exists", 409)
    g.name, g.description, g.criteria = name, description, normalize_criteria(criteria)
    audit.record(db, g.organization_id, actor, "device_group.updated", target_type="device_group", target_id=g.id,
                 target_label=name, metadata={"criteria": g.criteria})
    db.commit()
    return g


def delete_group(db: Session, g: DeviceGroup, actor: Actor) -> None:
    audit.record(db, g.organization_id, actor, "device_group.deleted", target_type="device_group", target_id=g.id,
                 target_label=g.name)
    db.delete(g)
    db.commit()


# --------------------------------------------------------------------------------------------- bulk fan-out
def resolve_targets(db: Session, ctx: "AuthContext", g: DeviceGroup) -> list[Device]:
    targets = members(db, ctx, g.criteria)
    if not targets:
        raise PolicyError("This group currently has no members", 409)
    if len(targets) > _MAX_MEMBERS:
        raise PolicyError(f"Group has {len(targets)} members; bulk actions are capped at {_MAX_MEMBERS}", 422)
    return targets
