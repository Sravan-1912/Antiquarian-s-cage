from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Permission, Role
from app.security.permissions import PERMISSIONS, ROLES


def sync_rbac(db: Session) -> None:
    """Idempotently reconcile the permission catalogue and built-in roles into the database."""
    existing = {p.key: p for p in db.scalars(select(Permission)).all()}
    for key, desc in PERMISSIONS.items():
        if key in existing:
            existing[key].description = desc
        else:
            existing[key] = Permission(key=key, description=desc)
            db.add(existing[key])
    db.flush()

    roles = {r.key: r for r in db.scalars(select(Role).where(Role.organization_id.is_(None))).all()}
    for key, spec in ROLES.items():
        role = roles.get(key)
        if role is None:
            role = Role(key=key, organization_id=None, is_system=True, name=spec["name"])
            db.add(role)
        role.name = spec["name"]
        role.description = spec["description"]
        role.permissions = [existing[k] for k in sorted(spec["permissions"])]
    db.commit()


def get_role(db: Session, key: str) -> Role | None:
    return db.scalar(select(Role).where(Role.key == key, Role.organization_id.is_(None)))
