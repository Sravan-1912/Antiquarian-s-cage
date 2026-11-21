"""Admin isolation (row-level multi-tenancy inside one organisation).

Hierarchy:
  * Super Admin  - holds the `tenant:global` permission; sees every resource in the organisation.
  * Admin        - sees only resources whose `owner_admin_id` equals the admin's own id.
  * Admin's staff- analysts / IT-support accounts an admin creates carry `owner_admin_id = that admin`, so they share
                   exactly that admin's view and nothing of any other admin.

`scope_admin_id(ctx)` returns the admin id a request is confined to, or None for a global (super-admin) view.
`owner_for(ctx)` returns the id to stamp on resources the request creates (so an admin's staff create resources that
stay inside that admin's tenant). Every list/get query over an owned table must pass through `restrict`.
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.api.deps import AuthContext

GLOBAL_PERMISSION = "tenant:global"
ADMIN_ROLE = "admin"


def is_global(ctx: "AuthContext") -> bool:
    return GLOBAL_PERMISSION in ctx.permissions


def scope_admin_id(ctx: "AuthContext") -> uuid.UUID | None:
    """The admin tenant this request is confined to, or None for an unrestricted view.

    Unrestricted (None) applies to Super Admins and to org-level staff the Super Admin created directly (an analyst or
    IT-support account with no owner_admin_id) — they are the organisation's security team. A tenant-scoped id applies
    to an Admin (confined to their own id) and to any account an Admin created (confined to that admin via
    owner_admin_id).
    """
    if is_global(ctx):
        return None
    if ctx.user.owner_admin_id is not None:  # staff created by a specific admin
        return ctx.user.owner_admin_id
    if any(r.key == ADMIN_ROLE for r in ctx.user.roles):  # a tenant-root admin
        return ctx.user.id
    return None  # org-level staff directly under the Super Admin keep the organisation-wide view


def owner_for(ctx: "AuthContext") -> uuid.UUID | None:
    """The owner_admin_id to stamp on a resource created by this request.

    Super Admin creates organisation-level resources (owner_admin_id = NULL) that only global views see until assigned
    to an admin. An admin (or their staff) creates resources owned by that admin's tenant.
    """
    return scope_admin_id(ctx)


def restrict(stmt, owner_column, ctx: "AuthContext"):
    """Narrow a SELECT to the caller's tenant. A no-op for a global (super-admin) view."""
    scope = scope_admin_id(ctx)
    if scope is not None:
        stmt = stmt.where(owner_column == scope)
    return stmt


def can_see(ctx: "AuthContext", owner_admin_id: uuid.UUID | None) -> bool:
    """Whether a single resource with this owner is visible to the caller."""
    scope = scope_admin_id(ctx)
    return scope is None or owner_admin_id == scope
