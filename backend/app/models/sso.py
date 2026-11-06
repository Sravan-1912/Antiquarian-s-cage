"""Passkeys (WebAuthn), applications (OIDC clients) and the OIDC authorization-code store."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, Timestamps, UUIDPk


class WebAuthnCredential(UUIDPk, Base):
    """A registered passkey. Only the public key is stored — biometrics never leave the user's authenticator."""

    __tablename__ = "webauthn_credentials"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    aaguid: Mapped[str | None] = mapped_column(String(36))
    transports: Mapped[dict] = mapped_column(default=dict)
    backed_up: Mapped[bool] = mapped_column(Boolean, default=False)  # synced passkey vs device-bound
    name: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class WebAuthnChallenge(UUIDPk, Base):
    """Single-use, short-lived challenges (registration: bound to a user; sign-in: bound to nothing until verified)."""

    __tablename__ = "webauthn_challenges"
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    purpose: Mapped[str] = mapped_column(String(16))  # register | authenticate
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    expires_at: Mapped[datetime] = mapped_column(index=True)
    used_at: Mapped[datetime | None]


class Application(UUIDPk, Timestamps, Base):
    __tablename__ = "applications"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    protocol: Mapped[str] = mapped_column(String(8), default="oidc")  # oidc (saml: not implemented)
    client_id: Mapped[str] = mapped_column(String(64), unique=True)
    client_type: Mapped[str] = mapped_column(String(16))  # confidential | public (PKCE only)
    client_secret_hash: Mapped[str | None] = mapped_column(String(64))
    redirect_uris: Mapped[dict] = mapped_column(default=dict)  # {"uris": [...]}
    launch_url: Mapped[str | None] = mapped_column(String(512))
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | disabled
    # Set ONLY when a real authorization-code exchange has completed — never by configuration alone.
    verified_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ApplicationAssignment(UUIDPk, Base):
    __tablename__ = "application_assignments"
    __table_args__ = (Index("ix_app_assign_employee", "employee_id", "revoked_at"),
                      Index("ix_app_assign_app", "application_id", "revoked_at"))
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("applications.id", ondelete="CASCADE"))
    employee_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))
    granted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    granted_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    revoke_reason: Mapped[str | None] = mapped_column(String(255))


class OIDCAuthorizationCode(UUIDPk, Base):
    __tablename__ = "oidc_authorization_codes"
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("applications.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    redirect_uri: Mapped[str] = mapped_column(String(512))
    scope: Mapped[str] = mapped_column(String(255))
    nonce: Mapped[str | None] = mapped_column(String(255))
    code_challenge: Mapped[str] = mapped_column(String(128))
    amr: Mapped[dict] = mapped_column(default=dict)
    auth_time: Mapped[datetime]
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
