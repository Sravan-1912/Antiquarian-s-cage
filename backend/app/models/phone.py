from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import utcnow
from app.models.base import Base, UUIDPk


class PhoneAuthenticator(UUIDPk, Base):
    """A paired phone. The private key never leaves the phone's secure hardware (Android Keystore / iOS Secure
    Enclave) and is created so that every signature requires a fresh fingerprint or face match."""

    __tablename__ = "phone_authenticators"
    __table_args__ = (Index("ix_phone_auth_user", "user_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(80))
    platform: Mapped[str] = mapped_column(String(16))  # android | ios
    key_alg: Mapped[str] = mapped_column(String(8))  # ES256 | RS256
    public_key_pem: Mapped[str] = mapped_column(Text)
    # Lets the app *list* pending requests without a biometric prompt. Approving always needs the biometric key.
    poll_secret_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class PhonePairing(UUIDPk, Base):
    __tablename__ = "phone_pairings"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class PhoneLoginRequest(UUIDPk, Base):
    """One approval request. `purpose` = console (web sign-in) or windows (Windows sign-in, Phase 10).
    Requests for unknown/ineligible accounts are stored as decoys (user_id NULL) so responses do not reveal
    whether an account exists; they can never be approved."""

    __tablename__ = "phone_login_requests"
    __table_args__ = (Index("ix_phone_req_user_status", "user_id", "status"),)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    purpose: Mapped[str] = mapped_column(String(16), default="console")
    browser_secret_hash: Mapped[str] = mapped_column(String(64))
    challenge: Mapped[str] = mapped_column(String(64))
    number: Mapped[int]
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|approved|denied|expired|consumed
    reason: Mapped[str | None] = mapped_column(String(64))
    client_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    context: Mapped[dict] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    decided_at: Mapped[datetime | None]
    authenticator_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("phone_authenticators.id", ondelete="SET NULL"))


class WindowsUnlockKey(UUIDPk, Base):
    """Server half of phone-approved Windows sign-in for one (device, Windows account).

    The endpoint keeps the Windows password encrypted under a random 32-byte key K (SYSTEM-only, machine-bound);
    the server keeps K (AES-GCM under DATA_ENCRYPTION_KEY) and releases it to that device only after the linked
    user approves on their phone. Neither side alone can recover the password."""

    __tablename__ = "windows_unlock_keys"
    __table_args__ = (Index("ix_winunlock_device_sid", "device_id", "windows_sid"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    windows_sid: Mapped[str] = mapped_column(String(184))
    windows_user: Mapped[str] = mapped_column(String(256))
    key_enc: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | active | revoked
    request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("phone_login_requests.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    activated_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
