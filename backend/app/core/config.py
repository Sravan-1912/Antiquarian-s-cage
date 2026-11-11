"""Environment-based configuration. No secrets have defaults; startup fails if they are missing."""
from __future__ import annotations

import base64
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "Antiquarian's Cage"
    public_base_url: str = "http://localhost:5173"
    # Address phones use to reach the API (pairing QR). Defaults to PUBLIC_BASE_URL; in development set it to this
    # machine's LAN address (e.g. http://192.168.1.20:8000) because a phone cannot reach "localhost".
    phone_api_base_url: str | None = None
    expose_api_docs: bool = False

    database_url: str
    # Optional: schema-owner connection used only by Alembic. The API itself runs as a least-privilege role.
    migration_database_url: str | None = None
    redis_url: str | None = None

    # Secrets (base64-encoded 32 random bytes) — generate with infrastructure/scripts/generate_secrets.py
    data_encryption_key: str = Field(min_length=40)
    audit_hmac_key: str = Field(min_length=40)

    allowed_origins: list[str] = ["http://localhost:5173"]

    session_idle_timeout_minutes: int = 30
    session_absolute_timeout_hours: int = 12
    cookie_secure: bool = True
    trust_proxy_headers: bool = False

    max_failed_logins: int = 5
    lockout_minutes: int = 15
    login_rate_limit_per_minute: int = 10
    password_min_length: int = 12

    email_token_ttl_hours: int = 24
    reset_token_ttl_minutes: int = 30
    invite_token_ttl_hours: int = 72

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "no-reply@antiquarians-cage.local"
    smtp_starttls: bool = True
    dev_outbox_dir: str = "var/outbox"

    heartbeat_interval_seconds: int = 60
    offline_threshold_seconds: int = 180
    inventory_interval_seconds: int = 3600
    enrollment_token_max_minutes: int = 1440
    device_cert_days: int = 90
    device_cert_renew_before_days: int = 30
    device_ca_dir: str = "var/pki"
    device_ca_key_passphrase: str = Field(default="", min_length=0)
    agent_signature_window_seconds: int = 300
    agent_max_body_bytes: int = 262_144
    # When true, agent requests must arrive through the mTLS proxy, which forwards the verified client-cert
    # certificate in X-Client-Cert; its SHA-256 fingerprint must match the device's active certificate.
    agent_require_mtls: bool = False
    heartbeat_retention_days: int = 30
    command_job_ttl_hours: int = 72
    agent_silence_alert_minutes: int = 15
    # In-process scheduler (alert sweep, email outbox, job expiry, retention). Guarded by a PostgreSQL advisory lock
    # so only one API instance runs it at a time. Disable when running Celery beat instead.
    scheduler_enabled: bool = True
    # Audit anchors: signed chain-head snapshots appended to <dir>/<org>.jsonl. In production point this at storage the
    # API cannot rewrite (WORM bucket mount, remote syslog collector, separate host) and back it up separately.
    audit_anchor_dir: str = "var/audit-anchors"
    audit_anchor_interval_minutes: int = 60
    scheduler_interval_seconds: int = 60

    @field_validator("data_encryption_key", "audit_hmac_key")
    @classmethod
    def _valid_key(cls, v: str) -> str:
        raw = base64.b64decode(v, validate=True)
        if len(raw) != 32:
            raise ValueError("key must decode to exactly 32 bytes")
        return v

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        if self.environment == "production":
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE must be true in production")
            if not self.redis_url:
                raise ValueError("REDIS_URL is required in production (rate limiting)")
            if not self.smtp_host:
                raise ValueError("SMTP_HOST is required in production")
            if self.data_encryption_key == self.audit_hmac_key:
                raise ValueError("DATA_ENCRYPTION_KEY and AUDIT_HMAC_KEY must differ")
            if len(self.device_ca_key_passphrase) < 24:
                raise ValueError("DEVICE_CA_KEY_PASSPHRASE (>=24 chars) is required in production")
            if not self.agent_require_mtls:
                raise ValueError("AGENT_REQUIRE_MTLS must be true in production")
            if not self.public_base_url.startswith("https://"):
                raise ValueError("PUBLIC_BASE_URL must be https:// in production")
            bad = [o for o in self.allowed_origins if not o.startswith("https://") or "localhost" in o or "127.0.0.1" in o]
            if bad or not self.allowed_origins:
                raise ValueError(f"ALLOWED_ORIGINS must be https and not localhost in production (got {bad or 'none'})")
            if self.database_url.startswith("sqlite"):
                raise ValueError("SQLite is not supported in production; use PostgreSQL")
            from urllib.parse import urlparse
            api_user = urlparse(self.database_url).username
            if self.migration_database_url and api_user and api_user == urlparse(self.migration_database_url).username:
                raise ValueError("the API must not connect as the schema owner; use the least-privilege role in DATABASE_URL")
        if not self.device_ca_key_passphrase:
            # Development/test only: derive a passphrase so the auto-created dev CA key is never stored in clear.
            import hashlib
            self.device_ca_key_passphrase = hashlib.sha256(b"dev-ca|" + self.data_key_bytes).hexdigest()
        return self

    @property
    def data_key_bytes(self) -> bytes:
        return base64.b64decode(self.data_encryption_key)

    @property
    def audit_key_bytes(self) -> bytes:
        return base64.b64decode(self.audit_hmac_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
