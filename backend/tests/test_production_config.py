"""Production configuration guards refuse unsafe settings at startup."""
import base64
import os

import pytest
from pydantic import ValidationError

K1 = base64.b64encode(os.urandom(32)).decode()
K2 = base64.b64encode(os.urandom(32)).decode()
GOOD = dict(
    environment="production", database_url="postgresql+psycopg://cage_app:x@db/cage",
    migration_database_url="postgresql+psycopg://cage_owner:y@db/cage", data_encryption_key=K1, audit_hmac_key=K2,
    cookie_secure=True, redis_url="redis://:p@redis:6379/0", smtp_host="smtp.example.com",
    device_ca_key_passphrase="x" * 32, agent_require_mtls=True, public_base_url="https://cage.example.com",
    allowed_origins=["https://cage.example.com"],
)


def _settings(**over):
    from app.core.config import Settings
    return Settings(_env_file=None, **{**GOOD, **over})


def test_good_production_config_loads():
    assert _settings().environment == "production"


@pytest.mark.parametrize("over, msg", [
    ({"cookie_secure": False}, "COOKIE_SECURE"),
    ({"redis_url": None}, "REDIS_URL"),
    ({"smtp_host": None}, "SMTP_HOST"),
    ({"device_ca_key_passphrase": "short"}, "DEVICE_CA_KEY_PASSPHRASE"),
    ({"agent_require_mtls": False}, "AGENT_REQUIRE_MTLS"),
    ({"public_base_url": "http://cage.example.com"}, "PUBLIC_BASE_URL"),
    ({"allowed_origins": ["http://localhost:5173"]}, "ALLOWED_ORIGINS"),
    ({"database_url": "sqlite:///x.db"}, "SQLite"),
    ({"database_url": "postgresql+psycopg://cage_owner:y@db/cage"}, "schema owner"),
    ({"audit_hmac_key": K1}, "must differ"),
])
def test_unsafe_production_settings_rejected(over, msg):
    with pytest.raises(ValidationError, match=msg):
        _settings(**over)
