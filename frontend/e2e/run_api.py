"""Start an isolated API for the Playwright suite: fresh SQLite database, fresh keys, separate mail outbox.

Never touches backend/.env or the development database: it runs from its own working directory with every
setting given explicitly. Usage (Playwright starts it): python e2e/run_api.py <port> <state-dir>
"""
from __future__ import annotations

import base64
import os
import shutil
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "backend"


def main(port: int, state: Path) -> None:
    shutil.rmtree(state, ignore_errors=True)
    state.mkdir(parents=True)
    os.chdir(state)  # no .env here, so nothing from the developer's environment is picked up
    url = f"sqlite:///{(state / 'e2e.db').as_posix()}"
    os.environ.update({
        "ENVIRONMENT": "development",
        "DATABASE_URL": url,
        "MIGRATION_DATABASE_URL": url,
        "DATA_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        "AUDIT_HMAC_KEY": base64.b64encode(os.urandom(32)).decode(),
        "DEV_OUTBOX_DIR": str(state / "outbox"),
        "DEVICE_CA_DIR": str(state / "pki"),
        "AUDIT_ANCHOR_DIR": str(state / "anchors"),
        "SCHEDULER_ENABLED": "false",
        "PUBLIC_BASE_URL": os.environ.get("E2E_BASE_URL", "http://localhost:5174"),
        "ALLOWED_ORIGINS": '["%s"]' % os.environ.get("E2E_BASE_URL", "http://localhost:5174"),
    })
    sys.path.insert(0, str(BACKEND))
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    command.upgrade(cfg, "head")

    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main(int(sys.argv[1]), Path(sys.argv[2]).resolve())
