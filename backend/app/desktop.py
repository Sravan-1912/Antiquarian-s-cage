"""Desktop entry point: run the whole backend as a local app for the Electron shell.

Responsibilities (all before the FastAPI app is imported, so settings pick them up):
  * choose a per-user data directory (%APPDATA%\\AntiquariansCage on Windows);
  * generate and persist the app secrets there on first run (never shipped in the build);
  * point the app at a local SQLite database in that directory;
  * run Alembic migrations to head;
  * bind a free loopback port, print it (so Electron can open the window), and serve the API + the console SPA there.

Run frozen (PyInstaller) or from source: ``python -m app.desktop``.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import sys
from pathlib import Path


def _resource(*parts: str) -> Path:
    """A bundled resource: next to the PyInstaller bundle when frozen, else in the backend source tree."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    return base.joinpath(*parts)


def _data_dir() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = root / "AntiquariansCage"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_or_create_secrets(data_dir: Path) -> dict[str, str]:
    """Secrets live only on this machine, generated on first run. Stored 0600 in the data directory."""
    f = data_dir / "secrets.json"
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    sec = {
        "DATA_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        "AUDIT_HMAC_KEY": base64.b64encode(os.urandom(32)).decode(),
        "DEVICE_CA_KEY_PASSPHRASE": secrets.token_urlsafe(32),
    }
    f.write_text(json.dumps(sec, indent=2), encoding="utf-8")
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    return sec


def _free_loopback_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run_migrations() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(_resource("alembic.ini")))
    cfg.set_main_option("script_location", str(_resource("migrations")))
    command.upgrade(cfg, "head")


def main() -> int:
    data_dir = _data_dir()
    port = int(os.environ.get("CAGE_PORT") or _free_loopback_port())
    origin = f"http://127.0.0.1:{port}"
    # Frozen: the built frontend is bundled next to the exe as ./spa. From source: the repo's frontend/dist.
    spa = _resource("spa") if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2] / "frontend" / "dist"

    os.environ.setdefault("CAGE_ENV_FILE", "")  # ignore any stray .env next to the exe
    os.environ.setdefault("ENVIRONMENT", "desktop")
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(data_dir / 'cage.db').as_posix()}")
    os.environ.setdefault("MIGRATION_DATABASE_URL", os.environ["DATABASE_URL"])  # migrate the same DB the app opens
    os.environ.setdefault("DEVICE_CA_DIR", str(data_dir / "pki"))
    os.environ.setdefault("AUDIT_ANCHOR_DIR", str(data_dir / "anchors"))
    os.environ.setdefault("DEV_OUTBOX_DIR", str(data_dir / "outbox"))
    os.environ.setdefault("PUBLIC_BASE_URL", origin)
    os.environ.setdefault("ALLOWED_ORIGINS", json.dumps([origin]))
    os.environ.setdefault("COOKIE_SECURE", "false")
    os.environ.setdefault("AGENT_REQUIRE_MTLS", "false")
    if spa.is_dir():
        os.environ.setdefault("SPA_DIR", str(spa))
    for k, v in _load_or_create_secrets(data_dir).items():
        os.environ.setdefault(k, v)

    _run_migrations()

    import uvicorn

    from app.core.config import get_settings
    get_settings.cache_clear()
    # Import the app object directly (not uvicorn's "app.main:app" string): this makes PyInstaller
    # follow the whole FastAPI graph into the bundle, and avoids re-importing from a stray on-disk copy.
    from app.main import app as fastapi_app
    print(f"CAGE_READY port={port} url={origin}", flush=True)  # Electron reads this line
    uvicorn.run(fastapi_app, host="127.0.0.1", port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
