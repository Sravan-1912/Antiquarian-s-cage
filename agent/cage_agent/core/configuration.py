"""Agent configuration and on-disk state.

Default data directory: %ProgramData%\\AntiquariansCage (service) — override with --data-dir for development.
Files: config.json (server URL, device id, intervals), device.key.dpapi, device.crt, ca.crt, logs\\agent.log
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AntiquariansCage"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ConfigError(Exception):
    pass


@dataclass
class AgentConfig:
    server_url: str
    device_id: str | None = None
    heartbeat_interval_seconds: int = 60
    inventory_interval_seconds: int = 3600
    key_scope: str = "machine"  # machine | user (see security/secure_storage.py)
    allow_insecure_localhost: bool = False
    ca_bundle: str | None = None  # TLS trust anchor for the server (None = Windows/OS trust store via certifi)
    extra: dict = field(default_factory=dict)

    def validate(self) -> None:
        u = urlparse(self.server_url)
        if u.scheme == "https":
            return
        if u.scheme == "http" and self.allow_insecure_localhost and u.hostname in LOCAL_HOSTS:
            return
        raise ConfigError("Server URL must use https:// (plain http is only permitted for localhost development "
                          "with --allow-insecure-localhost)")


class AgentPaths:
    def __init__(self, data_dir: Path):
        self.root = data_dir
        self.config = data_dir / "config.json"
        self.key = data_dir / "device.key.dpapi"
        self.cert = data_dir / "device.crt"
        self.ca = data_dir / "device-ca.crt"
        self.logs = data_dir / "logs"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(exist_ok=True)


def load(paths: AgentPaths) -> AgentConfig:
    if not paths.config.exists():
        raise ConfigError(f"Agent is not enrolled (no {paths.config}). Run: cage-agent enroll ...")
    data = json.loads(paths.config.read_text(encoding="utf-8"))
    cfg = AgentConfig(**data)
    cfg.validate()
    return cfg


def save(paths: AgentPaths, cfg: AgentConfig) -> None:
    tmp = paths.config.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    tmp.replace(paths.config)
