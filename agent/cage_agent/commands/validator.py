"""Validation of signed command envelopes. Used by BOTH the agent (before forwarding) and the privileged broker
(before executing) — the broker never trusts the agent's decision.

An envelope is accepted only if ALL hold:
  * exact field set, version 1, command on the local allowlist, parameters valid for that command;
  * device_id equals this device; key_id equals the pinned key; Ed25519 signature valid over the canonical form;
  * issued_at not in the future (beyond skew) and expires_at in the future;
  * nonce never seen before (persisted until expiry);
  * for policy.apply: version not older than the last applied version of that policy.
"""
from __future__ import annotations

import base64
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cage_agent.commands.schemas import ALLOWED_COMMANDS, validate_command_params
from cage_agent.policies import CATEGORIES, validate_policy_config
FIELDS = {"v", "job_id", "device_id", "command", "parameters", "issued_at", "expires_at", "nonce", "key_id", "signature"}
CLOCK_SKEW = timedelta(minutes=5)


class Rejected(Exception):
    pass


def canonical(envelope: dict) -> bytes:
    """Must match backend/app/security/command_signing.py::canonical."""
    body = {k: v for k, v in envelope.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass
class PinnedKey:
    key_id: str
    public_key_b64: str


class ReplayStore:
    """Persisted set of seen nonces with expiry, plus last applied policy versions."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._data = {"nonces": {}, "versions": {}}
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                # A corrupt store must not silently disable replay protection: start empty but keep a copy.
                path.replace(path.with_suffix(".corrupt"))

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data), encoding="utf-8")
        tmp.replace(self.path)

    def seen(self, nonce: str) -> bool:
        return nonce in self._data["nonces"]

    def remember(self, nonce: str, expires_at: datetime) -> None:
        with self._lock:
            now = datetime.now(timezone.utc)
            self._data["nonces"] = {n: e for n, e in self._data["nonces"].items()
                                    if datetime.fromisoformat(e) > now - CLOCK_SKEW}
            self._data["nonces"][nonce] = expires_at.isoformat()
            self._save()

    def last_version(self, policy_id: str) -> int:
        return int(self._data["versions"].get(policy_id, 0))

    def set_version(self, policy_id: str, version: int) -> None:
        with self._lock:
            self._data["versions"][policy_id] = version
            self._save()


def verify_and_parse(envelope: dict, *, device_id: str, key: PinnedKey, replay: ReplayStore,
                     now: datetime | None = None, consume: bool = True) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != FIELDS:
        raise Rejected("malformed envelope (unexpected field set)")
    if envelope["v"] != 1:
        raise Rejected("unsupported envelope version")
    if envelope["command"] not in ALLOWED_COMMANDS:
        raise Rejected(f"command not on local allowlist: {envelope['command']!r}")
    if envelope["device_id"] != device_id:
        raise Rejected("envelope addressed to a different device")
    if envelope["key_id"] != key.key_id:
        raise Rejected("signed with an unknown key")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key_b64)).verify(
            base64.b64decode(envelope["signature"]), canonical(envelope))
    except (InvalidSignature, ValueError):
        raise Rejected("invalid signature") from None
    now = now or datetime.now(timezone.utc)
    try:
        issued = datetime.fromisoformat(envelope["issued_at"])
        expires = datetime.fromisoformat(envelope["expires_at"])
    except (TypeError, ValueError):
        raise Rejected("invalid timestamps") from None
    if issued > now + CLOCK_SKEW:
        raise Rejected("issued in the future (clock skew?)")
    if expires <= now:
        raise Rejected("command expired")
    nonce = envelope["nonce"]
    if not isinstance(nonce, str) or not (16 <= len(nonce) <= 64) or replay.seen(nonce):
        raise Rejected("replayed or invalid nonce")

    p = envelope["parameters"]
    if not envelope["command"].startswith("policy."):
        try:
            validate_command_params(envelope["command"], p)
        except (ValueError, TypeError) as exc:
            raise Rejected(f"parameters rejected locally: {exc}") from None
        if consume:
            replay.remember(nonce, expires)
        return envelope
    if not isinstance(p, dict) or p.get("category") not in CATEGORIES:
        raise Rejected("unknown policy category")
    if not isinstance(p.get("version"), int) or not isinstance(p.get("policy_id"), str):
        raise Rejected("invalid policy reference")
    if envelope["command"] == "policy.apply":
        if p["version"] < replay.last_version(p["policy_id"]):
            raise Rejected(f"stale policy version {p['version']} (already applied {replay.last_version(p['policy_id'])})")
        try:
            p["configuration"] = validate_policy_config(p["category"], p.get("configuration"))
        except ValueError as exc:
            raise Rejected(f"configuration rejected locally: {exc}") from None
    if consume:
        replay.remember(nonce, expires)
    return envelope
