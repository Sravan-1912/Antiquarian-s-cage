"""Broker request handling, independent of the transport (named pipe) so it can be unit-tested."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from cage_agent.commands.validator import PinnedKey, Rejected, ReplayStore, verify_and_parse
from cage_agent.policies import ElevationRequired, Outcome, module

log = logging.getLogger("cage_broker")


class BrokerState:
    """Broker-owned storage: pinned command key + device id, replay store, rollback states, results cache."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.pin_path = root / "pinned.json"
        self.rollback_path = root / "rollback.json"
        self.results_path = root / "results.json"
        self.replay = ReplayStore(root / "replay.json")
        self._lock = threading.Lock()

    def pinned(self) -> tuple[str, PinnedKey] | None:
        if not self.pin_path.exists():
            return None
        d = json.loads(self.pin_path.read_text(encoding="utf-8"))
        return d["device_id"], PinnedKey(d["key_id"], d["public_key"])

    def pin(self, device_id: str, key_id: str, public_key: str) -> None:
        existing = self.pinned()
        if existing and (existing[0] != device_id or existing[1].key_id != key_id):
            raise ValueError("broker already pinned to a different device/key; re-provision deliberately")
        self.pin_path.write_text(json.dumps({"device_id": device_id, "key_id": key_id, "public_key": public_key}),
                                 encoding="utf-8")

    def _load(self, p: Path) -> dict:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}

    def _save(self, p: Path, data: dict) -> None:
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(p)

    def rollback_for(self, policy_id: str) -> dict:
        return self._load(self.rollback_path).get(policy_id, {})

    def set_rollback(self, policy_id: str, previous: dict | None) -> None:
        with self._lock:
            d = self._load(self.rollback_path)
            if previous is None:
                d.pop(policy_id, None)
            elif policy_id not in d:  # keep the ORIGINAL pre-policy state across re-applies of newer versions
                d[policy_id] = previous
            self._save(self.rollback_path, d)

    def cached_result(self, job_id: str) -> dict | None:
        return self._load(self.results_path).get(job_id)

    def cache_result(self, job_id: str, result: dict) -> None:
        with self._lock:
            d = self._load(self.results_path)
            d[job_id] = result
            if len(d) > 500:
                d = dict(list(d.items())[-500:])
            self._save(self.results_path, d)


BROKER_ACTIONS = {"device.restart", "device.restart_cancel", "device.lock", "account.disable", "account.enable",
                  "account.remove_admin", "assist.end"}  # assist.end: only closes Quick Assist (high integrity)


def _default_actions():
    from cage_agent.remote.actions import HANDLERS
    return HANDLERS


def _action(state: BrokerState, env: dict, actions) -> dict:
    command = env["command"]
    if command not in BROKER_ACTIONS:  # inspect / assist never need privileges
        return {"status": "rejected", "detail": f"broker: {command} is not a privileged action"}
    handlers = actions() if callable(actions) else actions
    try:
        out = handlers[command](env["parameters"])
    except (ElevationRequired, PermissionError) as exc:
        out = Outcome("needs_attention", f"Requires administrator rights; broker is not elevated ({exc})")
    except Exception as exc:  # noqa: BLE001
        log.exception("action failed")
        out = Outcome("failed", f"{exc.__class__.__name__}: {str(exc)[:300]}")
    result = {"status": out.status, "detail": out.detail, "previous_state": out.previous_state,
              "current_state": out.current_state}
    state.cache_result(env["job_id"], result)
    log.info("job %s %s → %s", env["job_id"], command, out.status)
    return result


def handle(state: BrokerState, request: dict, modules=module, actions=_default_actions) -> dict:
    envelope = request.get("envelope") if isinstance(request, dict) else None
    job_id = envelope.get("job_id") if isinstance(envelope, dict) else None
    if job_id and (cached := state.cached_result(str(job_id))):
        return cached  # idempotency: a redelivered job is never executed twice
    pinned = state.pinned()
    if pinned is None:
        return {"status": "needs_attention", "detail": "broker has no pinned command key; run 'cage-broker pin'"}
    device_id, key = pinned
    try:
        env = verify_and_parse(envelope, device_id=device_id, key=key, replay=state.replay)
    except Rejected as exc:
        log.warning("rejected job %s: %s", job_id, exc)
        return {"status": "rejected", "detail": f"broker: {exc}"}

    p = env["parameters"]
    if not env["command"].startswith("policy."):
        return _action(state, env, actions)
    mod = modules(p["category"])
    try:
        if env["command"] == "policy.apply":
            out: Outcome = mod.apply(p["configuration"])
            if out.status == "succeeded" and out.previous_state:
                state.set_rollback(p["policy_id"], out.previous_state)
            if out.status == "succeeded":
                state.replay.set_version(p["policy_id"], p["version"])
        else:  # policy.remove — restore broker-recorded state only
            out = mod.remove(state.rollback_for(p["policy_id"]))
            if out.status == "succeeded":
                state.set_rollback(p["policy_id"], None)
    except (ElevationRequired, PermissionError) as exc:
        out = Outcome("needs_attention", f"Requires administrator rights; broker is not elevated ({exc})")
    except Exception as exc:  # noqa: BLE001 — report every failure, never swallow
        log.exception("policy execution failed")
        out = Outcome("failed", f"{exc.__class__.__name__}: {str(exc)[:300]}")
    result = {"status": out.status, "detail": out.detail, "previous_state": out.previous_state,
              "current_state": out.current_state}
    state.cache_result(env["job_id"], result)
    log.info("job %s %s %s → %s", env["job_id"], env["command"], p["category"], out.status)
    return result
