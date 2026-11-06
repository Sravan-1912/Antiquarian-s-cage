"""Agent-side job handling: pin the command key, validate envelopes, hand valid jobs to the privileged broker and
report results. The agent itself never changes system configuration."""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

from cage_agent.commands.validator import PinnedKey, Rejected, ReplayStore, verify_and_parse

log = logging.getLogger("cage_agent.jobs")


class KeyMismatch(Exception):
    pass


class JobExecutor:
    def __init__(self, data_dir: Path, cfg, save_cfg: Callable[[], None],
                 broker_call: Callable[[dict], dict] | None = None):
        self.cfg = cfg
        self.save_cfg = save_cfg
        self.replay = ReplayStore(data_dir / "agent-replay.json")
        self.results_path = data_dir / "job-results.json"
        if broker_call is None:
            from cage_broker.pipe import call as broker_call
        self.broker_call = broker_call
        self.session_event: Callable[[str, str, str | None], None] | None = None
        self.assist = None

    # ------------------------------------------------------------------ key pinning
    def pinned_key(self, offered: dict | None) -> PinnedKey:
        kid, pub = self.cfg.extra.get("command_key_id"), self.cfg.extra.get("command_public_key")
        if kid and pub:
            if offered and (offered.get("key_id") != kid or offered.get("public_key") != pub):
                raise KeyMismatch(f"server offered command key {offered.get('key_id')} but {kid} is pinned; "
                                  "refusing all commands (key rotation requires re-provisioning)")
            return PinnedKey(kid, pub)
        if not offered:
            raise KeyMismatch("no command key pinned and none offered")
        # Trust-on-first-use over the already authenticated channel, for agents enrolled before Phase 3.
        log.warning("pinning command signing key %s (first use)", offered["key_id"])
        self.cfg.extra["command_key_id"], self.cfg.extra["command_public_key"] = offered["key_id"], offered["public_key"]
        self.save_cfg()
        return PinnedKey(offered["key_id"], offered["public_key"])

    # ------------------------------------------------------------------ results cache (idempotency)
    def _results(self) -> dict:
        return json.loads(self.results_path.read_text(encoding="utf-8")) if self.results_path.exists() else {}

    def _cache(self, job_id: str, result: dict) -> None:
        d = self._results()
        d[job_id] = result
        d = dict(list(d.items())[-500:])
        tmp = self.results_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d), encoding="utf-8")
        tmp.replace(self.results_path)

    # ------------------------------------------------------------------ processing
    def process(self, payload: dict, report: Callable[[str, dict], None]) -> int:
        try:
            key = self.pinned_key(payload.get("command_key"))
        except KeyMismatch as exc:
            log.error("%s", exc)
            return 0
        revoked = set(payload.get("revoked_job_ids") or [])
        handled = 0
        for env in payload.get("jobs") or []:
            job_id = str(env.get("job_id")) if isinstance(env, dict) else "?"
            if job_id in revoked:
                log.info("job %s revoked by server; dropped", job_id)
                continue
            cached = self._results().get(job_id)
            if cached:
                report(job_id, cached)  # re-report, never re-execute
                continue
            try:
                verify_and_parse(env, device_id=self.cfg.device_id, key=key, replay=self.replay)
            except Rejected as exc:
                log.warning("rejected job %s: %s", job_id, exc)
                result = {"status": "rejected", "detail": f"agent: {exc}"}
            else:
                command = env["command"]
                if command.startswith("assist."):
                    self._assist(report).start(env) if command == "assist.start" else self._assist(report).end(env)
                    handled += 1
                    continue  # the assist manager reports (and caches) asynchronously
                if self._runs_locally(command):
                    result = self._run_local(command, env["parameters"])
                else:
                    try:
                        result = self.broker_call({"envelope": env})
                    except Exception as exc:  # BrokerUnavailable or transport failure
                        log.error("broker unavailable for job %s: %s", job_id, exc)
                        result = {"status": "needs_attention", "detail": f"Privileged broker not available: {exc}"}
            self._finish(job_id, result, report)
            handled += 1
        return handled

    # ------------------------------------------------------------------ routing
    def _finish(self, job_id: str, result: dict, report: Callable[[str, dict], None]) -> None:
        result = {k: result.get(k) for k in ("status", "detail", "previous_state", "current_state") if k in result}
        result.setdefault("previous_state", {})
        result.setdefault("current_state", {})
        if result.get("status") not in ("succeeded", "failed", "needs_attention", "rejected"):
            result = {"status": "failed", "detail": "invalid result", "previous_state": {}, "current_state": {}}
        if job_id != "?":
            self._cache(job_id, result)
            report(job_id, result)

    @staticmethod
    def _runs_locally(command: str) -> bool:
        from cage_agent.commands.schemas import ROUTE
        if command == "device.lock":  # LockWorkStation must run in the user's session; session 0 → broker
            from cage_agent.remote.assist import _interactive
            return _interactive()
        return ROUTE[command] == "agent"

    @staticmethod
    def _run_local(command: str, params: dict) -> dict:
        from cage_agent.remote.actions import HANDLERS
        try:
            out = HANDLERS[command](params)
        except Exception as exc:  # noqa: BLE001 — reported, never swallowed
            log.exception("local action %s failed", command)
            return {"status": "failed", "detail": f"{exc.__class__.__name__}: {str(exc)[:300]}"}
        return {"status": out.status, "detail": out.detail, "previous_state": out.previous_state,
                "current_state": out.current_state}

    def _assist(self, report: Callable[[str, dict], None]):
        if self.assist is None:
            from cage_agent.remote.assist import AssistManager

            def rep(job_id: str, result: dict) -> None:
                self._finish(job_id, result, report)

            self.assist = AssistManager(rep, self.session_event or (lambda *a: None), broker_call=self.broker_call)
        return self.assist
