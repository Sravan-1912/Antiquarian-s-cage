"""Agent lifecycle: enrollment and the main heartbeat / inventory / certificate-renewal loop."""
from __future__ import annotations

import logging
import logging.handlers
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import psutil

from cage_agent import __version__
from cage_agent.collectors.inventory import collect_all, collect_os
from cage_agent.core import configuration, identity
from cage_agent.core.communication import AgentClient, AuthRejected, ServerError
from cage_agent.core.configuration import AgentConfig, AgentPaths

log = logging.getLogger("cage_agent")


def setup_logging(paths: AgentPaths, verbose: bool = False) -> None:
    paths.ensure()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(paths.logs / "agent.log", maxBytes=2_000_000, backupCount=5,
                                              encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root = logging.getLogger("cage_agent")
    root.handlers[:] = [fh, sh]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


def enroll(paths: AgentPaths, server_url: str, token: str, *, key_scope: str, allow_insecure_localhost: bool,
           ca_bundle: str | None, service_principal: str | None = None) -> AgentConfig:
    paths.ensure()
    if paths.config.exists():
        raise configuration.ConfigError("Agent is already enrolled; unenrol (delete the data directory) first")
    cfg = AgentConfig(server_url=server_url, key_scope=key_scope, allow_insecure_localhost=allow_insecure_localhost,
                      ca_bundle=ca_bundle, extra={"agent_version": __version__})
    cfg.validate()
    key = identity.generate_key()
    hostname = socket.gethostname()[:63]
    client = AgentClient(cfg)
    try:
        os_info = collect_os([])
        resp = client.enroll({"token": token, "csr_pem": identity.make_csr(key, hostname), "hostname": hostname,
                              "agent_version": __version__,
                              "os": {k: os_info.get(k) for k in ("name", "version", "build", "edition", "architecture")}})
    finally:
        client.close()
    identity.store_key(paths, key, key_scope, service_principal)
    paths.cert.write_text(resp["certificate_pem"], encoding="utf-8")
    paths.ca.write_text(resp["ca_certificate_pem"], encoding="utf-8")
    cfg.device_id = resp["device_id"]
    cfg.extra["command_key_id"] = resp.get("command_key_id")
    cfg.extra["command_public_key"] = resp.get("command_public_key")
    cfg.heartbeat_interval_seconds = int(resp["heartbeat_interval_seconds"])
    cfg.inventory_interval_seconds = int(resp["inventory_interval_seconds"])
    configuration.save(paths, cfg)
    log.info("enrolled as device %s", cfg.device_id)
    return cfg



def network_counters() -> dict:
    """Cumulative bytes sent/received since boot on all non-loopback adapters (the server derives usage from deltas).
    Omitted (not zero) if the OS cannot provide them, so missing data is never reported as "no traffic"."""
    try:
        per = psutil.net_io_counters(pernic=True)
    except (OSError, RuntimeError):
        return {}
    nics = {k: v for k, v in per.items() if "loopback" not in k.lower() and k.lower() not in ("lo", "lo0")}
    if not nics:
        return {}
    return {"net_bytes_sent": sum(v.bytes_sent for v in nics.values()),
            "net_bytes_recv": sum(v.bytes_recv for v in nics.values())}

class Agent:
    def __init__(self, paths: AgentPaths, stop: threading.Event | None = None, *, unlock_relay: str = "on"):
        self.paths = paths
        self.unlock_relay_mode = unlock_relay  # on | dev | off
        self.stop = stop or threading.Event()
        self.cfg = configuration.load(paths)
        self.cfg.extra["agent_version"] = __version__
        self.key = identity.load_key(paths)
        self.client = AgentClient(self.cfg)
        self.next_inventory = 0.0
        self.server_status = "unknown"
        from cage_agent.commands.executor import JobExecutor
        self.executor = JobExecutor(paths.root, self.cfg, lambda: configuration.save(self.paths, self.cfg))
        self.executor.session_event = self._session_event

    def _session_event(self, session_id: str, event: str, detail: str | None) -> None:
        try:
            self.client.session_event(self.key, session_id, {"event": event, "detail": (detail or "")[:500]})
            log.info("remote session %s: %s", session_id, event)
        except (ServerError, AuthRejected) as e:
            log.warning("could not report session event %s for %s: %s", event, session_id, e)

    def jobs_once(self) -> int:
        payload = self.client.jobs(self.key)

        def report(job_id: str, result: dict) -> None:
            try:
                self.client.job_result(self.key, job_id, result)
            except ServerError as e:  # 409 = already recorded / revoked; anything else is logged
                log.warning("could not report result for job %s: %s", job_id, e)

        n = self.executor.process(payload, report)
        if n:
            log.info("processed %d job(s)", n)
            self.next_inventory = 0.0  # re-collect so compliance reflects the change promptly
        return n

    def heartbeat_once(self) -> dict:
        resp = self.client.heartbeat(self.key, {"agent_version": __version__,
                                                "uptime_seconds": int(time.time() - psutil.boot_time()),
                                                **network_counters()})
        self.server_status = resp.get("status", "unknown")
        self.cfg.heartbeat_interval_seconds = max(15, int(resp.get("heartbeat_interval_seconds", 60)))
        self.cfg.inventory_interval_seconds = max(300, int(resp.get("inventory_interval_seconds", 3600)))
        if resp.get("certificate_renewal_due"):
            self.renew_certificate()
        return resp

    def inventory_once(self) -> None:
        data = collect_all(__version__)
        if data["collection_errors"]:
            log.warning("inventory collected with %d error(s): %s", len(data["collection_errors"]),
                        "; ".join(data["collection_errors"])[:500])
        self.client.inventory(self.key, data)
        log.info("inventory uploaded")

    def renew_certificate(self) -> None:
        new_key = identity.generate_key()
        resp = self.client.renew(self.key, {"csr_pem": identity.make_csr(new_key, socket.gethostname())})
        # Persist the new key before switching, so a crash cannot leave us with a cert whose key is lost.
        identity.store_key(self.paths, new_key, self.cfg.key_scope)
        self.paths.cert.write_text(resp["certificate_pem"], encoding="utf-8")
        self.key = new_key
        log.info("device certificate renewed (valid until %s)", resp["not_after"])

    def run(self) -> int:
        log.info("agent %s started for device %s → %s", __version__, self.cfg.device_id, self.cfg.server_url)
        failures = 0
        relay = None
        if self.unlock_relay_mode != "off" and sys.platform == "win32":
            from cage_agent.unlock import UnlockHandler, UnlockRelay
            relay = UnlockRelay(UnlockHandler(lambda path, body: self.client._send(path, body, self.key)),
                                dev_allow_current_user=self.unlock_relay_mode == "dev")
            relay.start()
        try:
            while not self.stop.is_set():
                try:
                    hb = self.heartbeat_once()
                    failures = 0
                    if hb.get("jobs_pending") and self.server_status == "active":
                        self.jobs_once()
                    if self.server_status == "active" and time.monotonic() >= self.next_inventory:
                        self.inventory_once()
                        self.next_inventory = time.monotonic() + self.cfg.inventory_interval_seconds
                    elif self.server_status == "suspended":
                        log.info("device is suspended by an administrator; only heartbeats are sent")
                except AuthRejected as e:
                    # Revoked / unenrolled / clock skew. Back off for a long time rather than hammering the server.
                    log.error("server rejected agent credentials: %s", e)
                    failures += 1
                    if self.stop.wait(min(3600, 300 * failures)):
                        break
                    continue
                except ServerError as e:
                    log.error("communication failed: %s", e)
                    failures += 1
                except Exception:  # noqa: BLE001 — never let a collector bug kill the service silently
                    log.exception("unexpected error in agent loop")
                    failures += 1
                wait = self.cfg.heartbeat_interval_seconds * (1 if failures == 0 else min(10, 2 ** failures))
                self.stop.wait(wait)
        finally:
            if relay is not None:
                relay.close()
            if self.executor.assist is not None:
                self.executor.assist.end_all()  # never leave an indicator/Quick Assist running unattended
            self.client.close()
            log.info("agent stopped")
        return 0


def status(paths: AgentPaths) -> dict:
    cfg = configuration.load(paths)
    not_after = identity.certificate_not_after(paths)
    return {"device_id": cfg.device_id, "server_url": cfg.server_url, "key_scope": cfg.key_scope,
            "certificate_not_after": not_after.isoformat() if not_after else None,
            "certificate_expires_in_days": (not_after - datetime.now(timezone.utc)) // timedelta(days=1)
            if not_after else None}
