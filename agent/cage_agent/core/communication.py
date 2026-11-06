"""HTTPS client for the agent channel: TLS verification always on, every request signed, bounded retries."""
from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric import ec

from cage_agent.core.configuration import AgentConfig
from cage_agent.security.signatures import sign_headers

log = logging.getLogger("cage_agent.comm")
RETRYABLE = {408, 425, 429, 500, 502, 503, 504}


class AuthRejected(Exception):
    """401/403 from the server: credentials revoked, device unenrolled or clock skew. Not retried blindly."""


class ServerError(Exception):
    pass


@dataclass
class Retry:
    attempts: int = 5
    base: float = 1.0
    cap: float = 60.0

    def delay(self, n: int) -> float:
        return random.uniform(0, min(self.cap, self.base * 2 ** n))  # full jitter


class AgentClient:
    def __init__(self, cfg: AgentConfig, *, client_cert: tuple[Path, Path] | None = None,
                 retry: Retry | None = None, transport: httpx.BaseTransport | None = None):
        cfg.validate()
        self.cfg = cfg
        self.retry = retry or Retry()
        verify: bool | str = cfg.ca_bundle or True
        kwargs = {"timeout": httpx.Timeout(20.0, connect=10.0), "verify": verify, "follow_redirects": False,
                  "headers": {"User-Agent": f"AntiquariansCageAgent/{cfg.extra.get('agent_version', '?')}"}}
        if transport is not None:
            kwargs["transport"] = transport
        # client_cert is used when the server enforces mTLS at the proxy (production).
        if client_cert is not None:
            kwargs["cert"] = tuple(str(p) for p in client_cert)
        self.http = httpx.Client(base_url=cfg.server_url.rstrip("/"), **kwargs)

    def close(self) -> None:
        self.http.close()

    def _send(self, path: str, payload: dict, key: ec.EllipticCurvePrivateKey | None) -> dict:
        body = json.dumps(payload, separators=(",", ":"), default=str).encode()
        full_path = urlparse(self.cfg.server_url.rstrip("/") + path).path
        last: Exception | None = None
        for n in range(self.retry.attempts):
            headers = {"Content-Type": "application/json"}
            if key is not None:
                if not self.cfg.device_id:
                    raise RuntimeError("signed request without an enrolled device id")
                headers |= sign_headers(key, self.cfg.device_id, "POST", full_path, body)  # fresh nonce per attempt
            try:
                r = self.http.post(path, content=body, headers=headers)
            except httpx.TransportError as exc:
                last = exc
                log.warning("network error on %s (attempt %d): %s", path, n + 1, exc.__class__.__name__)
            else:
                if r.status_code in (401, 403):
                    raise AuthRejected(_detail(r))
                if r.status_code in RETRYABLE:
                    last = ServerError(f"{r.status_code}: {_detail(r)}")
                    log.warning("server returned %s on %s (attempt %d)", r.status_code, path, n + 1)
                elif r.is_error:
                    raise ServerError(f"{r.status_code}: {_detail(r)}")  # 4xx: bug or rejected data, don't retry
                else:
                    return r.json() if r.content else {}
            if n + 1 < self.retry.attempts:
                time.sleep(self.retry.delay(n))
        raise ServerError(f"giving up on {path} after {self.retry.attempts} attempts: {last}")

    def enroll(self, payload: dict) -> dict:
        return self._send("/agent/v1/enroll", payload, None)

    def heartbeat(self, key, payload: dict) -> dict:
        return self._send("/agent/v1/heartbeat", payload, key)

    def inventory(self, key, payload: dict) -> dict:
        return self._send("/agent/v1/inventory", payload, key)

    def renew(self, key, payload: dict) -> dict:
        return self._send("/agent/v1/certificate/renew", payload, key)

    def jobs(self, key) -> dict:
        return self._send("/agent/v1/jobs", {}, key)

    def job_result(self, key, job_id: str, payload: dict) -> dict:
        return self._send(f"/agent/v1/jobs/{job_id}/result", payload, key)

    def session_event(self, key, session_id: str, payload: dict) -> dict:
        return self._send(f"/agent/v1/assist/{session_id}/event", payload, key)


def _detail(r: httpx.Response) -> str:
    try:
        d = r.json().get("detail")
        return d if isinstance(d, str) else json.dumps(d)[:300]
    except ValueError:
        return r.text[:300]
