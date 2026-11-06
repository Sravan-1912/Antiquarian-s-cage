from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from cage_agent.core.communication import AgentClient, AuthRejected, Retry, ServerError
from cage_agent.core.configuration import AgentConfig, ConfigError
from cage_agent.security import secure_storage
from cage_agent.security.signatures import canonical_request, sign_headers

BACKEND = Path(__file__).resolve().parents[2] / "backend"


def test_canonical_request_vector():
    # Fixed vector shared with backend/app/security/pki.py; both sides must produce identical bytes.
    body = b'{"a":1}'
    expected = ("CAGE-AGENT-V1\nPOST\n/agent/v1/heartbeat\n2026-01-01T00:00:00+00:00\nabc123\n"
                + hashlib.sha256(body).hexdigest()).encode()
    assert canonical_request("post", "/agent/v1/heartbeat", "2026-01-01T00:00:00+00:00", "abc123", body) == expected


@pytest.mark.skipif(not BACKEND.exists(), reason="backend source not present")
def test_canonical_request_matches_backend():
    # Extract the backend function source and execute it in isolation, then compare outputs byte-for-byte.
    import ast
    src = (BACKEND / "app" / "security" / "pki.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "canonical_request")
    ns: dict = {"hashlib": hashlib}
    exec(compile(ast.Module([fn], []), "pki.py", "exec"), ns)  # noqa: S102 — trusted repository source
    args = ("POST", "/agent/v1/inventory", "2026-11-06T12:00:00+00:00", "f" * 32, b'{"x":"\xc3\xa9"}')
    assert ns["canonical_request"](*args) == canonical_request(*args)


def test_signature_headers_verify():
    key = ec.generate_private_key(ec.SECP256R1())
    h = sign_headers(key, "dev-1", "POST", "/agent/v1/heartbeat", b"{}")
    import base64
    key.public_key().verify(base64.b64decode(h["X-Cage-Signature"]),
                            canonical_request("POST", "/agent/v1/heartbeat", h["X-Cage-Timestamp"], h["X-Cage-Nonce"], b"{}"),
                            ec.ECDSA(hashes.SHA256()))
    assert len(h["X-Cage-Nonce"]) == 32


def test_plain_http_refused_except_explicit_localhost():
    with pytest.raises(ConfigError):
        AgentConfig(server_url="http://cage.example.com").validate()
    with pytest.raises(ConfigError):
        AgentConfig(server_url="http://localhost:8000").validate()
    with pytest.raises(ConfigError):
        AgentConfig(server_url="http://10.0.0.5", allow_insecure_localhost=True).validate()
    AgentConfig(server_url="http://127.0.0.1:8000", allow_insecure_localhost=True).validate()
    AgentConfig(server_url="https://cage.example.com").validate()


def _client(handler) -> AgentClient:
    cfg = AgentConfig(server_url="https://cage.example.com", device_id="d1")
    return AgentClient(cfg, retry=Retry(attempts=3, base=0, cap=0), transport=httpx.MockTransport(handler))


def test_retries_transient_failures_with_fresh_nonces():
    nonces, calls = set(), {"n": 0}

    def handler(req: httpx.Request):
        calls["n"] += 1
        nonces.add(req.headers["X-Cage-Nonce"])
        return httpx.Response(503) if calls["n"] < 3 else httpx.Response(200, json={"status": "active"})

    key = ec.generate_private_key(ec.SECP256R1())
    assert _client(handler).heartbeat(key, {"agent_version": "x"}) == {"status": "active"}
    assert calls["n"] == 3 and len(nonces) == 3


def test_auth_rejection_is_not_retried():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(401, json={"detail": "Agent authentication failed"})

    with pytest.raises(AuthRejected):
        _client(handler).heartbeat(ec.generate_private_key(ec.SECP256R1()), {})
    assert calls["n"] == 1


def test_bounded_retries_give_up():
    def handler(req):
        raise httpx.ConnectError("down")

    with pytest.raises(ServerError, match="after 3 attempts"):
        _client(handler).heartbeat(ec.generate_private_key(ec.SECP256R1()), {})


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_roundtrip_user_and_machine():
    for scope in ("user", "machine"):
        blob = secure_storage.protect(b"secret-key-material", scope)
        assert b"secret-key-material" not in blob
        assert secure_storage.unprotect(blob) == b"secret-key-material"


@pytest.mark.skipif(sys.platform != "win32", reason="collectors target Windows")
def test_real_collection_conforms_to_backend_schema():
    """Runs the real collectors on this Windows machine and validates the payload with the server's schema."""
    from cage_agent.collectors.inventory import collect_all
    data = json.loads(json.dumps(collect_all("0.0.0-test")))
    assert data["hostname"] and data["memory_bytes"] > 0 and data["disks"]
    for check in data["security"].values():
        assert check["state"] in {"enabled", "disabled", "partial", "unknown", "not_applicable"}
    if (BACKEND / "app" / "schemas" / "endpoints.py").exists():
        sys.path.insert(0, str(BACKEND))
        try:
            from app.schemas.endpoints import InventoryRequest
            InventoryRequest.model_validate(data)
        finally:
            sys.path.remove(str(BACKEND))
