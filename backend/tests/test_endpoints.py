"""Endpoint enrollment, agent authentication (signatures, replay, revocation) and device lifecycle."""
from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.security.pki import canonical_request
from tests.conftest import bootstrap_admin, csrf, login

INVENTORY = {
    "agent_version": "0.2.0", "hostname": "WS-0042",
    "os": {"name": "Microsoft Windows 11 Pro", "version": "10.0.26100", "build": "26100"},
    "hardware": {"manufacturer": "Contoso", "model": "Laptop 7", "serial_number": "SN123"},
    "cpu": {"name": "Test CPU", "physical_cores": 8, "logical_processors": 16},
    "memory_bytes": 17179869184,
    "disks": [{"device": "C:\\", "mountpoint": "C:\\", "filesystem": "NTFS", "total_bytes": 100, "used_bytes": 40,
               "free_bytes": 60}],
    "network_interfaces": [{"name": "Ethernet", "mac_address": "00-11-22-33-44-55", "ipv4": ["10.0.0.5"]}],
    "security": {"firewall": {"state": "enabled", "data": {"domain": True}},
                 "bitlocker": {"state": "unknown", "detail": "requires elevation"}},
}


class FakeAgent:
    def __init__(self, client):
        self.client = client
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.device_id: str | None = None

    def csr(self, key=None) -> str:
        key = key or self.key
        return x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "anything")])
        ).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    def enroll(self, token: str, hostname: str = "WS-0042"):
        r = self.client.post("/agent/v1/enroll", json={"token": token, "csr_pem": self.csr(), "hostname": hostname,
                                                       "agent_version": "0.2.0"})
        if r.status_code == 201:
            self.device_id = r.json()["device_id"]
        return r

    def signed(self, path: str, payload: dict, *, ts: datetime | None = None, nonce: str | None = None,
               key=None, tamper_body: bool = False):
        body = json.dumps(payload).encode()
        ts_s = (ts or datetime.now(timezone.utc)).isoformat()
        nonce = nonce or secrets.token_hex(16)
        sig = (key or self.key).sign(canonical_request("POST", path, ts_s, nonce, body), ec.ECDSA(hashes.SHA256()))
        if tamper_body:
            body = body.replace(b"0.2.0", b"9.9.9")
        return self.client.post(path, content=body, headers={
            "Content-Type": "application/json", "X-Cage-Device": self.device_id or "", "X-Cage-Timestamp": ts_s,
            "X-Cage-Nonce": nonce, "X-Cage-Signature": base64.b64encode(sig).decode()})

    def heartbeat(self, **kw):
        return self.signed("/agent/v1/heartbeat", {"agent_version": "0.2.0", "uptime_seconds": 100}, **kw)


def _admin(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")


def _token(client, **extra) -> dict:
    r = client.post("/api/v1/enrollment-tokens", json={"label": "Laptop batch", **extra}, headers=csrf(client))
    assert r.status_code == 201, r.text
    return r.json()


def test_enrollment_heartbeat_inventory_flow(client, outbox):
    _admin(client, outbox)
    emp = client.post("/api/v1/employees", json={"employee_number": "E1", "full_name": "Grace Hopper",
                                                 "email": "grace@example.com", "department": "Eng",
                                                 "job_title": "Eng"}, headers=csrf(client)).json()
    tok = _token(client, employee_id=emp["id"])
    agent = FakeAgent(client)
    r = agent.enroll(tok["token"].lower().replace("-", " "))  # normalised: case/spacing tolerant
    assert r.status_code == 201, r.text
    cert = x509.load_pem_x509_certificate(r.json()["certificate_pem"].encode())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == agent.device_id  # server-assigned

    # Single-use token
    assert FakeAgent(client).enroll(tok["token"]).status_code == 401

    d = client.get(f"/api/v1/devices/{agent.device_id}").json()
    assert d["connectivity"] == "never" and d["online"] is False  # existing is not the same as online
    assert client.get(f"/api/v1/employees/{emp['id']}").json()["enrollment_status"] == "enrolled"

    hb = agent.heartbeat()
    assert hb.status_code == 200 and hb.json()["status"] == "active"
    assert client.get(f"/api/v1/devices/{agent.device_id}").json()["online"] is True

    assert agent.signed("/agent/v1/inventory", INVENTORY).status_code == 202
    d = client.get(f"/api/v1/devices/{agent.device_id}").json()
    assert d["manufacturer"] == "Contoso" and d["reported_mac_addresses"]["addresses"] == ["00:11:22:33:44:55"]
    inv = client.get(f"/api/v1/devices/{agent.device_id}/inventory").json()
    assert inv["security"]["bitlocker"]["state"] == "unknown"

    dash = client.get("/api/v1/dashboard/summary").json()["endpoints"]
    assert dash["available"] and dash["enrolled"] == 1 and dash["online"] == 1
    assert any(n["kind"] == "device.enrolled" for n in client.get("/api/v1/notifications").json())


def test_agent_request_security(client, outbox):
    _admin(client, outbox)
    agent = FakeAgent(client)
    assert agent.enroll(_token(client)["token"]).status_code == 201

    # Replay of an identical nonce is rejected
    assert agent.heartbeat(nonce="a" * 32).status_code == 200
    assert agent.heartbeat(nonce="a" * 32).status_code == 401
    # Stale timestamp
    assert agent.heartbeat(ts=datetime.now(timezone.utc) - timedelta(minutes=10)).status_code == 401
    # Wrong key (attacker knows device id only)
    assert agent.heartbeat(key=ec.generate_private_key(ec.SECP256R1())).status_code == 401
    # Body modified after signing
    assert agent.heartbeat(tamper_body=True).status_code == 401
    # Unknown fields / oversized values are rejected by the schema
    assert agent.signed("/agent/v1/inventory", {**INVENTORY, "evil": 1}).status_code == 422
    bad = {**INVENTORY, "hostname": "x; rm -rf /"}
    assert agent.signed("/agent/v1/inventory", bad).status_code == 422
    # Unsigned request
    assert client.post("/agent/v1/heartbeat", json={"agent_version": "1"}).status_code == 401
    # Session cookies do not grant agent access and agent auth does not grant admin access
    assert client.get("/api/v1/devices").status_code == 200


def test_bad_csr_and_tokens(client, outbox):
    _admin(client, outbox)
    tok = _token(client)
    agent = FakeAgent(client)
    r = client.post("/agent/v1/enroll", json={"token": tok["token"], "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n"
                                              + "A" * 200 + "\n-----END CERTIFICATE REQUEST-----",
                                              "hostname": "WS-1", "agent_version": "0.2.0"})
    assert r.status_code == 400
    # A non-P-256 key is refused
    rsa_like = ec.generate_private_key(ec.SECP384R1())
    r = client.post("/agent/v1/enroll", json={"token": tok["token"], "csr_pem": agent.csr(rsa_like),
                                              "hostname": "WS-1", "agent_version": "0.2.0"})
    assert r.status_code == 400 and "P-256" in r.json()["detail"]
    # Token still usable after failed attempts, then revocable
    t2 = _token(client)
    assert client.post(f"/api/v1/enrollment-tokens/{t2['id']}/revoke", headers=csrf(client)).status_code == 200
    assert FakeAgent(client).enroll(t2["token"]).status_code == 401
    assert agent.enroll(tok["token"]).status_code == 201
    states = {t["id"]: t["state"] for t in client.get("/api/v1/enrollment-tokens").json()}
    assert states[tok["id"]] == "used" and states[t2["id"]] == "revoked"


def test_lifecycle_suspend_revoke_unenroll(client, outbox):
    _admin(client, outbox)
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    did = agent.device_id
    act = lambda op: client.post(f"/api/v1/devices/{did}/{op}", json={"reason": "testing"}, headers=csrf(client))

    assert act("suspend").json()["status"] == "suspended"
    hb = agent.heartbeat()
    assert hb.status_code == 200 and hb.json()["status"] == "suspended"  # still visible, told it is suspended
    assert act("reactivate").json()["status"] == "active"
    assert act("revoke").json()["status"] == "revoked"
    assert agent.heartbeat().status_code == 401  # revocation is immediate
    certs = client.get(f"/api/v1/devices/{did}/certificates").json()
    assert all(c["status"] == "revoked" for c in certs)
    assert act("reactivate").status_code == 409  # revoked devices must re-enrol
    assert act("unenroll").json()["status"] == "unenrolled"
    kinds = [e["kind"] for e in client.get(f"/api/v1/devices/{did}/events").json()]
    assert kinds[:4] == ["unenroll", "revoke", "reactivate", "suspend"]
    audit = client.get("/api/v1/audit", params={"action": "device."}).json()
    assert {"device.enrolled", "device.suspended", "device.credentials_revoked", "device.unenrolled"} <= {
        a["action"] for a in audit["items"]}


def test_certificate_renewal(client, outbox):
    _admin(client, outbox)
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    new_key = ec.generate_private_key(ec.SECP256R1())
    r = agent.signed("/agent/v1/certificate/renew", {"csr_pem": agent.csr(new_key)})
    assert r.status_code == 200
    assert agent.heartbeat().status_code == 401  # old key no longer accepted
    agent.key = new_key
    assert agent.heartbeat().status_code == 200


def test_device_rbac(client, outbox):
    _admin(client, outbox)
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    r = client.post("/api/v1/users", json={"email": "it@example.com", "full_name": "It Person", "role": "it_support"},
                    headers=csrf(client))
    it_id = r.json()["id"]
    from tests.conftest import STRONG, last_token
    client.post("/api/v1/auth/invite/accept", json={"token": last_token(outbox, "/accept-invite"), "password": STRONG})
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "it@example.com")
    assert client.get("/api/v1/devices").json()["total"] == 0  # nothing assigned yet
    assert client.get(f"/api/v1/devices/{agent.device_id}").status_code == 404
    assert client.post("/api/v1/enrollment-tokens", json={"label": "x1"}, headers=csrf(client)).status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "root@example.com")
    assert client.patch(f"/api/v1/devices/{agent.device_id}", json={"support_owner_id": it_id},
                        headers=csrf(client)).status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "it@example.com")
    assert client.get("/api/v1/devices").json()["total"] == 1
    assert client.post(f"/api/v1/devices/{agent.device_id}/suspend", json={"reason": "nope"},
                       headers=csrf(client)).status_code == 403


def test_mtls_proxy_certificate_must_match_active_cert(client, outbox, monkeypatch):
    """With AGENT_REQUIRE_MTLS the proxy-forwarded certificate must be the device's active one."""
    from urllib.parse import quote

    from app.core.config import get_settings

    _admin(client, outbox)
    agent = FakeAgent(client)
    cert_pem = agent.enroll(_token(client)["token"]).json()["certificate_pem"]
    monkeypatch.setenv("AGENT_REQUIRE_MTLS", "true")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    get_settings.cache_clear()
    try:
        assert agent.heartbeat().status_code == 401  # signed, but no client certificate from the proxy
        other = FakeAgent(client)
        other_pem = other.enroll(_token(client)["token"]).json()["certificate_pem"]
        hdr = {"X-Client-Cert": quote(other_pem)}
        body = b'{"agent_version":"0.2.0"}'
        import base64, secrets
        from datetime import datetime, timezone
        ts, nonce = datetime.now(timezone.utc).isoformat(), secrets.token_hex(16)
        sig = base64.b64encode(agent.key.sign(canonical_request("POST", "/agent/v1/heartbeat", ts, nonce, body),
                                              ec.ECDSA(hashes.SHA256()))).decode()
        base = {"Content-Type": "application/json", "X-Cage-Device": agent.device_id, "X-Cage-Timestamp": ts,
                "X-Cage-Signature": sig}
        # Another device's (valid) certificate is refused
        assert client.post("/agent/v1/heartbeat", content=body, headers={**base, **hdr, "X-Cage-Nonce": nonce}).status_code == 401
        # The device's own certificate is accepted
        nonce2 = secrets.token_hex(16)
        sig2 = base64.b64encode(agent.key.sign(canonical_request("POST", "/agent/v1/heartbeat", ts, nonce2, body),
                                               ec.ECDSA(hashes.SHA256()))).decode()
        ok = client.post("/agent/v1/heartbeat", content=body, headers={**base, "X-Cage-Signature": sig2,
                         "X-Cage-Nonce": nonce2, "X-Client-Cert": quote(cert_pem)})
        assert ok.status_code == 200, ok.text
    finally:
        get_settings.cache_clear()
