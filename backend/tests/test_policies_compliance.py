"""Policy engine, signed command jobs, deployment workflow and compliance engine."""
from __future__ import annotations

from datetime import timedelta

from app.security import command_signing
from tests.conftest import bootstrap_admin, csrf, invite_and_accept, login
from tests.test_endpoints import INVENTORY, FakeAgent, _token

FW = {"name": "Baseline firewall", "category": "firewall", "configuration": {"profiles": ["domain", "private", "public"]}}


def _setup(client, outbox) -> FakeAgent:
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    r = agent.enroll(_token(client)["token"])
    assert r.status_code == 201
    assert r.json()["command_public_key"] and r.json()["command_key_id"].startswith("cmd-")
    agent.command_key = r.json()["command_public_key"]
    agent.heartbeat()
    return agent


def _policy(client, body=FW) -> dict:
    r = client.post("/api/v1/policies", json=body, headers=csrf(client))
    assert r.status_code == 201, r.text
    return r.json()


def test_policy_validation_and_versioning(client, outbox):
    _setup(client, outbox)
    bad = client.post("/api/v1/policies", json={"name": "Bad pw", "category": "password",
                                               "configuration": {"min_length": 30, "lockout_threshold": 5,
                                                                 "lockout_duration_minutes": 15,
                                                                 "lockout_window_minutes": 15}}, headers=csrf(client))
    assert bad.status_code == 422
    unknown_field = client.post("/api/v1/policies", json={**FW, "configuration": {"profiles": ["public"], "disable": True}},
                                headers=csrf(client))
    assert unknown_field.status_code == 422
    window = client.post("/api/v1/policies", json={"name": "Pw", "category": "password", "configuration": {
        "min_length": 12, "lockout_threshold": 5, "lockout_duration_minutes": 10, "lockout_window_minutes": 30}},
        headers=csrf(client))
    assert window.status_code == 422  # window > duration rejected (Windows constraint)
    p = _policy(client)
    assert p["version"] == 1
    r = client.patch(f"/api/v1/policies/{p['id']}", json={"configuration": {"profiles": ["public"]}}, headers=csrf(client))
    assert r.json()["version"] == 2
    revs = client.get(f"/api/v1/policies/{p['id']}/revisions").json()
    assert [x["version"] for x in revs] == [2, 1]
    assert client.post("/api/v1/policies", json=FW, headers=csrf(client)).status_code == 409  # duplicate name


def test_deployment_flow_with_signed_jobs(client, outbox):
    agent = _setup(client, outbox)
    p = _policy(client)
    deps = client.post(f"/api/v1/policies/{p['id']}/assign", json={"device_ids": [agent.device_id]},
                       headers=csrf(client)).json()
    assert deps[0]["status"] == "pending"

    hb = agent.heartbeat().json()
    assert hb["jobs_pending"] is True
    jobs = agent.signed("/agent/v1/jobs", {}).json()
    env = jobs["jobs"][0]
    assert env["command"] == "policy.apply" and env["device_id"] == agent.device_id
    assert command_signing.verify(env, jobs["command_key"]["public_key"])
    tampered = {**env, "parameters": {**env["parameters"], "configuration": {"profiles": []}}}
    assert not command_signing.verify(tampered, jobs["command_key"]["public_key"])

    assert client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]["status"] == "in_progress"
    assert agent.signed("/agent/v1/jobs", {}).json()["jobs"] == []  # delivered once (not re-sent within 10 min)

    r = agent.signed(f"/agent/v1/jobs/{env['job_id']}/result",
                     {"status": "succeeded", "detail": "enabled 3 profiles",
                      "previous_state": {"public": False}, "current_state": {"public": True}})
    assert r.status_code == 200
    d = client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]
    assert d["status"] == "applied" and d["previous_state"] == {"public": False}
    # A second, different result for the same job is refused
    assert agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "failed"}).status_code == 409

    # New version → automatic redeploy
    client.patch(f"/api/v1/policies/{p['id']}", json={"configuration": {"profiles": ["public", "private"]}},
                 headers=csrf(client))
    env2 = agent.signed("/agent/v1/jobs", {}).json()["jobs"][0]
    assert env2["parameters"]["version"] == 2

    # Unassign with rollback → signed policy.remove job
    agent.signed(f"/agent/v1/jobs/{env2['job_id']}/result", {"status": "succeeded"})
    client.post(f"/api/v1/policies/{p['id']}/unassign", json={"device_ids": [agent.device_id], "rollback": True},
                headers=csrf(client))
    env3 = agent.signed("/agent/v1/jobs", {}).json()["jobs"][0]
    assert env3["command"] == "policy.remove"
    agent.signed(f"/agent/v1/jobs/{env3['job_id']}/result", {"status": "succeeded"})
    latest = client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]
    assert latest["action"] == "remove" and "Rolled back" in latest["detail"]
    summary = client.get("/api/v1/dashboard/summary").json()["policies"]
    assert summary["available"] and summary["success_rate"] == 100


def test_failures_attention_and_notifications(client, outbox):
    agent = _setup(client, outbox)
    p = _policy(client)
    client.post(f"/api/v1/policies/{p['id']}/assign", json={"device_ids": [agent.device_id]}, headers=csrf(client))
    env = agent.signed("/agent/v1/jobs", {}).json()["jobs"][0]
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "needs_attention",
                                                           "detail": "privileged broker not available"})
    d = client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]
    assert d["status"] == "needs_attention"
    assert any(n["kind"] == "policy.deployment_failed" for n in client.get("/api/v1/notifications").json())
    r = client.post(f"/api/v1/deployments/{d['id']}/retry", headers=csrf(client))
    assert r.status_code == 200 and r.json()["status"] == "pending"


def test_emergency_revocation_and_expiry(client, outbox):
    agent = _setup(client, outbox)
    p = _policy(client)
    client.post(f"/api/v1/policies/{p['id']}/assign", json={"device_ids": [agent.device_id]}, headers=csrf(client))
    from app.core.database import session_factory
    from app.models import CommandJob

    with session_factory()() as db:
        job_id = str(db.query(CommandJob).one().id)
    assert client.post(f"/api/v1/command-jobs/{job_id}/revoke", headers=csrf(client)).status_code == 200
    jobs = agent.signed("/agent/v1/jobs", {}).json()
    assert jobs["jobs"] == [] and job_id in jobs["revoked_job_ids"]
    assert agent.signed(f"/agent/v1/jobs/{job_id}/result", {"status": "succeeded"}).status_code == 409
    assert client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]["status"] == "revoked"

    # Expiry while the device never picked the job up → "offline"
    d = client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]
    client.post(f"/api/v1/deployments/{d['id']}/retry", headers=csrf(client))
    with session_factory()() as db:
        j = db.query(CommandJob).filter(CommandJob.status == "queued").one()
        j.expires_at = j.issued_at - timedelta(minutes=1)
        db.commit()
    assert agent.signed("/agent/v1/jobs", {}).json()["jobs"] == []
    assert client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]["status"] == "offline"


def test_category_clash_and_rbac(client, outbox):
    agent = _setup(client, outbox)
    p1 = _policy(client)
    p2 = _policy(client, {**FW, "name": "Second firewall"})
    client.post(f"/api/v1/policies/{p1['id']}/assign", json={"device_ids": [agent.device_id]}, headers=csrf(client))
    r = client.post(f"/api/v1/policies/{p2['id']}/assign", json={"device_ids": [agent.device_id]}, headers=csrf(client))
    assert r.status_code == 409
    assert client.post(f"/api/v1/policies/{p1['id']}/retire", headers=csrf(client)).status_code == 409

    from tests.conftest import STRONG, last_token
    invite_and_accept(client, outbox, "sa@example.com", "security_analyst", full_name="Sec Analyst")
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "sa@example.com")
    assert client.get("/api/v1/policies").status_code == 200
    assert client.get("/api/v1/compliance/summary").status_code == 200
    assert client.post("/api/v1/policies", json={**FW, "name": "Sneaky"}, headers=csrf(client)).status_code == 403
    assert client.put("/api/v1/compliance/checks/firewall_enabled", json={"enabled": False, "severity": "low"},
                      headers=csrf(client)).status_code == 403


SEC = {
    "firewall": {"state": "enabled", "data": {}},
    "defender": {"state": "enabled", "data": {"real_time_protection": True}},
    "secure_boot": {"state": "unknown", "detail": "requires elevation"},
    "bitlocker": {"state": "unknown"},
    "guest_account": {"state": "disabled"},
    "smb1": {"state": "disabled"},
    "remote_desktop": {"state": "enabled", "data": {"nla_required": True}},
    "credential_guard": {"state": "disabled"},
    "screen_lock": {"state": "enabled", "data": {"inactivity_timeout_seconds": 600}},
    "windows_update": {"state": "enabled", "data": {"days_since_last_update": 3}},
    "account_policy": {"state": "enabled", "data": {"lockout_threshold": 5, "min_password_length": 12}},
    "audit_policy": {"state": "unknown", "detail": "requires elevation"},
}


def test_compliance_unknown_is_never_compliant(client, outbox):
    agent = _setup(client, outbox)
    inv = {**INVENTORY, "os": {**INVENTORY["os"], "edition": "Core"}, "security": SEC}
    assert agent.signed("/agent/v1/inventory", inv).status_code == 202
    c = client.get(f"/api/v1/compliance/devices/{agent.device_id}").json()
    res = {r["key"]: r["result"] for r in c["results"]}
    assert res["secure_boot"] == "UNKNOWN" and res["audit_policy"] == "UNKNOWN"
    assert res["credential_guard"] == "NOT_APPLICABLE"  # Home edition
    assert res["remote_desktop"] == "PASS" and res["smb1_disabled"] == "PASS"
    assert c["state"] == "unknown"  # no FAIL, but UNKNOWNs → not compliant
    ev = c["evaluation"]
    assert ev["unknown"] == 3 and ev["not_applicable"] == 1
    assert ev["score"] == round(100 * ev["passed"] / (ev["passed"] + ev["failed"] + ev["unknown"]))

    # A failing critical check → non_compliant + notification + remediation text
    bad = {**inv, "security": {**SEC, "firewall": {"state": "partial", "data": {"public": False}}}}
    agent.signed("/agent/v1/inventory", bad)
    c = client.get(f"/api/v1/compliance/devices/{agent.device_id}").json()
    assert c["state"] == "non_compliant" and c["results"][0]["key"] == "firewall_enabled"
    assert c["results"][0]["remediation"]
    assert any(n["kind"] == "device.non_compliant" for n in client.get("/api/v1/notifications").json())

    # Admin disables checks that cannot be determined → unknowns gone, firewall still failing
    for key in ("secure_boot", "bitlocker_enabled", "audit_policy"):
        client.put(f"/api/v1/compliance/checks/{key}", json={"enabled": False, "severity": "medium"}, headers=csrf(client))
    good = {**inv, "security": SEC}
    agent.signed("/agent/v1/inventory", good)
    c = client.get(f"/api/v1/compliance/devices/{agent.device_id}").json()
    assert c["state"] == "compliant" and c["evaluation"]["score"] == 100
    summary = client.get("/api/v1/compliance/summary").json()
    assert summary["states"]["compliant"] == 1 and summary["history"][-1]["devices"] == 1
    assert len(c["history"]) == 3


def test_usb_storage_events(client, outbox):
    agent = _setup(client, outbox)
    usb = lambda devs: {**INVENTORY, "security": {**INVENTORY["security"], "usb_storage": {
        "state": "enabled", "data": {f"dev{i}": d for i, d in enumerate(devs)}}}}
    agent.signed("/agent/v1/inventory", usb([]))
    agent.signed("/agent/v1/inventory", usb(["Kingston DataTraveler"]))
    agent.signed("/agent/v1/inventory", usb([]))
    kinds = [e["kind"] for e in client.get(f"/api/v1/devices/{agent.device_id}/events").json()]
    assert "usb_storage_connected" in kinds and "usb_storage_disconnected" in kinds
