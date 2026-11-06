"""Remote actions and consented remote-assistance sessions."""
from __future__ import annotations

from datetime import timedelta

from app.security import command_signing
from tests.conftest import STRONG, bootstrap_admin, csrf, last_token, login
from tests.test_endpoints import FakeAgent, _token


def _setup(client, outbox) -> FakeAgent:
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    agent.heartbeat()
    return agent


def _act(client, agent, command, params=None, password=None, reason="ticket 4711"):
    return client.post(f"/api/v1/devices/{agent.device_id}/actions",
                       json={"command": command, "parameters": params or {}, "reason": reason,
                             **({"confirm_password": password} if password else {})}, headers=csrf(client))


def _next_job(agent):
    r = agent.signed("/agent/v1/jobs", {}).json()
    assert r["jobs"], r
    env = r["jobs"][0]
    assert command_signing.verify(env, r["command_key"]["public_key"])
    return env


def test_actions_signed_and_reauth_for_sensitive(client, outbox):
    agent = _setup(client, outbox)
    r = _act(client, agent, "device.inspect")
    assert r.status_code == 201
    env = _next_job(agent)
    assert env["command"] == "device.inspect" and env["parameters"]["reason"] == "ticket 4711"
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result",
                 {"status": "succeeded", "current_state": {"uptime_seconds": 100}})
    hist = client.get(f"/api/v1/devices/{agent.device_id}/actions").json()
    assert hist[0]["status"] == "succeeded" and hist[0]["result"]["current_state"]["uptime_seconds"] == 100

    # Restart and account changes require the operator's password
    assert _act(client, agent, "device.restart", {"delay_seconds": 300}).status_code == 403
    assert _act(client, agent, "device.restart", {"delay_seconds": 300}, password="wrong").status_code == 403
    assert _act(client, agent, "device.restart", {"delay_seconds": 300}, password=STRONG).status_code == 201
    assert _act(client, agent, "device.restart", {"delay_seconds": 5}, password=STRONG).status_code == 422
    assert _act(client, agent, "account.disable", {"username": "bad\\name"}, password=STRONG).status_code == 422
    assert _act(client, agent, "account.disable", {"username": "Guest"}, password=STRONG).status_code == 201
    # Unknown / arbitrary commands are impossible
    assert _act(client, agent, "shell.exec", {"cmd": "whoami"}).status_code == 422
    denied = client.get("/api/v1/audit", params={"action": "remote.reauth_failed"}).json()
    assert denied["total"] == 2


def _assist(client, agent, minutes=15):
    return client.post(f"/api/v1/devices/{agent.device_id}/assist",
                       json={"reason": "User reported VPN issue", "max_minutes": minutes, "confirm_password": STRONG},
                       headers=csrf(client))


def test_session_consent_granted_then_user_ends(client, outbox):
    agent = _setup(client, outbox)
    s = _assist(client, agent).json()
    assert s["status"] == "requested" and s["require_consent"] is True
    assert _assist(client, agent).status_code == 409  # one open session per endpoint
    env = _next_job(agent)
    assert env["command"] == "assist.start" and env["parameters"]["require_consent"] is True
    assert env["parameters"]["requested_by"] == "root@example.com"
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result",
                 {"status": "succeeded", "current_state": {"consent": "granted", "consent_user": "VASAVI\\user"}})
    s = client.get(f"/api/v1/remote-sessions/{s['id']}").json()
    assert s["status"] == "active" and s["consent_decision"] == "granted" and s["expires_at"]
    r = agent.signed(f"/agent/v1/assist/{s['id']}/event", {"event": "ended_by_user", "detail": "clicked End"})
    assert r.json()["status"] == "ended"
    s = client.get(f"/api/v1/remote-sessions/{s['id']}").json()
    assert s["ended_by"] == "endpoint_user"
    actions = [a["action"] for a in client.get("/api/v1/audit", params={"action": "remote.session"}).json()["items"]]
    assert {"remote.session_requested", "remote.session_started", "remote.session_ended"} <= set(actions)


def test_session_denied_and_admin_termination(client, outbox):
    agent = _setup(client, outbox)
    s = _assist(client, agent).json()
    env = _next_job(agent)
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "succeeded", "current_state": {"consent": "denied"}})
    assert client.get(f"/api/v1/remote-sessions/{s['id']}").json()["status"] == "denied"

    s = _assist(client, agent).json()
    env = _next_job(agent)
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "succeeded", "current_state": {"consent": "granted"}})
    r = client.post(f"/api/v1/remote-sessions/{s['id']}/terminate", json={"reason": "done"}, headers=csrf(client))
    assert r.json()["status"] == "ending"
    end = _next_job(agent)
    assert end["command"] == "assist.end" and end["parameters"]["session_id"] == s["id"]
    agent.signed(f"/agent/v1/jobs/{end['job_id']}/result", {"status": "succeeded"})
    s = client.get(f"/api/v1/remote-sessions/{s['id']}").json()
    assert s["status"] == "ended" and s["ended_by"] == "administrator"


def test_session_expiry_and_offline_and_cancel(client, outbox):
    agent = _setup(client, outbox)
    s = _assist(client, agent, minutes=5).json()
    env = _next_job(agent)
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "succeeded", "current_state": {"consent": "granted"}})
    from app.core.database import session_factory
    from app.models import Device, RemoteSession

    with session_factory()() as db:
        x = db.get(RemoteSession, __import__("uuid").UUID(s["id"]))
        x.expires_at = x.started_at - timedelta(seconds=1)
        db.commit()
    assert client.get(f"/api/v1/remote-sessions/{s['id']}").json()["status"] == "expired"
    cleanup = _next_job(agent)  # server-side expiry issues a signed cleanup so the broker closes Quick Assist
    assert cleanup["command"] == "assist.end" and cleanup["parameters"]["session_id"] == s["id"]

    # Cancel before delivery → job revoked, never handed to the agent
    s = _assist(client, agent).json()
    assert client.post(f"/api/v1/remote-sessions/{s['id']}/terminate", json={"reason": "wrong device"},
                       headers=csrf(client)).json()["status"] == "cancelled"
    assert agent.signed("/agent/v1/jobs", {}).json()["jobs"] == []

    # Offline endpoint: refused up front
    with session_factory()() as db:
        d = db.get(Device, __import__("uuid").UUID(agent.device_id))
        d.last_heartbeat_at = d.last_heartbeat_at - timedelta(hours=1)
        db.commit()
    assert _assist(client, agent).status_code == 409
    # Limits from org policy
    agent.heartbeat()
    assert _assist(client, agent, minutes=200).status_code == 422


def test_consent_policy_and_rbac(client, outbox):
    agent = _setup(client, outbox)
    r = client.put("/api/v1/settings/remote-assistance",
                   json={"require_consent": False, "max_session_minutes": 30, "allow_it_support": False},
                   headers=csrf(client))
    assert r.status_code == 200
    s = _assist(client, agent).json()
    assert s["require_consent"] is False
    assert _next_job(agent)["parameters"]["require_consent"] is False

    for email, role in (("sa@example.com", "security_analyst"), ("it@example.com", "it_support")):
        client.post("/api/v1/users", json={"email": email, "full_name": "Some Body", "role": role}, headers=csrf(client))
        client.post("/api/v1/auth/invite/accept", json={"token": last_token(outbox, "/accept-invite"), "password": STRONG})
    it_id = next(u["id"] for u in client.get("/api/v1/users").json() if u["email"] == "it@example.com")
    client.patch(f"/api/v1/devices/{agent.device_id}", json={"support_owner_id": it_id}, headers=csrf(client))
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "sa@example.com")  # analyst: can read, cannot act
    assert _act(client, agent, "device.lock").status_code == 403
    assert client.put("/api/v1/settings/remote-assistance", json={"require_consent": False}, headers=csrf(client)).status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "it@example.com")  # IT support: may act on assigned endpoint; assistance disabled by policy
    assert _act(client, agent, "device.lock").status_code == 201
    assert _assist(client, agent).status_code == 403


def test_endpoint_end_triggers_signed_cleanup_and_flags_failure(client, outbox):
    agent = _setup(client, outbox)
    s = _assist(client, agent).json()
    env = _next_job(agent)
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "succeeded", "current_state": {"consent": "granted"}})
    agent.signed(f"/agent/v1/assist/{s['id']}/event", {"event": "ended_by_user", "detail": "clicked End"})
    agent.heartbeat()
    cleanup = _next_job(agent)
    assert cleanup["command"] == "assist.end" and cleanup["parameters"]["session_id"] == s["id"]
    agent.signed(f"/agent/v1/jobs/{cleanup['job_id']}/result",
                 {"status": "needs_attention", "detail": "Quick Assist still running; broker not elevated"})
    s = client.get(f"/api/v1/remote-sessions/{s['id']}").json()
    assert s["status"] == "ended" and s["ended_by"] == "endpoint_user" and "cleanup incomplete" in s["end_reason"]
    assert any(n["kind"] == "remote.cleanup_incomplete" for n in client.get("/api/v1/notifications").json())
