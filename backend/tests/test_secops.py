"""Phase 6: alert detection rules, auto-resolution, investigation workflow, notifications and reports."""
from __future__ import annotations

from datetime import timedelta

from tests.conftest import STRONG, bootstrap_admin, csrf, last_token, login
from tests.test_endpoints import INVENTORY, FakeAgent, _token
from tests.test_policies_compliance import SEC


def _db():
    from app.core.database import session_factory
    return session_factory()()


def _alerts(client, **params):
    return client.get("/api/v1/alerts", params={"status": "open", **params}).json()["items"]


def _sweep():
    from app.services import alerts
    with _db() as db:
        n = alerts.sweep(db)
        db.commit()
        return n


def test_failed_signins_raise_suspicious_alert_and_notify(client, outbox):
    bootstrap_admin(client, outbox)
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": "Wrong-Pass-123"})
    from app.core.rate_limit import get_rate_limiter
    get_rate_limiter().reset()
    # Account is now locked; wait it out by clearing the lock directly, then sign in successfully
    from app.models import User
    with _db() as db:
        u = db.query(User).one()
        u.locked_until = None
        db.commit()
    login(client, "root@example.com")
    items = _alerts(client)
    rules = {a["rule_key"]: a for a in items}
    assert rules["auth_failed_burst"]["kind"] == "suspicious_activity"
    assert "attack" not in rules["auth_failed_burst"]["title"].lower()
    assert "auth_success_after_failures" in rules
    notes = client.get("/api/v1/notifications").json()
    assert any(n["kind"] == "alert.auth_failed_burst" for n in notes)


def test_password_spray_from_one_ip(client, outbox):
    bootstrap_admin(client, outbox)
    for i in range(10):
        client.post("/api/v1/auth/login", json={"email": f"user{i % 4}@example.com", "password": "x"})
    from app.core.rate_limit import get_rate_limiter
    get_rate_limiter().reset()
    login(client, "root@example.com")
    spray = [a for a in _alerts(client) if a["rule_key"] == "auth_ip_spray"]
    assert spray and spray[0]["severity"] == "high" and len(spray[0]["evidence"]["accounts"]) == 4


def test_configuration_alerts_auto_resolve(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    bad = {**INVENTORY, "security": {**SEC, "firewall": {"state": "disabled", "data": {}},
                                     "defender": {"state": "disabled", "data": {"real_time_protection": False}}}}
    agent.signed("/agent/v1/inventory", bad)
    agent.signed("/agent/v1/inventory", bad)  # same condition again → one alert, two occurrences
    items = {a["rule_key"]: a for a in _alerts(client)}
    assert items["firewall_disabled"]["kind"] == "configuration" and items["firewall_disabled"]["occurrences"] == 2
    assert "not evidence of compromise" in items["firewall_disabled"]["description"]
    assert "antivirus_disabled" in items
    agent.signed("/agent/v1/inventory", {**INVENTORY, "security": SEC})
    assert not [a for a in _alerts(client) if a["rule_key"] in ("firewall_disabled", "antivirus_disabled")]
    closed = client.get("/api/v1/alerts", params={"status": "resolved"}).json()["items"]
    assert all("automatically" in a["resolution_notes"] for a in closed)


def test_agent_silence_and_recovery(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    agent.heartbeat()
    from app.models import Device
    import uuid
    with _db() as db:
        d = db.get(Device, uuid.UUID(agent.device_id))
        d.last_heartbeat_at = d.last_heartbeat_at - timedelta(hours=1)
        db.commit()
    assert _sweep() >= 1
    silent = [a for a in _alerts(client) if a["rule_key"] == "agent_silent"]
    assert silent and silent[0]["kind"] == "operational"
    agent.heartbeat()
    _sweep()
    assert not [a for a in _alerts(client) if a["rule_key"] == "agent_silent"]


def test_repeated_deployment_failures(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    agent.heartbeat()
    p = client.post("/api/v1/policies", json={"name": "FW policy", "category": "firewall",
                                              "configuration": {"profiles": ["public"]}}, headers=csrf(client)).json()
    client.post(f"/api/v1/policies/{p['id']}/assign", json={"device_ids": [agent.device_id]}, headers=csrf(client))
    for i in range(3):
        env = agent.signed("/agent/v1/jobs", {}).json()["jobs"][0]
        agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "needs_attention", "detail": "not elevated"})
        if i < 2:
            dep = client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]
            client.post(f"/api/v1/deployments/{dep['id']}/retry", headers=csrf(client))
    assert [a for a in _alerts(client) if a["rule_key"] == "deployment_failures"]
    dep = client.get(f"/api/v1/deployments?policy_id={p['id']}").json()[0]
    client.post(f"/api/v1/deployments/{dep['id']}/retry", headers=csrf(client))
    env = agent.signed("/agent/v1/jobs", {}).json()["jobs"][0]
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result", {"status": "succeeded"})
    assert not [a for a in _alerts(client) if a["rule_key"] == "deployment_failures"]


def test_usb_with_restriction_policy_is_medium(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    p = client.post("/api/v1/policies", json={"name": "USB RO", "category": "usb", "configuration": {"mode": "read_only"}},
                    headers=csrf(client)).json()
    client.post(f"/api/v1/policies/{p['id']}/assign", json={"device_ids": [agent.device_id]}, headers=csrf(client))
    usb = lambda devs: {**INVENTORY, "security": {**INVENTORY["security"], "usb_storage": {
        "state": "partial", "data": {f"dev{i}": d for i, d in enumerate(devs)}}}}
    agent.signed("/agent/v1/inventory", usb([]))
    agent.signed("/agent/v1/inventory", usb(["SanDisk Ultra"]))
    a = [x for x in _alerts(client) if x["rule_key"] == "usb_storage_connected"][0]
    assert a["severity"] == "medium" and "despite restriction policy" in a["title"]


def test_admin_burst_and_remote_anomalies_via_sweep(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    from app.models import User
    from app.services import audit
    from app.services.audit import Actor
    with _db() as db:
        u = db.query(User).one()
        for _ in range(5):
            audit.record(db, u.organization_id, Actor.from_user(u, "10.0.0.1"), "employee.offboarded")
        for _ in range(3):
            audit.record(db, u.organization_id, Actor.from_user(u, "10.0.0.1"), "remote.reauth_failed", result="denied")
        db.commit()
    _sweep()
    rules = {a["rule_key"]: a for a in _alerts(client)}
    assert rules["admin_activity_burst"]["severity"] == "high"
    assert rules["remote_access_anomaly"]["severity"] == "high"
    _sweep()  # same hour → deduplicated, not duplicated
    assert len([a for a in _alerts(client) if a["rule_key"] == "admin_activity_burst"]) == 1


def test_investigation_workflow_and_rbac(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    for email, role in (("sa@example.com", "security_analyst"), ("ad@example.com", "admin")):
        client.post("/api/v1/users", json={"email": email, "full_name": "Some Body", "role": role}, headers=csrf(client))
        client.post("/api/v1/auth/invite/accept", json={"token": last_token(outbox, "/accept-invite"), "password": STRONG})
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    agent.signed("/agent/v1/inventory", {**INVENTORY, "security": {**SEC, "firewall": {"state": "disabled"}}})
    alert = [a for a in _alerts(client) if a["rule_key"] == "firewall_disabled"][0]
    analysts = client.get("/api/v1/alerts/analysts").json()
    sa = next(x for x in analysts if x["email"] == "sa@example.com")
    assert all(x["email"] != "ad@example.com" for x in analysts)  # admins can read but not handle alerts
    patch = lambda body: client.patch(f"/api/v1/alerts/{alert['id']}", json=body, headers=csrf(client))
    assert patch({"assigned_to": sa["id"]}).json()["assigned_to_label"] == "sa@example.com"
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "ad@example.com")
    assert client.get(f"/api/v1/alerts/{alert['id']}").status_code == 200
    assert patch({"status": "investigating"}).status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "sa@example.com")
    assert patch({"status": "investigating"}).json()["status"] == "investigating"
    assert patch({"note": "Confirmed with user: firewall disabled by a VPN client installer."}).status_code == 200
    assert patch({"status": "resolved"}).status_code == 422  # notes required
    assert patch({"status": "new"}).status_code == 409  # invalid transition
    r = patch({"status": "resolved", "note": "Firewall re-enabled; installer reconfigured."})
    assert r.json()["status"] == "resolved" and r.json()["resolution_notes"].startswith("Firewall re-enabled")
    assert patch({"status": "investigating", "note": "Reopened: recurred"}).json()["status"] == "investigating"
    hist = [h["kind"] for h in client.get(f"/api/v1/alerts/{alert['id']}").json()["history"]]
    assert hist.count("status") == 3 and "note" in hist and "assigned" in hist and "created" in hist
    summary = client.get("/api/v1/dashboard/summary").json()["alerts"]
    assert summary["available"] and summary["open_total"] >= 1


def test_notification_preferences_and_email_outbox(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    prefs = {p["category"]: p for p in client.get("/api/v1/notifications/preferences").json()}
    assert prefs["security_alerts"]["email"] is True and prefs["security_alerts"]["email_min_severity"] == "high"
    assert prefs["security_alerts"]["min_severity"] == "informational"
    body = [{"category": "security_alerts", "in_app": False, "email": True, "min_severity": "informational",
             "email_min_severity": "medium"}]
    assert client.put("/api/v1/notifications/preferences", json=body, headers=csrf(client)).status_code == 200
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    agent.signed("/agent/v1/inventory", {**INVENTORY, "security": {**SEC, "firewall": {"state": "disabled"}}})
    assert not any(n["kind"].startswith("alert.") for n in client.get("/api/v1/notifications").json())
    from app.models import EmailOutbox
    from app.services import notifications
    with _db() as db:
        queued = db.query(EmailOutbox).filter(EmailOutbox.subject.like("%Firewall%")).all()
        assert len(queued) == 1 and queued[0].status == "pending"
        sent, failed = notifications.deliver_outbox(db)
        assert sent >= 1 and failed == 0
    import email as em
    bodies = [em.message_from_bytes(f.read_bytes())["Subject"] for f in outbox.glob("*.eml")]
    assert any("[HIGH] Firewall disabled" in (s or "") for s in bodies)


def test_reports_csv_pdf_permissions(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    client.post("/api/v1/employees", json={"employee_number": "E9", "full_name": "=HYPERLINK(1)", "email": "x@example.com",
                                           "department": "Ops", "job_title": "Eng"}, headers=csrf(client))
    cat = {r["key"]: r for r in client.get("/api/v1/reports").json()}
    assert len(cat) == 8 and all(r["available"] for r in cat.values())
    csv_r = client.get("/api/v1/reports/employee_access", params={"format": "csv"})
    assert csv_r.status_code == 200 and "'=HYPERLINK" in csv_r.content.decode("utf-8-sig")
    for key in cat:
        pdf = client.get(f"/api/v1/reports/{key}", params={"format": "pdf"})
        assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF", key
    assert client.get("/api/v1/reports/audit_history", params={"date_from": "2026-02-01", "date_to": "2026-01-01"}).status_code == 422
    exported = client.get("/api/v1/audit", params={"action": "report.exported"}).json()["total"]
    assert exported == 9

    client.post("/api/v1/users", json={"email": "ad@example.com", "full_name": "Ad Min", "role": "admin"}, headers=csrf(client))
    client.post("/api/v1/auth/invite/accept", json={"token": last_token(outbox, "/accept-invite"), "password": STRONG})
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "ad@example.com")
    cat = {r["key"]: r for r in client.get("/api/v1/reports").json()}
    assert cat["audit_history"]["available"] is False and cat["endpoint_inventory"]["available"] is True
    assert client.get("/api/v1/reports/audit_history").status_code == 403
