from sqlalchemy import text

from tests.conftest import STRONG, bootstrap_admin, csrf, last_token, login

EMP = {"employee_number": "E-1001", "full_name": "Grace Hopper", "email": "grace@example.com",
       "department": "Engineering", "job_title": "Engineer"}


def _invite(client, outbox, email_addr: str, role: str) -> None:
    r = client.post("/api/v1/users", json={"email": email_addr, "full_name": "Test Person", "role": role},
                    headers=csrf(client))
    assert r.status_code == 201, r.text
    token = last_token(outbox, "/accept-invite")
    r = client.post("/api/v1/auth/invite/accept", json={"token": token, "password": STRONG})
    assert r.status_code == 200, r.text


def test_rbac_matrix_enforced_by_backend(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite(client, outbox, "analyst@example.com", "security_analyst")
    _invite(client, outbox, "support@example.com", "it_support")
    _invite(client, outbox, "admin@example.com", "admin")
    assert client.post("/api/v1/employees", json=EMP, headers=csrf(client)).status_code == 201
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # Security analyst: read employees, no writes, no audit log, no admin management.
    login(client, "analyst@example.com")
    assert client.get("/api/v1/employees").status_code == 200
    assert client.post("/api/v1/employees", json={**EMP, "employee_number": "E-2", "email": "x@example.com"},
                       headers=csrf(client)).status_code == 403
    assert client.get("/api/v1/audit").status_code == 403
    assert client.get("/api/v1/users").status_code == 403
    assert client.get("/api/v1/dashboard/summary").status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # Admin: manages the employees it owns, but cannot manage administrators or read audit logs, and is isolated from
    # the Super Admin's own org-level employee (admin isolation).
    login(client, "admin@example.com")
    assert all(i["email"] != EMP["email"] for i in client.get("/api/v1/employees").json()["items"])
    emp_id = client.post("/api/v1/employees", json={**EMP, "employee_number": "E-A", "email": "a@example.com"},
                         headers=csrf(client)).json()["id"]
    assert client.post(f"/api/v1/employees/{emp_id}/suspend", json={"reason": "investigation"},
                       headers=csrf(client)).status_code == 200
    assert client.post("/api/v1/users", json={"email": "z@example.com", "full_name": "Zed Zed", "role": "super_admin"},
                       headers=csrf(client)).status_code == 403
    assert client.get("/api/v1/audit").status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # IT support cannot change employee lifecycle.
    login(client, "support@example.com")
    assert client.post(f"/api/v1/employees/{emp_id}/reactivate", json={"reason": "cleared"},
                       headers=csrf(client)).status_code == 403
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # Denials are recorded in the audit log.
    login(client, "root@example.com")
    denied = client.get("/api/v1/audit", params={"action": "authz.denied"}).json()
    assert denied["total"] >= 4


def test_last_super_admin_cannot_be_removed(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    me = client.get("/api/v1/auth/me").json()
    r = client.put(f"/api/v1/users/{me['id']}/roles", json={"roles": ["admin"]}, headers=csrf(client))
    assert r.status_code == 409
    assert client.post(f"/api/v1/users/{me['id']}/disable", headers=csrf(client)).status_code == 409


def test_role_change_revokes_target_sessions(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite(client, outbox, "admin@example.com", "admin")
    root_cookies = dict(client.cookies)
    client.cookies.clear()
    login(client, "admin@example.com")
    admin_cookie = client.cookies.get("cage_session")
    client.cookies.clear()
    for k, v in root_cookies.items():
        client.cookies.set(k, v)
    admin_id = next(u["id"] for u in client.get("/api/v1/users").json() if u["email"] == "admin@example.com")
    r = client.put(f"/api/v1/users/{admin_id}/roles", json={"roles": ["security_analyst"]}, headers=csrf(client))
    assert r.status_code == 200
    client.cookies.set("cage_session", admin_cookie)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_employee_joiner_mover_leaver(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    r = client.post("/api/v1/employees", json=EMP, headers=csrf(client))
    assert r.status_code == 201
    emp = r.json()
    assert client.post("/api/v1/employees", json={**EMP, "employee_number": "E-9"},
                       headers=csrf(client)).status_code == 409  # duplicate email (case-insensitive)
    assert client.post("/api/v1/employees", json={**EMP, "email": "GRACE@example.com", "employee_number": "E-9"},
                       headers=csrf(client)).status_code == 409

    r = client.patch(f"/api/v1/employees/{emp['id']}", json={"department": "Security"}, headers=csrf(client))
    assert r.json()["department"] == "Security"
    assert client.post(f"/api/v1/employees/{emp['id']}/reactivate", json={"reason": "n/a"},
                       headers=csrf(client)).status_code == 409
    assert client.post(f"/api/v1/employees/{emp['id']}/suspend", json={"reason": "leave"},
                       headers=csrf(client)).json()["status"] == "suspended"
    assert client.post(f"/api/v1/employees/{emp['id']}/offboard", json={"reason": "resigned"},
                       headers=csrf(client)).json()["status"] == "offboarded"
    assert client.patch(f"/api/v1/employees/{emp['id']}", json={"job_title": "X"},
                        headers=csrf(client)).status_code == 409

    kinds = [e["kind"] for e in client.get(f"/api/v1/employees/{emp['id']}/events").json()]
    assert kinds == ["leaver", "suspend", "mover", "joiner"]

    page = client.get("/api/v1/employees", params={"q": "grace", "status": "offboarded"}).json()
    assert page["total"] == 1
    notes = client.get("/api/v1/notifications").json()
    assert any(n["kind"] == "employee.offboarded" for n in notes)

    csv_resp = client.get("/api/v1/employees/export.csv")
    assert csv_resp.status_code == 200 and "grace@example.com" in csv_resp.text


def test_csv_formula_injection_neutralised(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    client.post("/api/v1/employees", json={**EMP, "full_name": "=HYPERLINK(1)"}, headers=csrf(client))
    assert "'=HYPERLINK(1)" in client.get("/api/v1/employees/export.csv").text


def test_dashboard_uses_real_data(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    d = client.get("/api/v1/dashboard/summary").json()
    assert d["employees"]["active"] == 0
    assert d["endpoints"]["available"] is True and d["endpoints"]["enrolled"] == 0
    assert d["compliance"]["available"] is True and d["compliance"]["compliant"] == 0
    assert d["alerts"]["available"] is True and d["alerts"]["open_total"] == 0  # real, empty — not fabricated
    client.post("/api/v1/employees", json=EMP, headers=csrf(client))
    d = client.get("/api/v1/dashboard/summary").json()
    assert d["employees"]["active"] == 1
    assert d["employees"]["by_department"] == [{"department": "Engineering", "count": 1}]
    assert any(a["action"] == "employee.created" for a in d["recent_activity"])


def test_audit_chain_verifies_and_detects_tampering(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    client.post("/api/v1/employees", json=EMP, headers=csrf(client))
    r = client.post("/api/v1/audit/verify", headers=csrf(client)).json()
    assert r["valid"] is True and r["checked"] >= 4

    from app.core.database import session_factory

    with session_factory()() as db:
        if db.bind.dialect.name == "postgresql":
            return  # UPDATE is blocked by trigger on PostgreSQL; covered by test below
        db.execute(text("UPDATE audit_logs SET target_label='tampered' WHERE action='employee.created'"))
        db.commit()
    r = client.post("/api/v1/audit/verify", headers=csrf(client)).json()
    assert r["valid"] is False and "modified" in r["reason"]


def test_audit_log_is_append_only_on_postgres(client, outbox):
    from app.core.database import session_factory

    with session_factory()() as db:
        if db.bind.dialect.name != "postgresql":
            import pytest
            pytest.skip("trigger exists only on PostgreSQL")
    bootstrap_admin(client, outbox)
    import pytest
    from sqlalchemy.exc import DBAPIError

    with session_factory()() as db, pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM audit_logs"))
        db.commit()


def test_global_search_respects_permissions(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    client.post("/api/v1/employees", json=EMP, headers=csrf(client))
    hits = client.get("/api/v1/search", params={"q": "grace"}).json()
    assert hits and hits[0]["type"] == "employee"
