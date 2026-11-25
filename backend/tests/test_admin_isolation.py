"""Admin isolation (row-level multi-tenancy): an Admin sees only its own users/employees/endpoints; a Super Admin
sees everything; endpoint accounts have no console access."""
from __future__ import annotations

from tests.conftest import bootstrap_admin, csrf, invite_and_accept, login
from tests.test_endpoints import FakeAgent


def _invite(client, outbox, email, role):
    invite_and_accept(client, outbox, email, role, full_name="A B")


def _employee(client, number, email):
    r = client.post("/api/v1/employees", json={"employee_number": number, "full_name": number, "email": email,
                                               "department": "Ops", "job_title": "Staff"}, headers=csrf(client))
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _enrol(client, outbox, hostname):
    tok = client.post("/api/v1/enrollment-tokens", json={"label": hostname, "expires_in_minutes": 30},
                      headers=csrf(client)).json()["token"]
    agent = FakeAgent(client)
    agent.enroll(tok, hostname=hostname)
    return agent.device_id


def _emails(items):
    return {i["email"] for i in (items["items"] if isinstance(items, dict) else items)}


def test_two_admins_are_isolated_and_super_admin_sees_all(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite(client, outbox, "admin_a@example.com", "admin")
    _invite(client, outbox, "admin_b@example.com", "admin")
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # Admin A creates an employee and enrols an endpoint.
    login(client, "admin_a@example.com")
    a_emp = _employee(client, "A-1", "alice@example.com")
    a_dev = _enrol(client, outbox, "LAPTOP-A")
    assert _emails(client.get("/api/v1/employees").json()) == {"alice@example.com"}
    assert {d["hostname"] for d in client.get("/api/v1/devices").json()["items"]} == {"LAPTOP-A"}
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # Admin B sees none of Admin A's resources, and creates its own.
    login(client, "admin_b@example.com")
    assert _emails(client.get("/api/v1/employees").json()) == set()
    assert client.get("/api/v1/devices").json()["items"] == []
    assert client.get(f"/api/v1/employees/{a_emp}").status_code == 404        # cannot read A's employee by id
    assert client.get(f"/api/v1/devices/{a_dev}").status_code == 404          # cannot read A's device by id
    b_emp = _employee(client, "B-1", "bob@example.com")
    _enrol(client, outbox, "LAPTOP-B")
    assert _emails(client.get("/api/v1/employees").json()) == {"bob@example.com"}
    # Admin B only sees itself in the administrators list, never Admin A or the Super Admin.
    assert _emails(client.get("/api/v1/users").json()) == {"admin_b@example.com"}
    client.post("/api/v1/auth/logout", headers=csrf(client))

    # Super Admin sees every admin's resources.
    login(client, "root@example.com")
    assert _emails(client.get("/api/v1/employees").json()) == {"alice@example.com", "bob@example.com"}
    assert {d["hostname"] for d in client.get("/api/v1/devices").json()["items"]} == {"LAPTOP-A", "LAPTOP-B"}
    assert {"admin_a@example.com", "admin_b@example.com", "root@example.com"} <= _emails(client.get("/api/v1/users").json())
    assert client.get(f"/api/v1/employees/{a_emp}").status_code == 200
    assert client.get(f"/api/v1/employees/{b_emp}").status_code == 200
    # Super Admin's dashboard counts both tenants; an admin's counts only its own.
    assert client.get("/api/v1/dashboard/summary").json()["endpoints"]["enrolled"] == 2


def test_admin_dashboard_counts_only_its_own_tenant(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite(client, outbox, "admin_a@example.com", "admin")
    _invite(client, outbox, "admin_b@example.com", "admin")
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "admin_a@example.com")
    _enrol(client, outbox, "A1")
    _enrol(client, outbox, "A2")
    dash = client.get("/api/v1/dashboard/summary").json()
    assert dash["endpoints"]["enrolled"] == 2
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "admin_b@example.com")
    assert client.get("/api/v1/dashboard/summary").json()["endpoints"]["enrolled"] == 0


def test_admin_cannot_create_administrators(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite(client, outbox, "admin_a@example.com", "admin")
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "admin_a@example.com")
    # admin role has no users:manage at all, so this is 403 regardless; the tenancy guard is defence in depth.
    assert client.post("/api/v1/users", json={"email": "x@example.com", "full_name": "X", "role": "admin"},
                       headers=csrf(client)).status_code == 403


def test_super_admin_created_analyst_keeps_org_wide_view(client, outbox):
    """Security staff the Super Admin creates directly are the org's security team and are not tenant-isolated."""
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite(client, outbox, "admin_a@example.com", "admin")
    _invite(client, outbox, "analyst@example.com", "security_analyst")
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "admin_a@example.com")
    _employee(client, "A-1", "alice@example.com")
    _enrol(client, outbox, "LAPTOP-A")
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "analyst@example.com")
    assert "alice@example.com" in _emails(client.get("/api/v1/employees").json())
    assert {d["hostname"] for d in client.get("/api/v1/devices").json()["items"]} == {"LAPTOP-A"}
