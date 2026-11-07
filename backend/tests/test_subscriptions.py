"""Subscription tiers and device-slot quotas: enrollment is rejected once a tenant's slots are full, and a Super
Admin can raise the limit by assigning a plan."""
from __future__ import annotations

from tests.conftest import STRONG, bootstrap_admin, csrf, last_token, login
from tests.test_endpoints import FakeAgent


def _invite_admin(client, outbox, email):
    assert client.post("/api/v1/users", json={"email": email, "full_name": "Ad Min", "role": "admin"},
                       headers=csrf(client)).status_code == 201
    client.post("/api/v1/auth/invite/accept", json={"token": last_token(outbox, "/accept-invite"), "password": STRONG})


def _token(client):
    r = client.post("/api/v1/enrollment-tokens", json={"label": "test-token", "expires_in_minutes": 30}, headers=csrf(client))
    return r


def _enrol(client, n):
    tok = _token(client).json()["token"]
    a = FakeAgent(client)
    return a.enroll(tok, hostname=f"H{n}")


def test_default_trial_quota_blocks_the_sixth_device(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite_admin(client, outbox, "admin_a@example.com")
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "admin_a@example.com")
    # Pre-issue a token while under the limit, to prove enrolment itself re-checks the quota.
    spare = _token(client).json()["token"]
    for i in range(5):
        assert _enrol(client, i).status_code == 201
    u = client.get("/api/v1/subscription").json()
    assert u == {"plan": "trial", "plan_source": "default", "used": 5, "limit": 5, "available": 0, "at_limit": True}
    # Token creation is refused once full...
    assert _token(client).status_code == 402
    # ...and so is enrolment with the token issued earlier (authoritative check).
    a = FakeAgent(client)
    r = a.enroll(spare, hostname="H6")
    assert r.status_code == 402 and "quota" in r.json()["detail"].lower()


def test_super_admin_raises_the_limit_with_a_plan(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite_admin(client, outbox, "admin_a@example.com")
    admin_id = next(u["id"] for u in client.get("/api/v1/users").json() if u["email"] == "admin_a@example.com")
    assert [p["key"] for p in client.get("/api/v1/subscription/plans").json()][:2] == ["trial", "starter"]
    r = client.put(f"/api/v1/admins/{admin_id}/subscription", json={"plan_key": "starter"}, headers=csrf(client))
    assert r.status_code == 200 and r.json()["limit"] == 25
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "admin_a@example.com")
    for i in range(6):  # beyond the old trial cap of 5
        assert _enrol(client, i).status_code == 201
    assert client.get("/api/v1/subscription").json() == {
        "plan": "starter", "plan_source": "admin", "used": 6, "limit": 25, "available": 19, "at_limit": False}


def test_organisation_default_plan_applies_to_admins_without_their_own(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite_admin(client, outbox, "admin_a@example.com")
    # Org default: only 1 slot.
    r = client.put("/api/v1/organization/subscription",
                   json={"plan_key": "trial", "max_device_slots": 1}, headers=csrf(client))
    assert r.status_code == 200 and r.json()["limit"] == 1
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "admin_a@example.com")
    assert client.get("/api/v1/subscription").json()["plan_source"] == "organization"
    assert _enrol(client, 0).status_code == 201
    assert _token(client).status_code == 402  # the single org-default slot is used


def test_super_admin_enrollments_are_not_capped(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    # No subscription set; the Super Admin enrolls org-level devices (owner_admin_id NULL) without a cap.
    for i in range(7):
        assert _enrol(client, i).status_code == 201
    assert client.get("/api/v1/subscription").json()["limit"] is None


def test_revoking_a_device_frees_a_slot(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite_admin(client, outbox, "admin_a@example.com")
    admin_id = next(u["id"] for u in client.get("/api/v1/users").json() if u["email"] == "admin_a@example.com")
    client.put(f"/api/v1/admins/{admin_id}/subscription", json={"plan_key": "trial", "max_device_slots": 1},
               headers=csrf(client))
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "admin_a@example.com")
    assert _enrol(client, 0).status_code == 201
    assert _token(client).status_code == 402
    dev_id = client.get("/api/v1/devices").json()["items"][0]["id"]
    assert client.post(f"/api/v1/devices/{dev_id}/revoke", json={"reason": "retired"}, headers=csrf(client)).status_code == 200
    assert client.get("/api/v1/subscription").json()["used"] == 0  # revoked frees the slot
    assert _token(client).status_code == 201


def test_admin_cannot_change_subscriptions(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _invite_admin(client, outbox, "admin_a@example.com")
    admin_id = next(u["id"] for u in client.get("/api/v1/users").json() if u["email"] == "admin_a@example.com")
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "admin_a@example.com")
    assert client.put(f"/api/v1/admins/{admin_id}/subscription", json={"plan_key": "enterprise"},
                      headers=csrf(client)).status_code == 403
    assert client.get("/api/v1/subscriptions").status_code == 403  # the org-wide list is Super-Admin only
