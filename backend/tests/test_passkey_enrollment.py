"""Passwordless onboarding and recovery (Stage A): bootstrap, invite and admin-issued recovery each register a
passkey via a single-use token, with no password ever set. Uses the real py_webauthn library via SoftAuthenticator."""
from __future__ import annotations

from tests.conftest import STRONG, csrf, last_token, login
from tests.test_identity import SoftAuthenticator, _passkey_login


def _enroll(client, token: str, authn: SoftAuthenticator, name="Phone"):
    o = client.post("/api/v1/auth/enroll/options", json={"token": token})
    assert o.status_code == 200, o.text
    opts = o.json()
    return client.post("/api/v1/auth/enroll/verify", json={
        "token": token, "challenge_id": opts["challenge_id"], "credential": authn.create(opts["options"]), "name": name})


def test_passwordless_bootstrap(client):
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com"})  # no password
    assert r.status_code == 201
    token = r.json()["enroll_token"]
    assert token and client.get("/api/v1/auth/me").status_code == 401  # not signed in yet

    authn = SoftAuthenticator()
    assert _enroll(client, token, authn, "Ada's phone").status_code == 200
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["email"] == "root@example.com"  # signed in, no password used
    # The token is single-use: it is rejected as soon as the ceremony is re-started.
    assert client.post("/api/v1/auth/enroll/options", json={"token": token}).status_code == 400
    # The passkey actually works for a fresh sign-in.
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert _passkey_login(client, authn).status_code == 200


def _bootstrap_passwordless(client):
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com"})
    authn = SoftAuthenticator()
    _enroll(client, r.json()["enroll_token"], authn)
    return authn


def test_invited_admin_enrols_a_passkey_instead_of_a_password(client, outbox):
    _bootstrap_passwordless(client)
    assert client.post("/api/v1/users", json={"email": "ada2@example.com", "full_name": "Ada Two", "role": "admin"},
                       headers=csrf(client)).status_code == 201
    client.post("/api/v1/auth/logout", headers=csrf(client))

    invite = last_token(outbox, "/accept-invite")  # the invite link doubles as a passkey-enrol link
    authn = SoftAuthenticator()
    assert _enroll(client, invite, authn, "Laptop").status_code == 200
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["email"] == "ada2@example.com"


def test_admin_issued_recovery_revokes_old_passkey_and_enrols_new(client, outbox):
    old = _bootstrap_passwordless(client)  # root signed in with passkey "old"
    uid = client.get("/api/v1/auth/me").json()["id"]
    # Root issues recovery for itself (sole Super Admin). In practice another admin or break-glass does this.
    assert client.post(f"/api/v1/users/{uid}/recovery", headers=csrf(client)).status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))

    token = last_token(outbox, "/recover")
    new = SoftAuthenticator()
    assert _enroll(client, token, new, "Replacement phone").status_code == 200
    assert client.get("/api/v1/auth/me").json()["email"] == "root@example.com"
    client.post("/api/v1/auth/logout", headers=csrf(client))
    # The new passkey works; the old one was revoked by recovery.
    assert _passkey_login(client, new).status_code == 200
    assert _passkey_login(client, old).status_code == 401


def test_recovery_requires_user_management_permission(client, outbox):
    _bootstrap_passwordless(client)
    assert client.post("/api/v1/users", json={"email": "analyst@example.com", "full_name": "An Analyst",
                                              "role": "security_analyst"}, headers=csrf(client)).status_code == 201
    uid = client.get("/api/v1/auth/me").json()["id"]
    client.post("/api/v1/auth/invite/accept",
                json={"token": last_token(outbox, "/accept-invite"), "password": STRONG})
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "analyst@example.com")  # analyst lacks users:manage
    assert client.post(f"/api/v1/users/{uid}/recovery", headers=csrf(client)).status_code == 403


def test_legacy_password_bootstrap_still_works_during_stage_a(client):
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com", "password": STRONG})
    assert r.status_code == 201 and r.json()["enroll_token"] is None
