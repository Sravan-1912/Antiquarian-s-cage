"""Passkey-only authentication: passwordless bootstrap, passkey sign-in, cookie/CSRF hardening and sessions."""
from sqlalchemy import select

from tests.conftest import bootstrap_admin, csrf, enrol_passkey, login


def test_passwordless_bootstrap_and_passkey_signin(client, outbox):
    assert client.get("/api/v1/auth/bootstrap-status").json() == {"needs_setup": True}
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com"})
    assert r.status_code == 201
    token = r.json()["enroll_token"]

    # Registration is closed once the first administrator exists.
    assert client.post("/api/v1/auth/register", json={
        "organization_name": "Evil", "full_name": "Mallory X", "email": "m@example.org"}).status_code == 403
    assert client.get("/api/v1/auth/bootstrap-status").json() == {"needs_setup": False}
    assert client.get("/api/v1/auth/me").status_code == 401  # not signed in until the passkey is registered

    enrol_passkey(client, token, "root@example.com", "Root device")  # registers the passkey and signs in
    me = client.get("/api/v1/auth/me").json()
    assert me["email"] == "root@example.com"
    assert [r["key"] for r in me["roles"]] == ["super_admin"] and "users:manage" in me["permissions"]
    assert "mfa_enabled" not in me  # no MFA field in the passkey-only model


def test_cookies_are_hardened_and_csrf_enforced(client, outbox):
    bootstrap_admin(client, outbox)  # signs in with a passkey
    authn = client._cage_authn["root@example.com"]
    o = client.post("/api/v1/auth/passkeys/login/options").json()
    r = client.post("/api/v1/auth/passkeys/login/verify",
                    json={"challenge_id": o["challenge_id"], "credential": authn.get(o["options"])})
    set_cookie = ";".join(r.headers.get_list("set-cookie")).lower()
    assert "cage_session=" in set_cookie and "httponly" in set_cookie and "samesite=strict" in set_cookie

    assert client.post("/api/v1/auth/logout").status_code == 403  # missing CSRF header
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert client.post("/api/v1/auth/logout", headers=csrf(client)).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_foreign_origin_rejected(client, outbox):
    bootstrap_admin(client, outbox)
    authn = client._cage_authn["root@example.com"]
    o = client.post("/api/v1/auth/passkeys/login/options").json()
    r = client.post("/api/v1/auth/passkeys/login/verify",
                    json={"challenge_id": o["challenge_id"], "credential": authn.get(o["options"])},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_passkey_login_rate_limited(client, outbox):
    bootstrap_admin(client, outbox)
    codes = [client.post("/api/v1/auth/passkeys/login/options").status_code for _ in range(24)]
    assert 429 in codes  # the passkey options endpoint is rate limited


def test_sessions_and_login_history(client, outbox):
    bootstrap_admin(client, outbox)
    sessions = client.get("/api/v1/auth/sessions").json()
    assert len(sessions) == 1 and sessions[0]["current"] is True
    history = client.get("/api/v1/auth/login-history").json()
    assert any(e["event_type"] == "login" and e["success"] for e in history)


def test_session_tokens_are_not_stored_in_plaintext(client, outbox):
    bootstrap_admin(client, outbox)
    raw = client.cookies.get("cage_session")
    from app.core.database import session_factory
    from app.models import UserSession
    with session_factory()() as db:
        hashes = db.scalars(select(UserSession.token_hash)).all()
    assert raw not in hashes and len(hashes[0]) == 64
