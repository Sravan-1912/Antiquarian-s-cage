import pyotp
from sqlalchemy import select

from tests.conftest import STRONG, bootstrap_admin, csrf, last_token, login


def test_bootstrap_registration_and_login(client, outbox):
    assert client.get("/api/v1/auth/bootstrap-status").json() == {"needs_setup": True}

    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com", "password": "weak"})
    assert r.status_code == 422

    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com", "password": STRONG})
    assert r.status_code == 201

    # Registration is closed once the first administrator exists.
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Evil", "full_name": "Mallory X", "email": "m@example.org", "password": STRONG})
    assert r.status_code == 403
    assert client.get("/api/v1/auth/bootstrap-status").json() == {"needs_setup": False}

    # Email must be verified before sign-in.
    r = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": STRONG})
    assert r.status_code == 403
    r = client.post("/api/v1/auth/verify-email", json={"token": last_token(outbox, "/verify-email")})
    assert r.status_code == 200

    assert login(client, "ROOT@example.com") == {"mfa_required": False}
    me = client.get("/api/v1/auth/me").json()
    assert me["email"] == "root@example.com"
    assert [r["key"] for r in me["roles"]] == ["super_admin"]
    assert "users:manage" in me["permissions"]


def test_cookies_are_hardened_and_csrf_enforced(client, outbox):
    bootstrap_admin(client, outbox)
    r = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": STRONG})
    set_cookie = ";".join(r.headers.get_list("set-cookie")).lower()
    assert "cage_session=" in set_cookie and "httponly" in set_cookie and "samesite=strict" in set_cookie

    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 403  # missing CSRF header
    r = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    r = client.post("/api/v1/auth/logout", headers=csrf(client))
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_foreign_origin_rejected(client, outbox):
    bootstrap_admin(client, outbox)
    r = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": STRONG},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_lockout_after_failed_attempts(client, outbox):
    bootstrap_admin(client, outbox)
    for _ in range(5):
        r = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": "Wrong-Pass-123"})
        assert r.status_code == 401
    # Locked — even the correct password is refused.
    r = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": STRONG})
    assert r.status_code == 423


def test_login_rate_limit(client, outbox):
    bootstrap_admin(client, outbox)
    codes = [client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"}).status_code
             for _ in range(12)]
    assert codes[:10] == [401] * 10
    assert 429 in codes[10:]


def test_unknown_user_and_bad_password_are_indistinguishable(client, outbox):
    bootstrap_admin(client, outbox)
    a = client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "Wrong-Pass-123"})
    b = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": "Wrong-Pass-123"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_totp_mfa_flow(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    secret = client.post("/api/v1/auth/mfa/setup", headers=csrf(client)).json()["secret"]
    r = client.post("/api/v1/auth/mfa/enable", json={"code": "123456"}, headers=csrf(client))
    assert r.status_code == 400
    r = client.post("/api/v1/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=csrf(client))
    assert r.status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))

    assert login(client, "root@example.com") == {"mfa_required": True}
    assert client.get("/api/v1/auth/me").status_code == 401  # password alone is not enough
    r = client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=csrf(client))
    assert r.status_code == 401
    # The code used at enrolment cannot be replayed; generate one for the next time-step window if needed.
    code = pyotp.TOTP(secret).now()
    r = client.post("/api/v1/auth/mfa/verify", json={"code": code}, headers=csrf(client))
    if r.status_code == 401:  # same 30s window as enrolment -> replay correctly rejected; use next step
        import time
        code = pyotp.TOTP(secret).at(int(time.time()) + 30)
        r = client.post("/api/v1/auth/mfa/verify", json={"code": code}, headers=csrf(client))
    assert r.status_code == 200, r.text
    assert client.get("/api/v1/auth/me").json()["mfa_enabled"] is True


def test_password_reset_revokes_sessions(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    old_cookie = client.cookies.get("cage_session")

    r = client.post("/api/v1/auth/password/forgot", json={"email": "root@example.com"})
    assert r.status_code == 202
    assert client.post("/api/v1/auth/password/forgot", json={"email": "ghost@example.com"}).status_code == 202

    token = last_token(outbox, "/reset-password")
    new = "Another-Strong-Pass-77"
    assert client.post("/api/v1/auth/password/reset", json={"token": token, "new_password": new}).status_code == 200
    assert client.post("/api/v1/auth/password/reset", json={"token": token, "new_password": new}).status_code == 400

    client.cookies.set("cage_session", old_cookie)
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": STRONG}).status_code == 401
    login(client, "root@example.com", new)


def test_sessions_and_login_history(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    sessions = client.get("/api/v1/auth/sessions").json()
    assert len(sessions) == 1 and sessions[0]["current"] is True
    history = client.get("/api/v1/auth/login-history").json()
    assert any(e["event_type"] == "login" and e["success"] for e in history)


def test_tokens_are_not_stored_in_plaintext(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    raw = client.cookies.get("cage_session")
    from app.core.database import session_factory
    from app.models import UserSession

    with session_factory()() as db:
        hashes = db.scalars(select(UserSession.token_hash)).all()
    assert raw not in hashes and len(hashes[0]) == 64
