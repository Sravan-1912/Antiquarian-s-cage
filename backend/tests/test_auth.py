"""Password authentication: bootstrap, sign-in, lockout, cookie/CSRF hardening and sessions."""
from sqlalchemy import select

from tests.conftest import ROOT_PW, bootstrap_admin, csrf, login


def test_password_bootstrap_and_signin(client, outbox):
    assert client.get("/api/v1/auth/bootstrap-status").json() == {"needs_setup": True}
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com", "password": ROOT_PW})
    assert r.status_code == 201, r.text

    # Registration is closed once the first administrator exists.
    assert client.post("/api/v1/auth/register", json={
        "organization_name": "Evil", "full_name": "Mallory X", "email": "m@example.org",
        "password": ROOT_PW}).status_code == 403
    assert client.get("/api/v1/auth/bootstrap-status").json() == {"needs_setup": False}

    # register signs the Super Admin in.
    me = client.get("/api/v1/auth/me").json()
    assert me["email"] == "root@example.com"
    assert [x["key"] for x in me["roles"]] == ["super_admin"] and "users:manage" in me["permissions"]
    assert me["must_change_password"] is False


def test_weak_password_rejected_on_bootstrap(client, outbox):
    r = client.post("/api/v1/auth/register", json={
        "organization_name": "Acme", "full_name": "Ada Root", "email": "root@example.com", "password": "short"})
    assert r.status_code == 422


def test_login_wrong_then_right(client, outbox):
    bootstrap_admin(client, outbox)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert client.post("/api/v1/auth/login",
                       json={"email": "root@example.com", "password": "wrong-password"}).status_code == 401
    assert login(client, "root@example.com")["must_change_password"] is False


def test_lockout_after_repeated_failures(client, outbox):
    bootstrap_admin(client, outbox)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    codes = [client.post("/api/v1/auth/login",
                         json={"email": "root@example.com", "password": "nope"}).status_code for _ in range(6)]
    assert 423 in codes  # account temporarily locked after the max failed attempts
    # even the correct password is refused while locked
    assert client.post("/api/v1/auth/login",
                       json={"email": "root@example.com", "password": ROOT_PW}).status_code == 423


def test_cookies_are_hardened_and_csrf_enforced(client, outbox):
    bootstrap_admin(client, outbox)
    r = client.post("/api/v1/auth/login", json={"email": "root@example.com", "password": ROOT_PW})
    set_cookie = ";".join(r.headers.get_list("set-cookie")).lower()
    assert "cage_session=" in set_cookie and "httponly" in set_cookie and "samesite=strict" in set_cookie

    assert client.post("/api/v1/auth/logout").status_code == 403  # missing CSRF header
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert client.post("/api/v1/auth/logout", headers=csrf(client)).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_rate_limited(client, outbox):
    bootstrap_admin(client, outbox)
    codes = [client.post("/api/v1/auth/login",
                         json={"email": "root@example.com", "password": "x"}).status_code for _ in range(14)]
    assert 429 in codes  # the login endpoint is rate limited


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
