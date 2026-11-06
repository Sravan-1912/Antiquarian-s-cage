"""Passkeys (with a software WebAuthn authenticator), OIDC SSO, applications and employee portal accounts."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from urllib.parse import parse_qs, urlencode, urlparse

import cbor2
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tests.conftest import STRONG, bootstrap_admin, csrf, last_token, login

ORIGIN, RP_ID = "http://localhost:5173", "localhost"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """Minimal platform-authenticator emulation: ES256 key, 'none' attestation, user verification performed."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0
        self.user_handle = b""

    def _auth_data(self, flags: int, attested: bytes = b"") -> bytes:
        self.count += 1
        return hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + struct.pack(">I", self.count) + attested

    def create(self, options: dict, origin: str = ORIGIN) -> dict:
        self.user_handle = unb64u(options["user"]["id"])
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        attested = bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose
        auth_data = self._auth_data(0x01 | 0x04 | 0x40, attested)  # UP | UV | AT
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}).encode()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(client), "attestationObject": b64u(att), "transports": ["internal"]}}

    def get(self, options: dict, origin: str = ORIGIN, uv: bool = True) -> dict:
        auth_data = self._auth_data(0x01 | (0x04 if uv else 0))
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        sig = self.key.sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": b64u(self.user_handle)}}


def _register_passkey(client, authn: SoftAuthenticator, name="Laptop") -> dict:
    o = client.post("/api/v1/auth/passkeys/register/options", headers=csrf(client)).json()
    assert o["options"]["authenticatorSelection"]["userVerification"] == "required"
    r = client.post("/api/v1/auth/passkeys/register/verify",
                    json={"challenge_id": o["challenge_id"], "credential": authn.create(o["options"]), "name": name},
                    headers=csrf(client))
    assert r.status_code == 200, r.text
    return r.json()


def _passkey_login(client, authn, **kw):
    o = client.post("/api/v1/auth/passkeys/login/options").json()
    return client.post("/api/v1/auth/passkeys/login/verify",
                       json={"challenge_id": o["challenge_id"], "credential": authn.get(o["options"], **kw)})


def test_passkey_register_login_and_revoke(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    authn = SoftAuthenticator()
    pk = _register_passkey(client, authn)
    assert pk["name"] == "Laptop" and len(client.get("/api/v1/auth/passkeys").json()) == 1
    client.post("/api/v1/auth/logout", headers=csrf(client))

    assert _passkey_login(client, authn).status_code == 200
    me = client.get("/api/v1/auth/me").json()
    assert me["email"] == "root@example.com"
    hist = client.get("/api/v1/auth/login-history").json()
    assert any(e["reason"] == "passkey" and e["success"] for e in hist)

    # Wrong origin (phishing site), missing user verification, replayed challenge → all refused
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert _passkey_login(client, authn, origin="https://evil.example").status_code == 401
    assert _passkey_login(client, authn, uv=False).status_code == 401
    o = client.post("/api/v1/auth/passkeys/login/options").json()
    cred = authn.get(o["options"])
    assert client.post("/api/v1/auth/passkeys/login/verify", json={"challenge_id": o["challenge_id"], "credential": cred}).status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert client.post("/api/v1/auth/passkeys/login/verify", json={"challenge_id": o["challenge_id"], "credential": cred}).status_code == 400

    # Revoked passkeys stop working
    login(client, "root@example.com")
    client.delete(f"/api/v1/auth/passkeys/{pk['id']}", headers=csrf(client))
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert _passkey_login(client, authn).status_code == 401
    login(client, "root@example.com")
    actions = {a["action"] for a in client.get("/api/v1/audit", params={"action": "auth.passkey"}).json()["items"]}
    assert actions == {"auth.passkey_registered", "auth.passkey_revoked"}


def test_cloned_authenticator_detected_by_sign_count(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    authn = SoftAuthenticator()
    _register_passkey(client, authn)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert _passkey_login(client, authn).status_code == 200
    client.post("/api/v1/auth/logout", headers=csrf(client))
    authn.count = 0  # a clone replays an older counter
    assert _passkey_login(client, authn).status_code == 401


# ------------------------------------------------------------------------------------------------ SSO
REDIRECT = "http://localhost:8090/callback"


def _employee_with_portal(client, outbox, email="grace@example.com"):
    emp = client.post("/api/v1/employees", json={"employee_number": "E1", "full_name": "Grace Hopper", "email": email,
                                                 "department": "Engineering", "job_title": "Engineer"},
                      headers=csrf(client)).json()
    r = client.post(f"/api/v1/employees/{emp['id']}/portal-access", headers=csrf(client))
    assert r.status_code == 200, r.text
    assert client.post(f"/api/v1/employees/{emp['id']}/portal-access", headers=csrf(client)).status_code == 409
    assert client.post("/api/v1/auth/invite/accept",
                       json={"token": last_token(outbox, "/accept-invite"), "password": STRONG}).status_code == 200
    return emp


def _app(client, **kw):
    body = {"name": "Wiki", "client_type": "confidential", "redirect_uris": [REDIRECT],
            "launch_url": "http://localhost:8090/", **kw}
    r = client.post("/api/v1/applications", json=body, headers=csrf(client))
    assert r.status_code == 201, r.text
    return r.json()


def _pkce():
    verifier = b64u(os.urandom(32))
    return verifier, b64u(hashlib.sha256(verifier.encode()).digest())


def _authorize(client, app, challenge, redirect=REDIRECT, **extra):
    q = {"response_type": "code", "client_id": app["client_id"], "redirect_uri": redirect, "scope": "openid email profile",
         "state": "st4te", "nonce": "n0nce", "code_challenge": challenge, "code_challenge_method": "S256", **extra}
    return client.get("/api/v1/oidc/authorize?" + urlencode(q), follow_redirects=False)


def _code(resp) -> str:
    assert resp.status_code == 303, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q.get("state") == ["st4te"], q
    return q["code"][0]


def _token(client, app, code, verifier, secret=None, redirect=REDIRECT):
    auth = base64.b64encode(f"{app['client_id']}:{secret or app['client_secret']}".encode()).decode()
    return client.post("/api/v1/oidc/token", data={"grant_type": "authorization_code", "code": code,
                                                   "redirect_uri": redirect, "code_verifier": verifier},
                       headers={"Authorization": f"Basic {auth}"})


def test_oidc_full_flow_and_verification(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    emp = _employee_with_portal(client, outbox)
    app = _app(client)
    assert app["client_secret"] and app["verified_at"] is None and "not yet verified" in app["integration"]
    assert "client_secret" not in client.get(f"/api/v1/applications/{app['id']}").json()
    client.post(f"/api/v1/applications/{app['id']}/assignments", json={"employee_ids": [emp["id"]]}, headers=csrf(client))
    client.post("/api/v1/auth/logout", headers=csrf(client))

    verifier, challenge = _pkce()
    r = _authorize(client, app, challenge)  # not signed in → console login with safe next
    loc = urlparse(r.headers["location"])
    assert loc.path == "/login" and parse_qs(loc.query)["next"][0].startswith("/api/v1/oidc/authorize?")

    login(client, "grace@example.com")
    assert client.get("/api/v1/me/workspace").json()["applications"][0]["name"] == "Wiki"
    code = _code(_authorize(client, app, challenge))
    assert _token(client, app, code, "x" * 50).status_code == 400  # wrong PKCE verifier burns the code
    code = _code(_authorize(client, app, challenge))
    tok = _token(client, app, code, verifier)
    assert tok.status_code == 200, tok.text
    assert _token(client, app, code, verifier).json()["error"] == "invalid_grant"  # single use

    disc = client.get("/api/v1/oidc/.well-known/openid-configuration").json()
    jwks = client.get("/api/v1/oidc/jwks").json()
    key = jwt.PyJWK(jwks["keys"][0]).key
    claims = jwt.decode(tok.json()["id_token"], key, algorithms=["RS256"], audience=app["client_id"], issuer=disc["issuer"])
    assert claims["email"] == "grace@example.com" and claims["nonce"] == "n0nce" and claims["amr"] == ["pwd"]
    assert claims["department"] == "Engineering"
    ui = client.get("/api/v1/oidc/userinfo", headers={"Authorization": f"Bearer {tok.json()['access_token']}"})
    assert ui.json()["sub"] == claims["sub"]

    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "root@example.com")
    a2 = client.get(f"/api/v1/applications/{app['id']}").json()
    assert a2["verified_at"] is not None and a2["integration"] == "verified"
    events = client.get(f"/api/v1/applications/{app['id']}/events").json()
    assert {"sso_authorize", "sso_token"} <= {e["event_type"] for e in events}

    # Revocation is effective immediately at userinfo
    aid = client.get(f"/api/v1/applications/{app['id']}/assignments").json()[0]["id"]
    client.delete(f"/api/v1/applications/{app['id']}/assignments/{aid}", headers=csrf(client))
    ui = client.get("/api/v1/oidc/userinfo", headers={"Authorization": f"Bearer {tok.json()['access_token']}"})
    assert ui.status_code == 401


def test_oidc_rejections(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    emp = _employee_with_portal(client, outbox)
    app = _app(client)
    assert client.post("/api/v1/applications", json={"name": "Bad", "client_type": "public",
                                                     "redirect_uris": ["http://evil.example/cb"]},
                       headers=csrf(client)).status_code == 422  # http only for localhost
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "grace@example.com")
    _, challenge = _pkce()
    # Unregistered redirect → never redirected there
    r = _authorize(client, app, challenge, redirect="http://localhost:9999/steal")
    assert urlparse(r.headers["location"]).path == "/sso-error"
    # PKCE missing
    r = _authorize(client, app, "", code_challenge_method="plain")
    assert "error=invalid_request" in r.headers["location"]
    # Not assigned → access_denied back to the app
    r = _authorize(client, app, challenge)
    assert "error=access_denied" in r.headers["location"] and r.headers["location"].startswith(REDIRECT)
    # Wrong client secret
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "root@example.com")
    client.post(f"/api/v1/applications/{app['id']}/assignments", json={"employee_ids": [emp["id"]]}, headers=csrf(client))
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "grace@example.com")
    v, c = _pkce()
    code = _code(_authorize(client, app, c))
    assert _token(client, app, code, v, secret="wrong").status_code == 401


def test_mfa_required_app_needs_passkey_step_up(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    emp = _employee_with_portal(client, outbox)
    app = _app(client, mfa_required=True)
    client.post(f"/api/v1/applications/{app['id']}/assignments", json={"employee_ids": [emp["id"]]}, headers=csrf(client))
    client.post("/api/v1/auth/logout", headers=csrf(client))

    login(client, "grace@example.com")
    authn = SoftAuthenticator()
    _register_passkey(client, authn, "Work laptop")
    v, c = _pkce()
    r = _authorize(client, app, c)
    assert "step_up=1" in r.headers["location"]  # password-only session is not enough
    client.post("/api/v1/auth/logout", headers=csrf(client))
    assert _passkey_login(client, authn).status_code == 200
    code = _code(_authorize(client, app, c))
    claims = jwt.decode(_token(client, app, code, v).json()["id_token"], options={"verify_signature": False})
    assert "mfa" in claims["amr"] and "hwk" in claims["amr"]


def test_leaver_revokes_portal_sso_and_passkeys(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    emp = _employee_with_portal(client, outbox)
    app = _app(client)
    client.post(f"/api/v1/applications/{app['id']}/assignments", json={"employee_ids": [emp["id"]]}, headers=csrf(client))
    root = dict(client.cookies)
    client.cookies.clear()
    login(client, "grace@example.com")
    authn = SoftAuthenticator()
    _register_passkey(client, authn)
    grace_cookie = client.cookies.get("cage_session")
    client.cookies.clear()
    for k, val in root.items():
        client.cookies.set(k, val)
    r = client.post(f"/api/v1/employees/{emp['id']}/offboard", json={"reason": "resigned"}, headers=csrf(client))
    assert r.status_code == 200
    ev = client.get(f"/api/v1/employees/{emp['id']}/events").json()[0]["details"]
    assert ev["application_access_revoked"] == 1 and ev["passkeys_revoked"] == 1 and ev["portal_account"] == "disabled"
    assert client.get(f"/api/v1/applications/{app['id']}/assignments").json() == []
    assert all(u["email"] != "grace@example.com" for u in client.get("/api/v1/users").json())  # not an administrator
    client.cookies.clear()
    client.cookies.set("cage_session", grace_cookie)
    assert client.get("/api/v1/me/workspace").status_code == 401
    client.cookies.clear()
    assert client.post("/api/v1/auth/login", json={"email": "grace@example.com", "password": STRONG}).status_code == 403
    assert _passkey_login(client, authn).status_code == 401


def test_employee_role_is_confined(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    _employee_with_portal(client, outbox)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    login(client, "grace@example.com")
    assert client.get("/api/v1/me/workspace").json()["employee"]["email"] == "grace@example.com"
    for path in ("/api/v1/employees", "/api/v1/devices", "/api/v1/applications", "/api/v1/dashboard/summary",
                 "/api/v1/audit", "/api/v1/users"):
        assert client.get(path).status_code == 403, path
