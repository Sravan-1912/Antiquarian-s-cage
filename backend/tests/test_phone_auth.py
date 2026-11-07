"""Phone approval sign-in. A software key stands in for the phone's biometric-protected hardware key; the server
cannot tell the difference, which is the point: it trusts only signatures from the paired public key."""
from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from sqlalchemy import select

from tests.conftest import bootstrap_admin, csrf, login

ADMIN = "root@example.com"


class SoftPhone:
    def __init__(self, alg: str = "ES256"):
        self.alg = alg
        self.key = ec.generate_private_key(ec.SECP256R1()) if alg == "ES256" else rsa.generate_private_key(65537, 2048)
        self.pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.id = self.secret = None

    def sign(self, msg: bytes) -> str:
        if self.alg == "ES256":
            sig = self.key.sign(msg, ec.ECDSA(hashes.SHA256()))
        else:
            sig = self.key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(sig).decode()

    def auth(self) -> dict:
        return {"authenticator_id": self.id, "poll_secret": self.secret}


def _pair(client, phone: SoftPhone) -> dict:
    from app.services.phone_auth import pair_message
    r = client.post("/api/v1/me/phone-authenticators/pairing", headers=csrf(client))
    assert r.status_code == 200, r.text
    token = r.json()["payload"]["token"]
    body = {"token": token, "public_key_pem": phone.pem, "key_alg": phone.alg, "name": "Test phone",
            "platform": "android", "signature": phone.sign(pair_message(token, phone.pem))}
    r = client.post("/api/v1/authenticator/pair", json=body)
    assert r.status_code == 200, r.text
    phone.id, phone.secret = r.json()["authenticator_id"], r.json()["poll_secret"]
    return body


def _setup(client, outbox, alg="ES256") -> SoftPhone:
    bootstrap_admin(client, outbox)
    login(client, ADMIN)
    phone = SoftPhone(alg)
    _pair(client, phone)
    client.post("/api/v1/auth/logout", headers=csrf(client))
    client.cookies.clear()
    return phone


def _decide(client, phone, req, decision="approve", number=None, signer=None):
    from app.services.phone_auth import approve_message
    n = req["_number"] if number is None else number
    sig = (signer or phone).sign(approve_message(req["id"], req["challenge"], decision, n))
    return client.post("/api/v1/authenticator/decide", json={**phone.auth(), "request_id": req["id"],
                                                             "decision": decision, "number": n, "signature": sig})


def _start(client, email=ADMIN):
    r = client.post("/api/v1/auth/phone/start", json={"email": email})
    assert r.status_code == 200, r.text
    return r.json()


def _pending(client, phone, number):
    reqs = client.post("/api/v1/authenticator/pending", json=phone.auth()).json()["requests"]
    assert reqs, "phone sees no pending request"
    req = reqs[0]
    assert number in req["choices"] and len(set(req["choices"])) == 3
    req["_number"] = number
    return req


@pytest.mark.parametrize("alg", ["ES256", "RS256"])
def test_phone_sign_in_full_flow(client, outbox, alg):
    phone = _setup(client, outbox, alg)
    st = _start(client)
    assert client.post("/api/v1/auth/phone/status", json={"request_id": st["request_id"]}).json()["status"] == "pending"
    assert client.get("/api/v1/auth/me").status_code == 401

    req = _pending(client, phone, st["number"])
    assert _decide(client, phone, req).json()["result"] == "approved"

    r = client.post("/api/v1/auth/phone/status", json={"request_id": st["request_id"]})
    assert r.json()["status"] == "approved"
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["email"] == ADMIN
    # Single use: the session is never issued twice.
    again = client.post("/api/v1/auth/phone/status", json={"request_id": st["request_id"]})
    assert again.status_code == 404 or again.json()["status"] == "consumed"


def test_wrong_number_denies_and_alerts(client, outbox):
    phone = _setup(client, outbox)
    st = _start(client)
    req = _pending(client, phone, st["number"])
    wrong = next(c for c in req["choices"] if c != st["number"])
    assert _decide(client, phone, req, number=wrong).json()["result"] == "denied"
    assert client.post("/api/v1/auth/phone/status", json={"request_id": st["request_id"]}).json()["status"] == "denied"
    assert client.get("/api/v1/auth/me").status_code == 401
    from app.core.database import session_factory
    from app.models import SecurityAlert
    with session_factory()() as db:
        a = db.scalar(select(SecurityAlert).where(SecurityAlert.rule_key == "phone_approval_refused"))
        assert a is not None and a.severity == "high"


def test_signature_from_other_key_and_replay_rejected(client, outbox):
    phone = _setup(client, outbox)
    st = _start(client)
    req = _pending(client, phone, st["number"])
    assert _decide(client, phone, req, signer=SoftPhone()).status_code == 400
    assert _decide(client, phone, req).status_code == 200
    assert _decide(client, phone, req).status_code == 409  # already answered


def test_other_browser_cannot_collect_session(client, outbox):
    phone = _setup(client, outbox)
    st = _start(client)
    _decide(client, phone, _pending(client, phone, st["number"]))
    stolen_id_only = client.post("/api/v1/auth/phone/status", json={"request_id": st["request_id"]},
                                 cookies={"cage_phone_req": "not-the-secret"})
    assert stolen_id_only.status_code == 404


def test_unknown_email_gets_indistinguishable_decoy(client, outbox):
    phone = _setup(client, outbox)
    real = _start(client)
    decoy = _start(client, "nobody@example.com")
    assert set(real) == set(decoy) and 10 <= decoy["number"] <= 99
    reqs = client.post("/api/v1/authenticator/pending", json=phone.auth()).json()["requests"]
    assert all(r["id"] != decoy["request_id"] for r in reqs)
    assert client.post("/api/v1/auth/phone/status", json={"request_id": decoy["request_id"]}).json()["status"] == "pending"


def test_expired_request_cannot_be_approved(client, outbox):
    phone = _setup(client, outbox)
    st = _start(client)
    req = _pending(client, phone, st["number"])
    from app.core.database import session_factory, utcnow
    from app.models import PhoneLoginRequest
    with session_factory()() as db:
        r = db.get(PhoneLoginRequest, __import__("uuid").UUID(st["request_id"]))
        r.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert _decide(client, phone, req).status_code == 409
    assert client.post("/api/v1/auth/phone/status", json={"request_id": st["request_id"]}).json()["status"] == "expired"


def test_pairing_rejects_bad_signature_and_reuse(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, ADMIN)
    phone = SoftPhone()
    body = _pair(client, phone)
    assert client.post("/api/v1/authenticator/pair", json=body).status_code == 400  # token already used
    r = client.post("/api/v1/me/phone-authenticators/pairing", headers=csrf(client))
    other = SoftPhone()
    bad = {**body, "token": r.json()["payload"]["token"], "public_key_pem": other.pem, "signature": phone.sign(b"x")}
    assert client.post("/api/v1/authenticator/pair", json=bad).status_code == 400


def test_removed_phone_stops_working(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, ADMIN)
    phone = SoftPhone()
    _pair(client, phone)
    phones = client.get("/api/v1/me/phone-authenticators").json()
    assert len(phones) == 1
    assert client.delete(f"/api/v1/me/phone-authenticators/{phones[0]['id']}", headers=csrf(client)).status_code == 200
    assert client.post("/api/v1/authenticator/pending", json=phone.auth()).status_code == 401
