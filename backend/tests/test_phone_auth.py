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
