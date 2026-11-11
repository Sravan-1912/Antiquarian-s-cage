"""Windows sign-in approved from the phone: server half (key escrow released only after biometric approval)."""
from __future__ import annotations

import base64
import os
import uuid

from sqlalchemy import select

from tests.conftest import csrf
from tests.test_endpoints import FakeAgent, _token
from tests.test_phone_auth import SoftPhone, _decide, _pair

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _link_device_to_root(device_id: str) -> None:
    """Assign the device to an employee whose workspace account is the signed-in admin (root@example.com)."""
    from app.core.database import session_factory
    from app.models import Device, Employee, User
    with session_factory()() as db:
        root = db.scalar(select(User).where(User.email == "root@example.com"))
        emp = Employee(id=uuid.uuid4(), organization_id=root.organization_id, employee_number="E-1",
                       full_name="Ada Root", email="root@example.com", department="IT", job_title="Admin",
                       user_id=root.id)
        db.add(emp)
        db.flush()
        db.get(Device, uuid.UUID(device_id)).employee_id = emp.id
        db.commit()


def _setup(client, outbox):
    from tests.conftest import bootstrap_admin, login
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    agent = FakeAgent(client)
    agent.enroll(_token(client)["token"])
    phone = SoftPhone("RS256")
    _pair(client, phone)
    return agent, phone


def _pending(client, phone):
    reqs = client.post("/api/v1/authenticator/pending", json=phone.auth()).json()["requests"]
    assert reqs
    return reqs[0]


def _approve(client, phone, number):
    req = _pending(client, phone)
    req["_number"] = number
    return _decide(client, phone, req)


def _start(agent, kind="unlock", sid=SID, key=None):
    body = {"kind": kind, "windows_user": "VASAVI\\ada", "sid": sid}
    if key:
        body["key"] = key
    return agent.signed("/agent/v1/unlock/start", body)


def _status(agent, st):
    return agent.signed("/agent/v1/unlock/status", {"request_id": st["request_id"], "secret": st["secret"]})


def _enroll(client, agent, phone, sid=SID) -> str:
    key = base64.b64encode(os.urandom(32)).decode()
    st = _start(agent, "enroll", sid, key).json()
    req = _pending(client, phone)
    assert req["purpose"] == "windows_enroll" and req["context"]["windows_user"] == "VASAVI\\ada"
    assert _status(agent, st).json()["status"] == "pending"
    assert _approve(client, phone, st["number"]).json()["result"] == "approved"
    assert _status(agent, st).json()["status"] == "enrolled"
    return key


def test_enroll_then_unlock_releases_key_once(client, outbox):
    agent, phone = _setup(client, outbox)
    _link_device_to_root(agent.device_id)
    key = _enroll(client, agent, phone)

    st = _start(agent).json()
    assert st["approver"] == "root@example.com"
    assert _approve(client, phone, st["number"]).json()["result"] == "approved"
    out = _status(agent, st).json()
    assert out == {"status": "approved", "key": key}
    assert _status(agent, st).json()["status"] == "consumed"  # released exactly once

    keys = client.get(f"/api/v1/devices/{agent.device_id}/windows-unlock").json()
    assert len(keys) == 1 and keys[0]["last_used_at"] is not None


def test_denied_or_wrong_number_releases_nothing(client, outbox):
    agent, phone = _setup(client, outbox)
    _link_device_to_root(agent.device_id)
    _enroll(client, agent, phone)
    st = _start(agent).json()
    req = _pending(client, phone)
    req["_number"] = next(c for c in req["choices"] if c != st["number"])
    assert _decide(client, phone, req).json()["result"] == "denied"
    out = _status(agent, st).json()
    assert out == {"status": "denied"}


def test_setup_needs_approval_and_wrong_account_or_device_gets_nothing(client, outbox):
    agent, phone = _setup(client, outbox)
    _link_device_to_root(agent.device_id)
    key = base64.b64encode(os.urandom(32)).decode()
    st = _start(agent, "enroll", SID, key).json()
    # Not approved yet -> unlock is impossible.
    assert _start(agent).status_code == 404
    # Another device cannot read this device's request even with the secret.
    other = FakeAgent(client)
    other.enroll(_token(client)["token"], hostname="WS-0099")
    assert _status(other, st).status_code == 404
    _approve(client, phone, st["number"])
    assert _status(agent, st).json()["status"] == "enrolled"
    # A different Windows account on the same device is not enrolled.
    assert _start(agent, sid="S-1-5-21-1-2-3-500").status_code == 404


def test_unassigned_device_and_no_phone_are_explained(client, outbox):
    agent, _ = _setup(client, outbox)
    r = _start(agent)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "unassigned"
    _link_device_to_root(agent.device_id)
    for p in client.get("/api/v1/me/phone-authenticators").json():
        client.delete(f"/api/v1/me/phone-authenticators/{p['id']}", headers=csrf(client))
    r = _start(agent)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_phone"


def test_removed_setup_cannot_unlock(client, outbox):
    agent, phone = _setup(client, outbox)
    _link_device_to_root(agent.device_id)
    _enroll(client, agent, phone)
    k = client.get("/api/v1/me/windows-unlock").json()[0]
    assert client.delete(f"/api/v1/me/windows-unlock/{k['id']}", headers=csrf(client)).status_code == 200
    assert _start(agent).status_code == 404


def test_setup_key_must_be_32_bytes(client, outbox):
    agent, _ = _setup(client, outbox)
    _link_device_to_root(agent.device_id)
    assert _start(agent, "enroll", SID, base64.b64encode(b"short").decode()).status_code == 400
