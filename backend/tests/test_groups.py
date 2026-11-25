"""Dynamic endpoint groups + bulk actions."""
from __future__ import annotations

from tests.conftest import csrf
from tests.test_remote import _next_job, _setup
from tests.test_scripts import _create as _create_script


def _group(client, criteria, name="Windows actives"):
    return client.post("/api/v1/device-groups", json={"name": name, "description": "", "criteria": criteria},
                       headers=csrf(client))


def test_group_crud_and_live_membership(client, outbox):
    agent = _setup(client, outbox)  # one enrolled, active device
    r = _group(client, {"status": "active"})
    assert r.status_code == 201, r.text
    gid = r.json()["id"]
    assert r.json()["member_count"] == 1  # the active device matches

    # duplicate name rejected
    assert _group(client, {"status": "active"}).status_code == 409

    # live preview reflects criteria without saving
    pv = client.post("/api/v1/device-groups/preview", json={"criteria": {"status": "suspended"}}, headers=csrf(client))
    assert pv.status_code == 200 and pv.json() == []  # no suspended devices

    members = client.get(f"/api/v1/device-groups/{gid}/members").json()
    assert len(members) == 1 and members[0]["id"] == agent.device_id


def test_bulk_script_fans_out_to_members(client, outbox):
    agent = _setup(client, outbox)
    sid = _create_script(client).json()["id"]
    gid = _group(client, {"status": "active"}).json()["id"]

    r = client.post(f"/api/v1/device-groups/{gid}/bulk",
                    json={"kind": "script", "script_id": sid, "reason": "patch everyone"}, headers=csrf(client))
    assert r.status_code == 201, r.text
    assert r.json()["total"] == 1 and r.json()["dispatched"] == 1

    # the member received a signed script.run job
    env = _next_job(agent)
    assert env["command"] == "script.run"


def test_bulk_status_suspends_members(client, outbox):
    agent = _setup(client, outbox)
    gid = _group(client, {"status": "active"}).json()["id"]
    r = client.post(f"/api/v1/device-groups/{gid}/bulk",
                    json={"kind": "status", "op": "suspend", "reason": "maintenance window"}, headers=csrf(client))
    assert r.status_code == 201 and r.json()["dispatched"] == 1
    # device is now suspended → the active-status group is empty
    assert client.get(f"/api/v1/device-groups/{gid}/members").json() == []


def test_bulk_on_empty_group_rejected(client, outbox):
    _setup(client, outbox)
    gid = _group(client, {"status": "revoked"}, name="None").json()["id"]
    r = client.post(f"/api/v1/device-groups/{gid}/bulk",
                    json={"kind": "status", "op": "suspend", "reason": "maintenance"}, headers=csrf(client))
    assert r.status_code == 409
