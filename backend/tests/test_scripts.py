"""Scripts library + deployment: CRUD, signed script.run deployment, and result capture."""
from __future__ import annotations

from tests.conftest import csrf
from tests.test_remote import _next_job, _setup


def _create(client, **over):
    body = {"name": "Clear temp", "description": "demo", "interpreter": "powershell",
            "content": "Write-Output hello", "timeout_seconds": 60}
    body.update(over)
    return client.post("/api/v1/scripts", json=body, headers=csrf(client))


def test_script_crud_and_validation(client, outbox):
    _setup(client, outbox)  # Super Admin (has devices:shell), one enrolled device
    r = _create(client)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert r.json()["content"] == "Write-Output hello"

    # library listing omits content
    lst = client.get("/api/v1/scripts").json()
    assert any(s["id"] == sid and "content" not in s for s in lst)

    # duplicate name rejected; bad interpreter rejected
    assert _create(client).status_code == 409
    assert _create(client, name="x", interpreter="ruby").status_code == 422

    # update
    up = client.put(f"/api/v1/scripts/{sid}", json={"name": "Clear temp", "description": "d2",
                    "interpreter": "bash", "content": "echo hi", "timeout_seconds": 120}, headers=csrf(client))
    assert up.status_code == 200 and up.json()["interpreter"] == "bash"


def test_deploy_signs_job_and_captures_result(client, outbox):
    agent = _setup(client, outbox)
    sid = _create(client).json()["id"]

    # deploy to the enrolled device
    dep = client.post(f"/api/v1/scripts/{sid}/deploy",
                      json={"device_ids": [agent.device_id], "reason": "ticket 4711"}, headers=csrf(client))
    assert dep.status_code == 201, dep.text
    runs = dep.json()
    assert len(runs) == 1 and runs[0]["status"] == "queued"
    run_id = runs[0]["id"]

    # the agent pulls a signed script.run job carrying the script body
    env = _next_job(agent)
    assert env["command"] == "script.run"
    assert env["parameters"]["content"] == "Write-Output hello"
    assert env["parameters"]["run_id"] == run_id

    # agent reports the result (exit code + captured output)
    agent.signed(f"/agent/v1/jobs/{env['job_id']}/result",
                 {"status": "succeeded", "current_state": {"exit_code": 0, "stdout": "hello\n", "stderr": ""}})

    out = client.get(f"/api/v1/scripts/{sid}/runs").json()
    assert out[0]["status"] == "succeeded"
    assert out[0]["exit_code"] == 0
    assert out[0]["stdout"] == "hello\n"

    # also visible on the per-endpoint runs endpoint
    dev_runs = client.get(f"/api/v1/devices/{agent.device_id}/script-runs").json()
    assert dev_runs[0]["id"] == run_id


def test_deploy_requires_targets_and_reason(client, outbox):
    _setup(client, outbox)
    sid = _create(client).json()["id"]
    assert client.post(f"/api/v1/scripts/{sid}/deploy", json={"device_ids": [], "reason": "x"},
                       headers=csrf(client)).status_code == 422


def test_timeline_merges_sources(client, outbox):
    agent = _setup(client, outbox)  # enrolling the device records a lifecycle event
    sid = _create(client).json()["id"]
    # a remote action + a script deployment add more timeline entries
    client.post(f"/api/v1/devices/{agent.device_id}/actions",
                json={"command": "device.inspect", "parameters": {}, "reason": "look"}, headers=csrf(client))
    client.post(f"/api/v1/scripts/{sid}/deploy",
                json={"device_ids": [agent.device_id], "reason": "ticket 1"}, headers=csrf(client))

    tl = client.get(f"/api/v1/devices/{agent.device_id}/timeline")
    assert tl.status_code == 200, tl.text
    entries = tl.json()
    cats = {e["category"] for e in entries}
    assert "lifecycle" in cats      # enrolment
    assert "action" in cats         # device.inspect
    assert "script" in cats         # script deployment
    # newest-first ordering
    ats = [e["at"] for e in entries]
    assert ats == sorted(ats, reverse=True)
