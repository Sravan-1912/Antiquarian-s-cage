from __future__ import annotations

import sys
import time
import uuid

import pytest

from cage_agent.commands.executor import JobExecutor
from cage_agent.commands.validator import Rejected, ReplayStore, verify_and_parse
from cage_agent.core.configuration import AgentConfig
from cage_agent.policies import Outcome
from cage_agent.remote import actions, assist
from cage_broker.core import BrokerState, handle
from tests.test_commands import DEVICE, Signer


def _env(signer, command, params):
    e = signer.envelope(command=command)
    e["parameters"] = {**params, "reason": "ticket 1", "requested_by": "admin@example.com"}
    from cage_agent.commands.validator import canonical
    import base64
    e["signature"] = base64.b64encode(signer.key.sign(canonical({k: v for k, v in e.items() if k != "signature"}))).decode()
    return e


@pytest.fixture()
def signer():
    return Signer()


@pytest.mark.parametrize("command,params,ok", [
    ("device.restart", {"delay_seconds": 300, "message": "Save your work."}, True),
    ("device.restart", {"delay_seconds": 10, "message": "x"}, False),
    ("device.restart", {"delay_seconds": 300, "message": 'x" & calc'}, False),
    ("device.lock", {}, True),
    ("device.lock", {"extra": 1}, False),
    ("account.disable", {"username": "Guest"}, True),
    ("account.disable", {"username": "a;b|c"}, False),
    ("assist.start", {"session_id": str(uuid.uuid4()), "max_minutes": 15, "require_consent": True,
                      "consent_timeout_seconds": 120}, True),
    ("assist.start", {"session_id": "not-a-uuid", "max_minutes": 15, "require_consent": True,
                      "consent_timeout_seconds": 120}, False),
])
def test_command_parameter_validation(signer, tmp_path, command, params, ok):
    env = _env(signer, command, params)
    call = lambda: verify_and_parse(env, device_id=DEVICE, key=signer.pinned, replay=ReplayStore(tmp_path / "r.json"))
    if ok:
        call()
    else:
        with pytest.raises(Rejected, match="parameters rejected"):
            call()


def test_last_admin_protection():
    users = [{"name": "Alice", "enabled": True}, {"name": "Bob", "enabled": False}]
    admins = {"alice", "bob"}
    assert actions._enabled_local_admins(users, admins) == {"alice"}


def test_last_admin_refused(monkeypatch):
    monkeypatch.setattr(actions, "_accounts", lambda: ([{"name": "Alice", "enabled": True}], {"alice"}))
    calls = []
    monkeypatch.setattr(actions, "run", lambda *a, **k: calls.append(a))
    assert actions.account_disable({"username": "alice"}).status == "needs_attention"
    assert actions.account_remove_admin({"username": "Alice"}).status == "needs_attention"
    assert calls == []  # nothing executed


def test_broker_dispatches_only_privileged_actions(signer, tmp_path):
    st = BrokerState(tmp_path / "b")
    st.pin(DEVICE, "cmd-test", signer.pub)
    fake = {"device.restart": lambda p: Outcome("succeeded", f"in {p['delay_seconds']}s")}
    r = handle(st, {"envelope": _env(signer, "device.restart", {"delay_seconds": 120, "message": "m"})}, actions=fake)
    assert r["status"] == "succeeded" and r["detail"] == "in 120s"
    r = handle(st, {"envelope": _env(signer, "device.inspect", {})}, actions=fake)
    assert r["status"] == "rejected"


def test_executor_routes_inspect_locally(signer, tmp_path, monkeypatch):
    monkeypatch.setitem(actions.HANDLERS, "device.inspect", lambda p: Outcome("succeeded", "ok", {}, {"uptime": 1}))
    broker_calls = []
    cfg = AgentConfig(server_url="https://x", device_id=DEVICE, extra={"command_key_id": "cmd-test",
                                                                      "command_public_key": signer.pub})
    ex = JobExecutor(tmp_path, cfg, lambda: None, broker_call=lambda r: broker_calls.append(r) or {"status": "succeeded"})
    reports = {}
    ex.process({"jobs": [_env(signer, "device.inspect", {}), _env(signer, "device.restart",
                                                                  {"delay_seconds": 120, "message": "m"})]},
               lambda j, r: reports.__setitem__(j, r))
    assert len(broker_calls) == 1 and broker_calls[0]["envelope"]["command"] == "device.restart"
    assert any(r["current_state"] == {"uptime": 1} for r in reports.values())


def _stub_helper(monkeypatch, consent: str, ended: str, linger: float = 0.0):
    def cmd(mode, p):
        out = {"decision": consent, "user": "PC\\tester"} if mode == "consent" else {"ended": ended}
        code = f"import json,time; time.sleep({linger if mode == 'indicator' else 0}); print(json.dumps({out!r}))"
        return [sys.executable, "-c", code]
    monkeypatch.setattr(assist, "_helper_cmd", cmd)
    monkeypatch.setattr(assist, "_interactive", lambda: True)
    monkeypatch.setattr(assist.AssistManager, "_close_quick_assist", lambda self: True)


def _wait(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        time.sleep(0.05)
    assert cond()


def _start_env(sid):
    return {"job_id": str(uuid.uuid4()), "parameters": {"session_id": sid, "max_minutes": 5, "require_consent": True,
                                                         "consent_timeout_seconds": 60, "requested_by": "a", "reason": "r"}}


def test_assist_denied_never_shows_indicator(monkeypatch):
    _stub_helper(monkeypatch, "denied", "user")
    reports, events = [], []
    m = assist.AssistManager(lambda j, r: reports.append(r), lambda *e: events.append(e), launch_quick_assist=False)
    m.start(_start_env(str(uuid.uuid4())))
    _wait(lambda: reports)
    assert reports[0]["current_state"]["consent"] == "denied" and not m.live and not events


def test_assist_granted_then_user_ends(monkeypatch):
    _stub_helper(monkeypatch, "granted", "user")
    reports, events = [], []
    m = assist.AssistManager(lambda j, r: reports.append(r), lambda *e: events.append(e), launch_quick_assist=False)
    sid = str(uuid.uuid4())
    m.start(_start_env(sid))
    _wait(lambda: events)
    assert reports[0]["current_state"] == {"consent": "granted", "consent_user": "PC\\tester"}
    assert events[0][:2] == (sid, "ended_by_user")


def test_assist_admin_termination(monkeypatch):
    _stub_helper(monkeypatch, "granted", "expired", linger=30)
    reports, events = [], []
    m = assist.AssistManager(lambda j, r: reports.append(r), lambda *e: events.append(e), launch_quick_assist=False)
    sid = str(uuid.uuid4())
    m.start(_start_env(sid))
    _wait(lambda: sid in m.live)
    m.end({"job_id": "end-1", "parameters": {"session_id": sid}})
    _wait(lambda: sid not in m.live)
    assert reports[-1]["detail"] == "Session ended on endpoint" and not events  # admin end reported via job, not event


def test_assist_refused_in_session_zero(monkeypatch):
    monkeypatch.setattr(assist, "_interactive", lambda: False)
    reports = []
    m = assist.AssistManager(lambda j, r: reports.append(r), lambda *e: None)
    m.start(_start_env(str(uuid.uuid4())))
    _wait(lambda: reports)
    assert reports[0]["status"] == "needs_attention"



def test_assist_end_escalates_to_broker_when_quick_assist_survives(monkeypatch):
    """Quick Assist runs at high integrity: if the agent cannot close it, the signed assist.end goes to the broker,
    and success is only reported when the process is verifiably gone."""
    reports = []
    state = {"running": True}
    monkeypatch.setattr(assist.AssistManager, "_close_quick_assist", lambda self: not state["running"])
    monkeypatch.setattr(assist.AssistManager, "_quick_assist_running", staticmethod(lambda: state["running"]))

    def broker(req):
        assert req["envelope"]["parameters"]["session_id"] == "s1"
        state["running"] = False
        return {"status": "succeeded"}

    m = assist.AssistManager(lambda j, r: reports.append(r), lambda *e: None, broker_call=broker)
    m.end({"job_id": "e1", "parameters": {"session_id": "s1"}})
    assert reports[-1]["status"] == "succeeded" and "closed by broker" in reports[-1]["detail"]

    state["running"] = True
    m2 = assist.AssistManager(lambda j, r: reports.append(r), lambda *e: None,
                              broker_call=lambda req: {"status": "needs_attention", "detail": "broker not elevated"})
    m2.end({"job_id": "e2", "parameters": {"session_id": "s2"}})
    assert reports[-1]["status"] == "needs_attention" and "still running" in reports[-1]["detail"]


def test_broker_accepts_signed_assist_end(signer, tmp_path):
    st = BrokerState(tmp_path / "b2")
    st.pin(DEVICE, "cmd-test", signer.pub)
    calls = []
    fake = {"assist.end": lambda p: calls.append(p) or Outcome("succeeded", "Quick Assist closed")}
    r = handle(st, {"envelope": _env(signer, "assist.end", {"session_id": str(uuid.uuid4())})}, actions=fake)
    assert r["status"] == "succeeded" and len(calls) == 1
    r = handle(st, {"envelope": _env(signer, "assist.start", {"session_id": str(uuid.uuid4()), "max_minutes": 5,
                                                              "require_consent": True, "consent_timeout_seconds": 60})},
               actions=fake)
    assert r["status"] == "rejected"  # the broker never starts sessions
