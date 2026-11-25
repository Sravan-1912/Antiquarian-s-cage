import json
import sys
import time

import pytest

from cage_agent.core.communication import AuthRejected, ServerError
from cage_agent.unlock import PIPE_NAME, UnlockHandler, UnlockRelay


class FakeServer:
    def __init__(self):
        self.calls = []
        self.state = "pending"

    def send(self, path, payload):
        self.calls.append((path, payload))
        if path.endswith("/start"):
            if payload["sid"] == "S-1-5-21-unassigned":
                raise ServerError('409: {"code": "unassigned", "message": "This device is not assigned to anyone"}')
            return {"request_id": "r1", "number": 42, "secret": "s3cret", "expires_at": "t", "approver": "a@x"}
        assert payload["secret"] == "s3cret"
        return {"status": self.state, **({"key": "K"} if self.state == "approved" else {})}


def test_secret_never_leaves_relay_and_is_single_use():
    srv = FakeServer()
    h = UnlockHandler(srv.send)
    out = h.handle({"op": "start", "kind": "unlock", "windows_user": "PC\\ada", "sid": "S-1-5-21-1"})
    assert out == {"ok": True, "request_id": "r1", "number": 42, "expires_at": "t", "approver": "a@x"}
    assert "secret" not in json.dumps(out)
    assert h.handle({"op": "status", "request_id": "r1"})["status"] == "pending"
    srv.state = "approved"
    assert h.handle({"op": "status", "request_id": "r1"}) == {"ok": True, "status": "approved", "key": "K"}
    assert h.handle({"op": "status", "request_id": "r1"})["code"] == "unknown"  # terminal -> forgotten


def test_errors_are_explained_not_swallowed():
    h = UnlockHandler(FakeServer().send)
    out = h.handle({"op": "start", "kind": "unlock", "windows_user": "PC\\ada", "sid": "S-1-5-21-unassigned"})
    assert out == {"ok": False, "code": "unassigned", "message": "This device is not assigned to anyone"}

    def offline(path, payload):
        raise ServerError("giving up on /agent/v1/unlock/start after 3 attempts: ConnectError")
    assert UnlockHandler(offline).handle({"op": "start", "kind": "unlock", "windows_user": "u", "sid": "S-1-5-21-1"})["code"] == "offline"

    def revoked(path, payload):
        raise AuthRejected("device revoked")
    assert UnlockHandler(revoked).handle({"op": "start", "kind": "unlock", "windows_user": "u", "sid": "S-1-5-21-1"})["code"] == "device_rejected"
    assert h.handle({"op": "start", "kind": "enroll", "windows_user": "u", "sid": "S-1-5-21-1"})["code"] == "bad_request"
    assert h.handle({"op": "nope"})["code"] == "bad_request"


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes")
def test_real_pipe_round_trip_dev_mode():
    from cage_broker import pipe
    relay = UnlockRelay(UnlockHandler(FakeServer().send), dev_allow_current_user=True)
    relay.start()
    try:
        for _ in range(50):
            try:
                out = pipe.call({"op": "start", "kind": "unlock", "windows_user": "PC\\ada", "sid": "S-1-5-21-1"}, PIPE_NAME, 200)
                break
            except pipe.BrokerUnavailable:
                time.sleep(0.05)
        assert out["ok"] and out["number"] == 42
    finally:
        relay.close()


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes")
def test_non_system_client_rejected_outside_dev_mode():
    """Production mode: only SYSTEM (LogonUI) may use the relay. The DACL already blocks other users; a
    same-account caller that slips past it (e.g. the agent's own account) is refused by the token check."""
    from cage_broker import pipe
    srv = FakeServer()
    relay = UnlockRelay(UnlockHandler(srv.send), dev_allow_current_user=False)
    relay.start()
    try:
        out = None
        for _ in range(50):
            try:
                out = pipe.call({"op": "start", "kind": "unlock", "windows_user": "u", "sid": "S-1-5-21-1"}, PIPE_NAME, 200)
                break
            except pipe.BrokerUnavailable:
                time.sleep(0.05)
        # Either the DACL refuses the connection (BrokerUnavailable, out stays None) or the token check refuses it.
        assert out is None or out == {"ok": False, "code": "forbidden", "message": "Not allowed."}
        assert srv.calls == []  # nothing ever reached the server
    finally:
        relay.stop.set()
