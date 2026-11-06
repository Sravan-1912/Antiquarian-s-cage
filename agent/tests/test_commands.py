from __future__ import annotations

import ast
import base64
import json
import secrets
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cage_agent.commands.executor import JobExecutor
from cage_agent.commands.validator import PinnedKey, Rejected, ReplayStore, canonical, verify_and_parse
from cage_agent.core.configuration import AgentConfig
from cage_agent.policies import ElevationRequired, Outcome
from cage_broker.core import BrokerState, handle

BACKEND = Path(__file__).resolve().parents[2] / "backend"
DEVICE = str(uuid.uuid4())
FW_CFG = {"profiles": ["domain", "private", "public"], "enforce": True}


class Signer:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = base64.b64encode(raw).decode()
        self.pinned = PinnedKey("cmd-test", self.pub)

    def envelope(self, command="policy.apply", device=DEVICE, version=1, cfg=None, expires_in=3600, **over):
        now = datetime.now(timezone.utc)
        env = {"v": 1, "job_id": str(uuid.uuid4()), "device_id": device, "command": command,
               "parameters": {"policy_id": "p1", "policy_name": "FW", "category": "firewall", "version": version,
                              "configuration": cfg if cfg is not None else dict(FW_CFG)},
               "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=expires_in)).isoformat(),
               "nonce": secrets.token_hex(16), "key_id": "cmd-test", **over}
        env["signature"] = base64.b64encode(self.key.sign(canonical(env))).decode()
        return env


@pytest.fixture()
def signer():
    return Signer()


def _verify(env, signer, tmp_path, **kw):
    return verify_and_parse(env, device_id=DEVICE, key=signer.pinned, replay=ReplayStore(tmp_path / "r.json"), **kw)


def test_valid_envelope_accepted_and_replay_blocked(signer, tmp_path):
    store = ReplayStore(tmp_path / "r.json")
    env = signer.envelope()
    verify_and_parse(env, device_id=DEVICE, key=signer.pinned, replay=store)
    with pytest.raises(Rejected, match="replay"):
        verify_and_parse(env, device_id=DEVICE, key=signer.pinned, replay=ReplayStore(tmp_path / "r.json"))


@pytest.mark.parametrize("mutate,msg", [
    (lambda e: e["parameters"].update(category="firewall", configuration={"profiles": []}), "signature"),
    (lambda e: e.update(command="shell.exec"), "allowlist"),
    (lambda e: e.update(extra="x"), "field set"),
])
def test_tampering_rejected(signer, tmp_path, mutate, msg):
    env = signer.envelope()
    mutate(env)
    with pytest.raises(Rejected, match=msg):
        _verify(env, signer, tmp_path)


def test_wrong_device_key_expiry_version_config(signer, tmp_path):
    with pytest.raises(Rejected, match="different device"):
        _verify(signer.envelope(device=str(uuid.uuid4())), signer, tmp_path)
    with pytest.raises(Rejected, match="signature"):
        _verify(signer.envelope(), Signer(), tmp_path)  # attacker key, same key id
    with pytest.raises(Rejected, match="expired"):
        _verify(signer.envelope(expires_in=-5), signer, tmp_path)
    with pytest.raises(Rejected, match="configuration rejected"):
        _verify(signer.envelope(cfg={"profiles": ["public"], "enforce": True, "disable": True}), signer, tmp_path)
    store = ReplayStore(tmp_path / "v.json")
    store.set_version("p1", 3)
    with pytest.raises(Rejected, match="stale policy version"):
        verify_and_parse(signer.envelope(version=2), device_id=DEVICE, key=signer.pinned, replay=store)


@pytest.mark.skipif(not BACKEND.exists(), reason="backend source not present")
def test_canonical_matches_backend():
    src = (BACKEND / "app" / "security" / "command_signing.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "canonical")
    ns: dict = {"json": json}
    exec(compile(ast.Module([fn], []), "command_signing.py", "exec"), ns)  # noqa: S102 — trusted repo source
    env = {"b": 1, "a": {"z": "é", "y": [1, 2]}, "signature": "zzz"}
    assert ns["canonical"](env) == canonical(env)


class FakeModule:
    def __init__(self, raise_elev=False):
        self.raise_elev = raise_elev
        self.removed_with = None

    def apply(self, cfg):
        if self.raise_elev:
            raise ElevationRequired("Access is denied")
        return Outcome("succeeded", "applied", {"profiles": {"public": False}, "changed": ["public"]}, {"public": True})

    def remove(self, previous):
        self.removed_with = previous
        return Outcome("succeeded", "restored")


def test_broker_rollback_uses_its_own_state_and_is_idempotent(signer, tmp_path):
    st = BrokerState(tmp_path / "broker")
    st.pin(DEVICE, "cmd-test", signer.pub)
    fake = FakeModule()
    env = signer.envelope()
    r1 = handle(st, {"envelope": env}, modules=lambda c: fake)
    assert r1["status"] == "succeeded"
    assert handle(st, {"envelope": env}, modules=lambda c: fake) == r1  # cached, not re-executed / replay-rejected
    # The agent tries to smuggle a forged previous_state: ignored, broker's stored state is used.
    rm = signer.envelope(command="policy.remove")
    handle(st, {"envelope": rm, "previous_state": {"registry": {"HKLM\\Evil\\x": {"value": 1}}}}, modules=lambda c: fake)
    assert fake.removed_with == {"profiles": {"public": False}, "changed": ["public"]}
    # Re-pinning to a different key is refused
    with pytest.raises(ValueError):
        st.pin(DEVICE, "cmd-other", "AAAA")


def test_broker_reports_elevation_and_rejections(signer, tmp_path):
    st = BrokerState(tmp_path / "b")
    st.pin(DEVICE, "cmd-test", signer.pub)
    r = handle(st, {"envelope": signer.envelope()}, modules=lambda c: FakeModule(raise_elev=True))
    assert r["status"] == "needs_attention" and "administrator" in r["detail"]
    r = handle(st, {"envelope": Signer().envelope()}, modules=lambda c: FakeModule())
    assert r["status"] == "rejected"


def test_executor_pins_key_and_handles_broker_outage(signer, tmp_path):
    cfg = AgentConfig(server_url="https://x", device_id=DEVICE)
    saved = []
    reports = {}
    ex = JobExecutor(tmp_path, cfg, lambda: saved.append(1), broker_call=lambda req: (_ for _ in ()).throw(OSError("down")))
    env = signer.envelope()
    revoked = signer.envelope()
    payload = {"jobs": [env, revoked], "revoked_job_ids": [revoked["job_id"]],
               "command_key": {"key_id": "cmd-test", "public_key": signer.pub}}
    assert ex.process(payload, lambda j, r: reports.__setitem__(j, r)) == 1
    assert cfg.extra["command_key_id"] == "cmd-test" and saved
    assert reports[env["job_id"]]["status"] == "needs_attention" and revoked["job_id"] not in reports
    # Key substitution by the server (or an attacker) after pinning → nothing processed
    other = Signer()
    bad = {"jobs": [other.envelope()], "command_key": {"key_id": "cmd-evil", "public_key": other.pub}}
    assert ex.process(bad, lambda j, r: reports.__setitem__(j, r)) == 0


@pytest.mark.skipif(sys.platform != "win32", reason="registry is Windows-only")
def test_registry_apply_and_exact_rollback():
    from cage_agent.policies import registry as reg
    path = r"HKCU\Software\AntiquariansCageTest\Sub"
    reg.write(path, "Existing", 7)
    prev = reg.apply_values([(path, "Existing", 9, "dword"), (path, "New", "x", "sz")])
    assert reg.read(path, "Existing")["value"] == 9 and reg.read(path, "New")["value"] == "x"
    reg.restore_values(prev)
    assert reg.read(path, "Existing")["value"] == 7 and reg.read(path, "New") == {"absent": True}
    import winreg
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\AntiquariansCageTest\Sub")
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\AntiquariansCageTest")

    # Keys created by apply (including missing parents) are removed again on rollback → exact original state
    deep = r"HKCU\Software\AntiquariansCageTest\A\B"
    prev = reg.apply_values([(deep, "X", 1, "dword"), (deep, "Y", "y", "sz")])
    assert reg.read(deep, "X")["value"] == 1
    reg.restore_values(prev)
    assert not reg._exists(r"HKCU\Software\AntiquariansCageTest")


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes are Windows-only")
def test_named_pipe_roundtrip():
    from cage_broker import pipe
    name = rf"\\.\pipe\CageTest-{uuid.uuid4().hex[:8]}"
    stop = threading.Event()
    t = threading.Thread(target=pipe.serve, args=(lambda r: {"echo": r}, [pipe.current_user_sid()], stop, name),
                         daemon=True)
    t.start()
    import time
    for _ in range(50):  # wait until the server thread has created the pipe instance
        try:
            reply = pipe.call({"hello": 1}, name, timeout_ms=200)
            break
        except pipe.BrokerUnavailable:
            time.sleep(0.05)
    assert reply["echo"] == {"hello": 1}
    stop.set()
    pipe.wake(name)
    with pytest.raises(pipe.BrokerUnavailable):
        pipe.call({"x": 1}, rf"\\.\pipe\CageTest-missing-{uuid.uuid4().hex[:6]}", timeout_ms=200)
