"""Network usage is derived from cumulative agent counters: deltas only, reboot-safe, never invented."""
import uuid
from datetime import timedelta

from tests.conftest import bootstrap_admin, login


def _device(db, org, name):
    from app.models import Device
    d = Device(id=uuid.uuid4(), organization_id=org, display_name=name, hostname=name.lower())
    db.add(d)
    db.flush()
    return d


def _hb(db, dev, minutes_ago, sent, recv):
    from app.core.database import utcnow
    from app.models import DeviceHeartbeat
    db.add(DeviceHeartbeat(device_id=dev.id, received_at=utcnow() - timedelta(minutes=minutes_ago),
                           net_bytes_sent=sent, net_bytes_recv=recv))


def test_usage_sums_deltas_and_survives_reboot(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    from sqlalchemy import select

    from app.core.database import session_factory
    from app.models import Organization
    from app.services.devices import network_usage
    with session_factory()() as db:
        org = db.scalar(select(Organization.id))
        a, b, c = _device(db, org, "A"), _device(db, org, "B"), _device(db, org, "C")
        # A: baseline 1000/5000, +100/+500, then reboot (counters reset) to 40/60, then +10/+20
        for m, s, r in [(50, 1000, 5000), (40, 1100, 5500), (30, 40, 60), (20, 50, 80)]:
            _hb(db, a, m, s, r)
        # B: older than the window (ignored) + one heartbeat inside: baseline only -> not reporting yet
        _hb(db, b, 60 * 30, 1, 1)
        _hb(db, b, 10, 999, 999)
        # C: agent without counters -> not reporting at all
        from app.core.database import utcnow
        from app.models import DeviceHeartbeat
        db.add(DeviceHeartbeat(device_id=c.id, received_at=utcnow()))
        db.commit()
        u = network_usage(db, org, 24)
    assert u["per_device"][str(a.id)] == {"sent": 100 + 40 + 10, "received": 500 + 60 + 20}
    assert str(b.id) not in u["per_device"]  # one reading in the window = baseline only, not "0 bytes"
    assert str(c.id) not in u["per_device"]
    assert u["devices_reporting"] == 1 and u["bytes_sent"] == 150 and u["bytes_received"] == 580

    dash = client.get("/api/v1/dashboard/summary").json()
    net = dash["endpoints"]["network"]
    assert net["bytes_received"] == 580 and net["devices_reporting"] == 1 and "per_device" not in net
    assert set(dash["endpoints"]["last_contact"]) == {"online", "under_1h", "1h_24h", "1d_7d", "over_7d", "never"}
    assert dash["administrators"]["online"] >= 1  # this test's own live session
    assert client.get(f"/api/v1/devices/{a.id}/network").json()["bytes_sent"] == 150


def test_heartbeat_rejects_negative_counters():
    import pytest
    from pydantic import ValidationError

    from app.schemas.endpoints import HeartbeatRequest
    HeartbeatRequest(agent_version="0.5.0", net_bytes_sent=1, net_bytes_recv=2)
    with pytest.raises(ValidationError):
        HeartbeatRequest(agent_version="0.5.0", net_bytes_sent=-1)
