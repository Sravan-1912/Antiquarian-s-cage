"""SIEM / webhook egress: config (write-only token), the test endpoint, and durable outbox delivery."""
from __future__ import annotations

import uuid
from unittest import mock

from sqlalchemy import select

from app.core import database
from app.models import Organization, SiemDelivery
from app.services import siem
from tests.conftest import bootstrap_admin, csrf, login


def _admin(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")


def test_siem_config_token_is_write_only(client, outbox):
    _admin(client, outbox)
    r = client.put("/api/v1/siem", json={"url": "https://siem.example/in", "token": "Bearer xyz",
                                         "min_severity": "high"}, headers=csrf(client))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_token"] and body["min_severity"] == "high" and "token" not in body
    g = client.get("/api/v1/siem").json()
    assert g["url"] == "https://siem.example/in" and g["has_token"] and "token" not in g


def test_siem_test_endpoint_posts(client, outbox):
    _admin(client, outbox)
    client.put("/api/v1/siem", json={"url": "https://siem.example/in", "token": "t"}, headers=csrf(client))
    with mock.patch("app.services.siem.httpx.post") as p:
        p.return_value = mock.Mock(raise_for_status=lambda: None)
        assert client.post("/api/v1/siem/test", headers=csrf(client)).json()["ok"] is True
        p.assert_called_once()
        assert p.call_args.kwargs["headers"]["Authorization"] == "t"  # token used verbatim


def test_siem_outbox_delivers_and_backs_off(client, outbox):
    _admin(client, outbox)
    client.put("/api/v1/siem", json={"url": "https://siem.example/in", "token": "Splunk k",
                                     "min_severity": "low"}, headers=csrf(client))
    s = database._SessionLocal()
    try:
        org = s.scalar(select(Organization.id))
        s.add(SiemDelivery(id=uuid.uuid4(), organization_id=org, payload={"type": "security_alert", "severity": "high"}))
        s.commit()
        with mock.patch("app.services.siem.httpx.post") as p:
            p.return_value = mock.Mock(raise_for_status=lambda: None)
            assert siem.deliver_outbox(s) == (1, 0)
        # Failure path: delivery stays pending with a backoff, not dropped.
        d = SiemDelivery(id=uuid.uuid4(), organization_id=org, payload={"type": "x"})
        s.add(d)
        s.commit()
        with mock.patch("app.services.siem.httpx.post", side_effect=RuntimeError("siem down")):
            assert siem.deliver_outbox(s) == (0, 1)
        s.refresh(d)
        assert d.status == "pending" and d.attempts == 1 and "siem down" in d.last_error
    finally:
        s.close()
