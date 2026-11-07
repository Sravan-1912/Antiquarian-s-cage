"""Query-count scaling test: every list/summary endpoint must use a bounded number of SQL statements, independent of
fleet size (catches N+1 queries), and stay within a latency budget on a realistic fleet.

Run on PostgreSQL for meaningful timings:  pytest tests/test_performance.py -s
"""
import os
import random
import time
import uuid
from datetime import timedelta

from sqlalchemy import event

from tests.conftest import bootstrap_admin, login

CHECKS = ["firewall", "antivirus", "bitlocker", "secure_boot", "screen_lock", "os_updates", "password_policy",
          "guest_account", "smbv1", "rdp", "credential_guard", "audit_policy"]
SKIP_PREFIXES = ("/api/v1/auth/", "/api/v1/oidc/", "/api/v1/agent/", "/.well-known", "/api/v1/health",
                 "/api/v1/audit/anchors/public-key")
LATENCY_BUDGET_MS = 800


def _seed(n: int) -> None:
    from app.core.database import session_factory, utcnow
    from app.models import (
        ComplianceEvaluation, ComplianceResult, Device, DeviceEvent, DeviceHeartbeat, DeviceInventory, Employee,
        Organization, SecurityAlert,
    )
    from sqlalchemy import select
    rnd = random.Random(n)
    now = utcnow()
    with session_factory()() as db:
        org = db.scalar(select(Organization.id))
        for i in range(n):
            emp = Employee(id=uuid.uuid4(), organization_id=org, employee_number=f"P-{n}-{i}",
                           full_name=f"Perf Person {i}", email=f"perf{n}-{i}@example.com",
                           department=rnd.choice(["Ops", "Eng", "Sales", "HR"]), job_title="Staff")
            dev = Device(id=uuid.uuid4(), organization_id=org, employee_id=emp.id, display_name=f"PERF-{n}-{i}",
                         hostname=f"perf-{n}-{i}", os_name="Windows 11 Pro", os_version="10.0.26100",
                         agent_version="0.4.0", compliance_state=rnd.choice(["compliant", "non_compliant", "unknown"]),
                         last_heartbeat_at=now - timedelta(seconds=rnd.randint(0, 7200)), last_inventory_at=now)
            db.add(emp)
            db.flush()
            db.add(dev)
            db.flush()
            inv = DeviceInventory(id=uuid.uuid4(), device_id=dev.id, memory_bytes=16 << 30,
                                  security={"firewall": "on"}, os={"name": "Windows 11 Pro"})
            db.add(inv)
            db.flush()
            ev = ComplianceEvaluation(id=uuid.uuid4(), organization_id=org, device_id=dev.id, inventory_id=inv.id,
                                      state=dev.compliance_state, score=rnd.randint(40, 100), passed=8, failed=2,
                                      unknown=1, not_applicable=1)
            db.add(ev)
            db.flush()
            db.add_all([ComplianceResult(id=uuid.uuid4(), evaluation_id=ev.id, device_id=dev.id, check_key=c,
                                         result=rnd.choice(["PASS", "FAIL", "UNKNOWN"]), severity="high")
                        for c in CHECKS])
            db.add_all([DeviceHeartbeat(device_id=dev.id, received_at=now - timedelta(minutes=k)) for k in range(3)])
            db.add(DeviceEvent(id=uuid.uuid4(), device_id=dev.id, kind="enrolled"))
            if i % 3 == 0:
                db.add(SecurityAlert(id=uuid.uuid4(), organization_id=org, rule_key="firewall_disabled",
                                     kind="configuration", title=f"Firewall disabled on PERF-{i}", description="perf",
                                     severity="high", device_id=dev.id, employee_id=emp.id,
                                     dedup_key=f"perf-{n}-{i}", evidence={}))
        db.commit()


def _endpoints(app) -> list[str]:
    out = [path for path, ops in app.openapi()["paths"].items()
           if "get" in ops and "{" not in path and path.startswith("/api/v1/") and not path.startswith(SKIP_PREFIXES)]
    assert len(out) > 20, f"route discovery found only {out}"
    return sorted(out)


def _measure(client, paths: list[str]) -> dict[str, tuple[int, float, int]]:
    from app.core.database import get_engine
    eng = get_engine()
    counter = {"n": 0}

    debug = os.environ.get("PERF_DEBUG_PATH")  # print the SQL of one endpoint to find the repeated query

    def on_exec(_conn, _cur, statement, *_a, **_k):
        counter["n"] += 1
        if debug and counter.get("path") == debug:
            print("   SQL:", " ".join(statement.split())[:160])

    event.listen(eng, "before_cursor_execute", on_exec)
    res = {}
    try:
        for p in paths:
            counter["n"] = 0
            counter["path"] = p
            t = time.perf_counter()
            r = client.get(p)
            res[p] = (counter["n"], (time.perf_counter() - t) * 1000, r.status_code)
    finally:
        event.remove(eng, "before_cursor_execute", on_exec)
    return res


def test_query_counts_do_not_grow_with_fleet(client, outbox):
    bootstrap_admin(client, outbox)
    login(client, "root@example.com")
    paths = _endpoints(client.app)
    from app.services import reports
    paths += [f"/api/v1/reports/{k}?format=csv" for k in reports.REPORTS]
    _seed(10)
    small = _measure(client, paths)
    _seed(300)
    large = _measure(client, paths)

    print(f"\n{'endpoint':60} {'q@10':>5} {'q@310':>6} {'ms@310':>8} status")
    grew, slow = [], []
    for p in paths:
        qs, _, _ = small[p]
        ql, ms, st = large[p]
        print(f"{p:60} {qs:5d} {ql:6d} {ms:8.1f} {st}")
        if st == 200 and ql > qs + 2:  # small slack for paging/first-row branches
            grew.append(f"{p}: {qs} -> {ql} queries")
        if st == 200 and ms > LATENCY_BUDGET_MS:
            slow.append(f"{p}: {ms:.0f} ms")
    assert not grew, "query count grows with fleet size (N+1):\n" + "\n".join(grew)
    assert not slow, "over latency budget:\n" + "\n".join(slow)
