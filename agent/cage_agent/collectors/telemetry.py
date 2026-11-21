"""Lightweight EDR telemetry: detect newly-created processes by polling (no ETW/eBPF driver), and emit
`process_created` events for the server-side detection engine.

Polling catches processes that are still alive at poll time; very short-lived processes between polls can be missed —
a kernel ETW (Windows) / eBPF (Linux) collector is the richer follow-up. This version is dependency-light (psutil only),
cross-platform, and safe (read-only).
"""
from __future__ import annotations

import logging

import psutil

log = logging.getLogger("cage_agent.telemetry")
_MAX_EVENTS = 200


class ProcessTelemetry:
    def __init__(self) -> None:
        self._seen: set[int] = set()
        self.primed = False

    def _snapshot(self) -> dict[int, dict]:
        out: dict[int, dict] = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline", "exe", "create_time"]):
            try:
                out[p.info["pid"]] = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out

    def collect(self) -> list[dict]:
        """Return `process_created` events for processes new since the last call. The first call primes and returns []."""
        current = self._snapshot()
        if not self.primed:
            self._seen = set(current)
            self.primed = True
            return []
        new_pids = [pid for pid in current if pid not in self._seen]
        events: list[dict] = []
        for pid in new_pids:
            info = current[pid]
            parent = current.get(info.get("ppid"))
            events.append({"type": "process_created", "data": {
                "name": (info.get("name") or "")[:128],
                "pid": pid, "ppid": info.get("ppid"),
                "cmdline": " ".join(info.get("cmdline") or [])[:1000],
                "username": (info.get("username") or "")[:128],
                "exe": (info.get("exe") or "")[:260],
                "parent": {"name": (parent.get("name") if parent else "") or ""},
            }})
            if len(events) >= _MAX_EVENTS:
                break
        self._seen = set(current)
        return events
