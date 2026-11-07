from collections import namedtuple

import psutil

from cage_agent.core import agent

Io = namedtuple("Io", "bytes_sent bytes_recv")


def test_counts_real_adapters_and_skips_loopback(monkeypatch):
    fake = {"Local Area Connection": Io(10, 20), "Wi-Fi": Io(1, 2),
            "Loopback Pseudo-Interface 1": Io(1000, 1000), "lo": Io(5, 5)}
    monkeypatch.setattr(psutil, "net_io_counters", lambda pernic=True: fake)
    assert agent.network_counters() == {"net_bytes_sent": 11, "net_bytes_recv": 22}


def test_missing_counters_are_omitted_not_zero(monkeypatch):
    def boom(pernic=True):
        raise OSError("unavailable")
    monkeypatch.setattr(psutil, "net_io_counters", boom)
    assert agent.network_counters() == {}
