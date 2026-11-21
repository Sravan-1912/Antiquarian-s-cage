"""Aggregate the signed-in user's browser history into per-domain visit counts (read-only, best-effort).

Reports only aggregated domain + visit counts (never full URLs or page titles) for the fleet "Top websites" view.
Reads Chromium-family (Chrome/Edge/Brave/Chromium) and Firefox history databases; because browsers hold the file
open, each DB is copied to a temp path and opened read-only. Never raises — any failure yields fewer/zero domains.
"""
from __future__ import annotations

import glob
import os
import sqlite3
import sys
import tempfile
from urllib.parse import urlparse


def _domain(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""
    return host[4:] if host.startswith("www.") else host


def _read_db(path: str, query: str, counts: dict[str, int]) -> None:
    if not os.path.isfile(path):
        return
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        with open(path, "rb") as src, open(tmp, "wb") as dst:
            dst.write(src.read())
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=5)
        try:
            for url, visits in con.execute(query):
                d = _domain(url or "")
                if d and "." in d:
                    counts[d] = counts.get(d, 0) + int(visits or 0)
        finally:
            con.close()
    except Exception:  # noqa: BLE001 — locked / missing / schema drift: skip this profile
        pass
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _chromium_roots() -> list[str]:
    if sys.platform == "win32":
        la = os.environ.get("LOCALAPPDATA", "")
        return [os.path.join(la, *p) for p in (
            ("Google", "Chrome", "User Data"), ("Microsoft", "Edge", "User Data"),
            ("BraveSoftware", "Brave-Browser", "User Data"), ("Chromium", "User Data"),
        )]
    home = os.path.expanduser("~")
    return [os.path.join(home, ".config", p) for p in (
        "google-chrome", "microsoft-edge", "chromium", "BraveSoftware/Brave-Browser",
    )]


def _firefox_roots() -> list[str]:
    if sys.platform == "win32":
        return [os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")]
    return [os.path.join(os.path.expanduser("~"), ".mozilla", "firefox")]


_CHROMIUM_Q = "SELECT url, visit_count FROM urls WHERE visit_count > 0"
_FIREFOX_Q = "SELECT url, visit_count FROM moz_places WHERE visit_count > 0"


def collect(limit: int = 50) -> list[dict]:
    """Return [{domain, visits}] aggregated across the user's browsers, most-visited first (top `limit`)."""
    counts: dict[str, int] = {}
    try:
        for root in _chromium_roots():
            for hist in glob.glob(os.path.join(root, "*", "History")):
                _read_db(hist, _CHROMIUM_Q, counts)
        for root in _firefox_roots():
            for places in glob.glob(os.path.join(root, "*", "places.sqlite")):
                _read_db(places, _FIREFOX_Q, counts)
    except Exception:  # noqa: BLE001
        pass
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"domain": d[:255], "visits": v} for d, v in top]
