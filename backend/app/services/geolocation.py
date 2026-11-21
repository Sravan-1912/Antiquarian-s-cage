"""Resolve an endpoint's position from the Wi-Fi access points it reported, or fall back to IP geolocation.

Accuracy is never overstated: every result records its `source` ("wifi" | "ip" | "none") and an `accuracy_m` radius.
 - Wi-Fi positioning (via the Google Geolocation API, when `google_geolocation_api_key` is set) is the accurate tier
   (~20–100 m in populated areas).
 - Otherwise we use free IP-based geolocation (ip-api.com), which is city-level and wrong behind a VPN.
Both are best-effort: a lookup failure leaves the previous location untouched.
"""
from __future__ import annotations

import ipaddress
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utcnow
from app.models import Device, DeviceLocation

log = logging.getLogger("app.geolocation")

_GOOGLE_URL = "https://www.googleapis.com/geolocation/v1/geolocate"
_IPAPI_URL = "http://ip-api.com/json/{ip}"


def _is_public(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def _ip_lookup(ip: str) -> dict | None:
    try:
        r = httpx.get(_IPAPI_URL.format(ip=ip), params={"fields": "status,country,regionName,city,lat,lon"}, timeout=8.0)
        d = r.json()
        if d.get("status") == "success":
            return {"lat": d.get("lat"), "lon": d.get("lon"), "city": d.get("city"),
                    "region": d.get("regionName"), "country": d.get("country")}
    except Exception as exc:  # noqa: BLE001
        log.debug("ip geolocation failed: %s", exc)
    return None


def _wifi_lookup(api_key: str, aps: list[dict]) -> dict | None:
    points = [
        {k: v for k, v in (
            ("macAddress", ap.get("mac")),
            ("signalStrength", ap.get("signal_dbm")),
            ("channel", ap.get("channel")),
        ) if v is not None}
        for ap in aps if ap.get("mac")
    ]
    if len(points) < 2:  # Google needs ≥2 APs for a useful fix
        return None
    try:
        r = httpx.post(_GOOGLE_URL, params={"key": api_key}, json={"considerIp": False, "wifiAccessPoints": points}, timeout=8.0)
        if r.status_code != 200:
            log.debug("wifi geolocation HTTP %s: %s", r.status_code, r.text[:200])
            return None
        d = r.json()
        loc = d.get("location") or {}
        if loc.get("lat") is not None and loc.get("lng") is not None:
            return {"lat": loc["lat"], "lon": loc["lng"], "accuracy_m": int(d.get("accuracy") or 0) or None}
    except Exception as exc:  # noqa: BLE001
        log.debug("wifi geolocation failed: %s", exc)
    return None


def resolve_and_store(db: Session, device: Device, aps: list[dict], ip: str | None) -> DeviceLocation | None:
    """Resolve the best-available position for `device` and upsert its single location row."""
    settings = get_settings()
    source, lat, lon, accuracy_m = "none", None, None, None
    city = region = country = None

    # City/region label + a coarse IP position (also the fallback when Wi-Fi isn't available).
    if _is_public(ip):
        ipinfo = _ip_lookup(ip)
        if ipinfo:
            lat, lon = ipinfo["lat"], ipinfo["lon"]
            city, region, country = ipinfo["city"], ipinfo["region"], ipinfo["country"]
            accuracy_m = 25_000  # IP geolocation is city-level
            source = "ip"

    # Accurate tier: Wi-Fi positioning overrides the coordinates (keeps the IP-derived city label).
    if settings.google_geolocation_api_key and aps:
        wifi = _wifi_lookup(settings.google_geolocation_api_key, aps)
        if wifi:
            lat, lon = wifi["lat"], wifi["lon"]
            accuracy_m = wifi["accuracy_m"]
            source = "wifi"

    if source == "none":
        return None  # nothing usable; leave any previous location in place

    row = db.scalar(select(DeviceLocation).where(DeviceLocation.device_id == device.id))
    if row is None:
        row = DeviceLocation(device_id=device.id)
        db.add(row)
    row.source = source
    row.latitude, row.longitude, row.accuracy_m = lat, lon, accuracy_m
    row.city, row.region, row.country = city, region, country
    row.ip = ip
    row.ap_count = len(aps)
    row.resolved_at = utcnow()
    db.commit()
    return row
