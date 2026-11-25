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
import math

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
    prev = (row.latitude, row.longitude, row.resolved_at) if row and row.latitude is not None else None
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
    try:
        _geo_security(db, device, prev, lat, lon, country)
    except Exception as exc:  # noqa: BLE001 — never fail location ingest on a detection error
        log.debug("geo-security checks skipped: %s", exc)
    return row


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def _geo_security(db: Session, device: Device, prev, lat, lon, country) -> None:
    """Evaluate geo-fencing + impossible-travel against the org's GeoSecurityPolicy (best-effort)."""
    from app.models import GeoSecurityPolicy
    from app.services import alerts

    policy = db.scalar(select(GeoSecurityPolicy).where(GeoSecurityPolicy.organization_id == device.organization_id))
    if policy is None:
        return
    org_id = device.organization_id

    # Impossible travel: distance / elapsed time implies a speed no aircraft could manage.
    if policy.impossible_travel and prev and lat is not None and lon is not None:
        plat, plon, pt = prev
        hours = max((utcnow() - pt).total_seconds() / 3600.0, 1e-6)
        km = _haversine_km(plat, plon, lat, lon)
        kmh = km / hours
        if km > 500 and kmh > 900:
            alerts.raise_alert(
                db, org_id, "impossible_travel", severity="high",
                title=f"Impossible travel for {device.hostname}",
                description=f"{device.hostname} moved {km:.0f} km in {hours:.1f} h (~{kmh:.0f} km/h) between location reports.",
                dedup_key=f"impossible_travel:{device.id}",
                device_id=device.id, evidence={"km": round(km), "hours": round(hours, 2), "kmh": round(kmh),
                                               "from": [round(plat, 3), round(plon, 3)], "to": [round(lat, 3), round(lon, 3)]})

    # Geo-fence: the endpoint resolved outside the allowed countries.
    if policy.geofence_enabled and policy.allowed_countries and country and country not in policy.allowed_countries:
        alerts.raise_alert(
            db, org_id, "geofence_violation", severity="high",
            title=f"{device.hostname} is outside allowed regions",
            description=f"{device.hostname} resolved to {country}, which is not in the allowed list "
                        f"({', '.join(policy.allowed_countries)}).",
            dedup_key=f"geofence:{device.id}:{country}",
            device_id=device.id, evidence={"country": country, "allowed": policy.allowed_countries})
        if policy.on_violation == "isolate":
            try:
                from app.services import audit, remote
                remote.create_action(db, device, "device.isolate", {},
                                     reason=f"Automatic geo-fence isolation ({country} not allowed)",
                                     actor=audit.Actor(type="system", user_id=None, label="geo-fence"))
            except Exception as exc:  # noqa: BLE001 — isolation is best-effort; the alert already fired
                log.warning("geo-fence auto-isolate failed for %s: %s", device.id, exc)
