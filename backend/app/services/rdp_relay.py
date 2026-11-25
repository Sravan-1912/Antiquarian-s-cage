"""In-process relay that tunnels a Remote Desktop (RDP) TCP stream between an endpoint and an operator so it works
across any network, with no VPN and no inbound firewall rules on either side.

Both ends dial OUT to the backend over WebSocket (so NAT/firewalls don't matter):

    mstsc  <--TCP-->  operator helper  <--WS-->  backend relay  <--WS-->  endpoint agent  <--TCP-->  127.0.0.1:3389

The relay only ever copies bytes between the two authenticated sockets of one session; it never interprets RDP.

Authorisation is a short-lived, stateless HMAC token bound to (session_id, side): the endpoint token is handed to
the agent inside the signed `rdp.start` job; the operator token is minted by an authenticated REST call once the
operator proves it may reach that device. Pairing is per-process, so run a single backend instance (or sticky-route
the two WS paths of a session to the same instance).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import time
from dataclasses import dataclass, field

from app.core.config import get_settings

_SIDES = ("endpoint", "operator")


def _key() -> bytes:
    # A dedicated sub-key derived from the audit HMAC key; never reused as an encryption key.
    return hashlib.sha256(b"cage-rdp-relay|" + get_settings().audit_key_bytes).digest()


def mint_token(session_id: str, side: str, ttl_seconds: int = 600) -> str:
    assert side in _SIDES
    exp = int(time.time()) + ttl_seconds
    msg = f"{session_id}|{side}|{exp}".encode()
    sig = hmac.new(_key(), msg, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(msg + b"|" + sig).rstrip(b"=").decode()


def verify_token(token: str, session_id: str, side: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        body, sig = raw.rsplit(b"|", 1)
        sid, tside, exp = body.decode().split("|")
    except (ValueError, UnicodeDecodeError):
        return False
    expected = hmac.new(_key(), body, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(sig, expected):
        return False
    return sid == session_id and tside == side and int(exp) >= int(time.time())


@dataclass
class _Slot:
    endpoint: object | None = None
    operator: object | None = None
    paired: asyncio.Event = field(default_factory=asyncio.Event)


class RelayHub:
    def __init__(self) -> None:
        self._slots: dict[str, _Slot] = {}
        self._lock = asyncio.Lock()

    async def join(self, session_id: str, side: str, ws) -> None:
        """Attach one side's WebSocket; once both sides are present, copy bytes from this side to the other until
        either closes, then tear the session's pairing down (a later reconnect starts a fresh pairing)."""
        async with self._lock:
            slot = self._slots.setdefault(session_id, _Slot())
            setattr(slot, side, ws)
            if slot.endpoint is not None and slot.operator is not None:
                slot.paired.set()
        try:
            await asyncio.wait_for(slot.paired.wait(), timeout=120)
        except asyncio.TimeoutError:
            await self._drop(session_id)
            return
        other = slot.operator if side == "endpoint" else slot.endpoint
        if other is None:
            return
        try:
            while True:
                data = await ws.receive_bytes()
                await other.send_bytes(data)
        except Exception:  # noqa: BLE001 — any disconnect/transport error ends the pump
            pass
        finally:
            await self._drop(session_id)

    async def _drop(self, session_id: str) -> None:
        async with self._lock:
            slot = self._slots.pop(session_id, None)
        if not slot:
            return
        for ws in (slot.endpoint, slot.operator):
            if ws is not None:
                try:
                    await ws.close()
                except Exception:  # noqa: BLE001
                    pass


hub = RelayHub()
