"""Unattended Remote Desktop session on the endpoint, tunnelled so it works across any network (no VPN).

rdp.start → show the mandatory on-screen banner (fail closed if there is no interactive session) → ask the privileged
            broker to enable native Windows RDP + open the local firewall → open an OUTBOUND relay tunnel to the
            backend and bridge it to 127.0.0.1:3389 → report that the session is active.
rdp.end   → stop the tunnel, close the banner, ask the broker to disable RDP again.

The tunnel means neither side needs an inbound hole: the endpoint and the operator both dial out to the backend, which
copies bytes between them. There is deliberately no "silent" mode — RDP is enabled only while the banner is on screen,
shown first; if the banner cannot be shown (Windows agent in session 0, or no active graphical session on Linux) the
session is refused.

On Linux the host is xrdp instead of native Windows RDP, and the root agent enables it directly (there is no separate
broker); the banner is launched into the logged-in desktop user's session. Everything else — the relay tunnel to
127.0.0.1:3389 and the operator's mstsc — is identical to Windows.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from cage_agent.remote.assist import _helper_cmd as _assist_helper_cmd, _interactive

log = logging.getLogger("cage_agent.rdp")
LOCAL_RDP = ("127.0.0.1", 3389)
_IS_WIN = sys.platform == "win32"
# An E2E-capable operator sends this magic + its X25519 public key as its first frame; a plaintext operator sends raw
# RDP bytes (which begin 0x03 0x00 — a TPKT header — never this magic), so the two are unambiguous and plaintext still
# works unchanged. See remote/e2e.py.
E2E_MAGIC = b"CAGEE2E1"


def _banner_cmd(p: dict) -> list[str]:
    return [*_assist_helper_cmd("indicator", p), "--kind", "rdp"]


def _linux_gui_session() -> tuple[str, str, str] | None:
    """(user, DISPLAY, XAUTHORITY) of the active graphical seat, or None when there is no graphical session to show
    the banner in — in which case RDP is refused (fail closed, exactly like the Windows session-0 case)."""
    try:
        out = subprocess.run(["loginctl", "list-sessions", "--no-legend"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            info = subprocess.run(["loginctl", "show-session", parts[0], "-p", "Active", "-p", "Type", "-p", "Name",
                                  "-p", "Display"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        props = dict(kv.split("=", 1) for kv in info.splitlines() if "=" in kv)
        if props.get("Active") == "yes" and props.get("Type") in ("x11", "wayland") and props.get("Name"):
            user = props["Name"]
            return user, (props.get("Display") or ":0"), f"/home/{user}/.Xauthority"
    return None


def _linux_banner_cmd(p: dict, gui: tuple[str, str, str]) -> list[str]:
    # The agent runs as root; launch the banner as the logged-in desktop user, into their display.
    user, display, xauth = gui
    return ["sudo", "-u", user, "env", f"DISPLAY={display}", f"XAUTHORITY={xauth}", *_banner_cmd(p)]


# --------------------------------------------------------------------------------------- relay tunnel
def _ws_url(server_url: str, session_id: str, token: str) -> str:
    base = server_url.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")
    return f"{base}/agent/v1/rdp/tunnel?session={session_id}&token={token}"


def run_tunnel(server_url: str, ca_bundle: str | None, session_id: str, token: str, stop: threading.Event,
               device_sign: Callable[[bytes], bytes] | None = None) -> None:
    """Keep an outbound relay tunnel to the backend while the session lasts, reconnecting between operator sessions.
    `device_sign` (ECDSA over bytes with the device key) enables the end-to-end encrypted path when the operator asks."""
    url = _ws_url(server_url, session_id, token)
    log.info("rdp tunnel: starting, dialing relay at %s", url.split("?")[0])
    ctx = None
    if url.startswith("wss://"):
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    try:
        asyncio.run(_tunnel_main(url, ctx, stop, device_sign))
    except Exception as exc:  # noqa: BLE001 — tunnel is best-effort; the session/banner own the lifecycle
        log.warning("rdp tunnel stopped: %s", exc)


async def _tunnel_main(url: str, ctx: ssl.SSLContext | None, stop: threading.Event,
                       device_sign: Callable[[bytes], bytes] | None = None) -> None:
    import websockets
    while not stop.is_set():
        try:
            async with websockets.connect(url, ssl=ctx, max_size=None, open_timeout=20,
                                          ping_interval=20, ping_timeout=20, close_timeout=10) as ws:
                log.info("rdp tunnel: relay WebSocket connected; waiting for the operator")
                await _bridge_once(ws, stop, device_sign)
        except Exception as exc:  # noqa: BLE001
            log.warning("rdp tunnel: relay connection failed (%s: %s); retrying", exc.__class__.__name__, exc)
        if not stop.is_set():
            await asyncio.sleep(1)


async def _bridge_once(ws, stop: threading.Event, device_sign: Callable[[bytes], bytes] | None = None) -> None:
    # The operator speaks first: either an E2E HELLO (magic + X25519 key) or raw RDP bytes (mstsc's TPKT header).
    try:
        first = await asyncio.wait_for(ws.recv(), timeout=110)
    except asyncio.TimeoutError:
        log.info("rdp tunnel: no operator connected within 110s; reconnecting")
        return
    if stop.is_set():
        return
    log.info("rdp tunnel: operator connected (%d bytes); bridging to local RDP", len(first) if first else 0)
    first = first.encode() if isinstance(first, str) else first
    session = None
    if device_sign is not None and first.startswith(E2E_MAGIC):
        from cage_agent.remote import e2e
        try:
            auth, session = e2e.respond(first[len(E2E_MAGIC):], device_sign)
        except e2e.E2EError as exc:
            log.warning("e2e handshake rejected: %s", exc)
            return
        await ws.send(auth)
        first = None  # the operator's RDP bytes now arrive as encrypted frames
    loop = asyncio.get_event_loop()
    try:
        sock = await loop.run_in_executor(None, _connect_local_rdp)
    except OSError as exc:
        log.warning("rdp tunnel: cannot reach local Remote Desktop (127.0.0.1:3389): %s", exc)
        return
    if sock is None:
        log.warning("rdp tunnel: local Remote Desktop (127.0.0.1:3389) not reachable (no listener?)")
        return
    log.info("rdp tunnel: bridging operator <-> 127.0.0.1:3389 (session live)")
    try:
        if first:
            await loop.sock_sendall(sock, first)
        t1 = asyncio.create_task(_ws_to_sock(ws, sock, loop, session))
        t2 = asyncio.create_task(_sock_to_ws(ws, sock, loop, session))
        _done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        # Drain both tasks so a closed-connection exception is never left "unretrieved" (which spams the log and
        # looked like a crash). One side ending just means this operator session closed; the tunnel reconnects.
        await asyncio.gather(t1, t2, return_exceptions=True)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _connect_local_rdp() -> socket.socket | None:
    s = socket.create_connection(LOCAL_RDP, timeout=10)
    s.setblocking(False)
    return s


async def _ws_to_sock(ws, sock, loop, session=None) -> None:
    # Operator → endpoint. End cleanly on any close/decrypt error; the outer loop reconnects for the next session.
    try:
        async for msg in ws:
            data = msg.encode() if isinstance(msg, str) else msg
            if session is not None:
                data = session.open(data)  # decrypt the operator→endpoint frame
            await loop.sock_sendall(sock, data)
    except Exception:  # noqa: BLE001 - WebSocket closed (incl. "no close frame"), socket gone, or a bad E2E frame
        return


async def _sock_to_ws(ws, sock, loop, session=None) -> None:
    # Endpoint → operator. Same: a clean return on close instead of an unhandled ConnectionClosedError.
    try:
        while True:
            data = await loop.sock_recv(sock, 65536)
            if not data:
                return
            await ws.send(session.seal(data) if session is not None else data)
    except Exception:  # noqa: BLE001
        return  # encrypt endpoint→operator


@dataclass
class _Live:
    indicator: subprocess.Popen
    stop: threading.Event = field(default_factory=threading.Event)
    tunnel: threading.Thread | None = None
    ended_by_admin: bool = False


class RdpManager:
    def __init__(self, report: Callable[[str, dict], None], event: Callable[[str, str, str | None], None],
                 broker_call: Callable[[dict], dict] | None = None, server_url: str = "", ca_bundle: str | None = None,
                 device_sign: Callable[[bytes], bytes] | None = None):
        self.report = report          # (job_id, result) → server job result
        self.event = event            # (session_id, event, detail) → server session event
        self.broker_call = broker_call  # privileged RDP enable/disable
        self.server_url = server_url
        self.ca_bundle = ca_bundle
        self.device_sign = device_sign  # ECDSA signer for the E2E (zero-knowledge relay) handshake
        self.live: dict[str, _Live] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ start
    def start(self, env: dict) -> None:
        threading.Thread(target=self._start, args=(env,), name=f"rdp-{env['job_id'][:8]}", daemon=True).start()

    def _enable(self, env: dict) -> dict:
        # Windows: the privileged broker re-validates the signed envelope and flips native RDP on.
        # Linux: there is no separate broker — the root agent enables xrdp directly.
        if _IS_WIN:
            return self.broker_call({"envelope": env})
        from cage_agent.remote import linux_actions
        o = linux_actions.rdp_enable({})
        return {"status": o.status, "detail": o.detail, "previous_state": o.previous_state,
                "current_state": o.current_state}

    def _disable(self, env: dict) -> dict:
        if _IS_WIN:
            if self.broker_call is None:
                return {"status": "needs_attention", "detail": "no privileged broker"}
            return self.broker_call({"envelope": env})
        from cage_agent.remote import linux_actions
        o = linux_actions.rdp_disable({})
        return {"status": o.status, "detail": o.detail, "previous_state": o.previous_state,
                "current_state": o.current_state}

    def _start(self, env: dict) -> None:
        p, job_id, sid = env["parameters"], env["job_id"], env["parameters"]["session_id"]
        # Decide how to show the mandatory banner, per platform. RDP is refused if it cannot be shown (fail closed).
        if _IS_WIN:
            if not _interactive():
                self.report(job_id, {"status": "needs_attention", "detail": "Agent runs in session 0; the mandatory "
                                     "on-screen banner cannot be shown, so no remote-desktop session was started"})
                return
            if self.broker_call is None:
                self.report(job_id, {"status": "needs_attention",
                                     "detail": "Privileged broker unavailable; RDP not enabled"})
                return
            banner_cmd = _banner_cmd(p)
        else:
            gui = _linux_gui_session()
            if gui is None:
                self.report(job_id, {"status": "needs_attention", "detail": "No active graphical desktop session on "
                                     "this endpoint; the mandatory Remote Desktop banner cannot be shown, so the "
                                     "session was refused."})
                return
            banner_cmd = _linux_banner_cmd(p, gui)
        # 1) Show the banner FIRST — RDP is never enabled without a visible indicator on the endpoint.
        try:
            ind = subprocess.Popen(banner_cmd, stdout=subprocess.PIPE, text=True)
        except OSError as exc:
            self.report(job_id, {"status": "failed", "detail": f"Banner could not be shown: {exc}"})
            return
        # 2) Only now enable RDP (Windows → privileged broker; Linux → xrdp via the root agent).
        try:
            r = self._enable(env)
        except Exception as exc:  # noqa: BLE001
            ind.terminate()
            self.report(job_id, {"status": "needs_attention", "detail": f"Privileged broker not available: {exc}"})
            return
        if r.get("status") != "succeeded":
            ind.terminate()
            self.report(job_id, r)
            return
        # 3) Open the outbound relay tunnel so the operator can reach this machine's RDP from any network.
        live = _Live(ind)
        token = p.get("tunnel_token", "")
        if token and self.server_url:
            log.info("rdp.start: enabled OK; launching relay tunnel thread for session %s", sid[:8])
            live.tunnel = threading.Thread(target=run_tunnel,
                                           args=(self.server_url, self.ca_bundle, sid, token, live.stop, self.device_sign),
                                           name=f"rdp-tunnel-{sid[:8]}", daemon=True)
            live.tunnel.start()
        else:
            log.warning("rdp.start: NOT starting tunnel (tunnel_token present=%s, server_url present=%s)",
                        bool(token), bool(self.server_url))
        with self._lock:
            self.live[sid] = live
        self.report(job_id, {"status": "succeeded", "detail": "Remote desktop active (relayed); connect from the console",
                             "current_state": {"connection": "relay"}})
        out, _ = ind.communicate()  # blocks until the user ends it, the timer expires, or an admin terminates
        live.stop.set()
        with self._lock:
            live = self.live.pop(sid, None)
        if live and live.ended_by_admin:
            return  # end() handles disabling RDP and reporting
        try:
            ended = json.loads(out.strip().splitlines()[-1]).get("ended")
        except (ValueError, IndexError):
            ended = "user"
        self.event(sid, "ended_by_user" if ended == "user" else "expired",
                   "Banner closed on endpoint" if ended == "user" else "Session timer expired")

    # ------------------------------------------------------------------ end
    def end(self, env: dict) -> None:
        sid = env["parameters"]["session_id"]
        with self._lock:
            live = self.live.get(sid)
            if live:
                live.ended_by_admin = True
                live.stop.set()
        if live:
            live.indicator.terminate()
        try:
            r = self._disable(env)
        except Exception as exc:  # noqa: BLE001
            r = {"status": "needs_attention", "detail": str(exc)}
        status = r.get("status", "needs_attention")
        detail = "Session ended; Remote Desktop disabled" if status == "succeeded" else \
            f"Banner closed, but Remote Desktop could not be disabled: {r.get('detail') or status}"
        self.report(env["job_id"], {"status": status, "detail": detail})

    def end_all(self) -> None:
        with self._lock:
            sessions = list(self.live.items())
        for sid, live in sessions:
            live.ended_by_admin = True
            live.stop.set()
            live.indicator.terminate()
            self.event(sid, "terminated", "Agent stopping")
