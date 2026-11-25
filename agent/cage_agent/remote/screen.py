"""Agent-side remote screen control, tunnelled over the backend relay (works on ANY Windows edition — including Home —
and across any network, because the agent captures the screen and injects input itself rather than relying on the
Windows RDP host).

screen.start → show the mandatory on-screen banner (fail closed if it cannot be shown) → open an OUTBOUND relay tunnel
               → stream JPEG frames of the primary monitor to the operator and inject the operator's mouse/keyboard.
screen.end   → stop streaming and close the banner.

Wire protocol over the (binary) relay:
  agent → operator :  b'\\x02' + json{"w","h"}   (one meta frame: scaled stream size)
                      b'\\x01' + <jpeg bytes>     (each video frame)
  operator → agent :  utf-8 json                 ({"t":"m",...} mouse / {"t":"k",...} key / {"t":"scroll",...})

The agent runs in the interactive user's elevated session, so it can both capture that desktop and inject input into
it. Everything is gated server-side (RBAC) and shows a banner for the whole session, like RDP/shell/assist.
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from cage_agent.remote import winput as _si
from cage_agent.remote.winput import VK as _VK
from cage_agent.remote.assist import _helper_cmd as _assist_helper_cmd, _interactive
from cage_agent.remote.rdp import _linux_banner_cmd, _linux_gui_session, _ws_url

log = logging.getLogger("cage_agent.screen")
_IS_WIN = sys.platform == "win32"
_MAX_W = 1366       # cap the streamed width to bound bandwidth; scaled proportionally
_JPEG_QUALITY = 50
_FPS = 8


def _banner_cmd(p: dict) -> list[str]:
    return [*_assist_helper_cmd("indicator", p), "--kind", "screen"]


@dataclass
class _Live:
    indicator: subprocess.Popen
    stop: threading.Event = field(default_factory=threading.Event)
    tunnel: threading.Thread | None = None
    ended_by_admin: bool = False


class ScreenManager:
    def __init__(self, report: Callable[[str, dict], None], event: Callable[[str, str, str | None], None],
                 server_url: str = "", ca_bundle: str | None = None):
        self.report = report
        self.event = event
        self.server_url = server_url
        self.ca_bundle = ca_bundle
        self.live: dict[str, _Live] = {}
        self._lock = threading.Lock()

    def start(self, env: dict) -> None:
        threading.Thread(target=self._start, args=(env,), name=f"screen-{env['job_id'][:8]}", daemon=True).start()

    def _start(self, env: dict) -> None:
        p, job_id, sid = env["parameters"], env["job_id"], env["parameters"]["session_id"]
        # Banner first — the screen is never shared without a visible indicator (fail-closed, same as RDP/shell/assist).
        if _IS_WIN:
            if not _interactive():
                self.report(job_id, {"status": "needs_attention", "detail": "Agent runs in session 0; the mandatory "
                                     "banner cannot be shown, so remote screen was not started"})
                return
            banner_cmd = _banner_cmd(p)
        else:
            gui = _linux_gui_session()
            if gui is None:
                self.report(job_id, {"status": "needs_attention", "detail": "No active graphical desktop session; the "
                                     "mandatory banner cannot be shown, so remote screen was refused."})
                return
            banner_cmd = _linux_banner_cmd(p, gui)
        try:
            ind = subprocess.Popen(banner_cmd, stdout=subprocess.PIPE, text=True)
        except OSError as exc:
            self.report(job_id, {"status": "failed", "detail": f"Banner could not be shown: {exc}"})
            return
        live = _Live(ind)
        token = p.get("tunnel_token", "")
        if token and self.server_url:
            live.tunnel = threading.Thread(
                target=_run_screen_tunnel, args=(self.server_url, self.ca_bundle, sid, token, live.stop),
                name=f"screen-tunnel-{sid[:8]}", daemon=True)
            live.tunnel.start()
        with self._lock:
            self.live[sid] = live
        self.report(job_id, {"status": "succeeded", "detail": "Remote screen active (relayed); view from the console"})
        out, _ = ind.communicate()  # blocks until the banner's End button, the timer, or an admin terminates it
        live.stop.set()
        with self._lock:
            live = self.live.pop(sid, None)
        if live and live.ended_by_admin:
            return
        self.event(sid, "ended_by_user", "Banner closed on endpoint")

    def end(self, env: dict) -> None:
        sid = env["parameters"]["session_id"]
        with self._lock:
            live = self.live.get(sid)
            if live:
                live.ended_by_admin = True
                live.stop.set()
                live.indicator.terminate()
        self.report(env["job_id"], {"status": "succeeded", "detail": "Remote screen ended"})

    def end_all(self) -> None:
        with self._lock:
            sessions = list(self.live.items())
        for sid, live in sessions:
            live.ended_by_admin = True
            live.stop.set()
            live.indicator.terminate()
            self.event(sid, "terminated", "Agent stopping")


def _run_screen_tunnel(server_url, ca_bundle, session_id, token, stop) -> None:
    url = _ws_url(server_url, session_id, token)
    ctx = None
    if url.startswith("wss://"):
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    try:
        asyncio.run(_screen_main(url, ctx, stop))
    except Exception as exc:  # noqa: BLE001
        log.warning("screen tunnel stopped: %s", exc)


async def _screen_main(url, ctx, stop) -> None:
    import websockets
    while not stop.is_set():
        try:
            async with websockets.connect(url, ssl=ctx, max_size=None, open_timeout=20, ping_interval=20) as ws:
                await _screen_bridge(ws, stop)
        except Exception as exc:  # noqa: BLE001
            log.debug("screen tunnel reconnect after: %s", exc)
        if not stop.is_set():
            await asyncio.sleep(1)


async def _screen_bridge(ws, stop) -> None:
    cap = _Capturer()
    inj = _Injector(cap)
    await ws.send(b"\x02" + json.dumps({"w": cap.out_w, "h": cap.out_h}).encode())
    interval = 1.0 / max(1, _FPS)

    async def send_frames() -> None:
        loop = asyncio.get_event_loop()
        while not stop.is_set():
            t0 = loop.time()
            jpeg = await asyncio.to_thread(cap.grab_jpeg)
            if jpeg:
                await ws.send(b"\x01" + jpeg)
            await asyncio.sleep(max(0.0, interval - (loop.time() - t0)))

    async def recv_input() -> None:
        async for msg in ws:
            raw = msg if isinstance(msg, (bytes, bytearray)) else msg.encode()
            try:
                ev = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001
                continue
            await asyncio.to_thread(inj.handle, ev)

    t1 = asyncio.create_task(send_frames())
    t2 = asyncio.create_task(recv_input())
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
        cap.close()


class _Capturer:
    """Grabs the primary monitor with mss, scales it down and JPEG-encodes it with Pillow."""

    def __init__(self) -> None:
        import mss
        self._sct = mss.mss()
        self._mon = self._sct.monitors[1]  # primary physical monitor
        self.screen_w = int(self._mon["width"])
        self.screen_h = int(self._mon["height"])
        scale = min(1.0, _MAX_W / self.screen_w) if self.screen_w else 1.0
        self.out_w = max(1, int(self.screen_w * scale))
        self.out_h = max(1, int(self.screen_h * scale))

    def grab_jpeg(self) -> bytes | None:
        try:
            from io import BytesIO
            from PIL import Image
            shot = self._sct.grab(self._mon)
            img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
            if (self.out_w, self.out_h) != shot.size:
                img = img.resize((self.out_w, self.out_h), Image.BILINEAR)
            buf = BytesIO()
            img.save(buf, format="JPEG", quality=_JPEG_QUALITY)
            return buf.getvalue()
        except Exception as exc:  # noqa: BLE001 — a transient grab failure must not kill the stream
            log.debug("frame grab failed: %s", exc)
            return None

    def close(self) -> None:
        try:
            self._sct.close()
        except Exception:  # noqa: BLE001
            pass


class _Injector:
    """Injects the operator's mouse/keyboard into the interactive desktop (Windows: SendInput via ctypes)."""

    def __init__(self, cap: _Capturer) -> None:
        self.w = cap.screen_w
        self.h = cap.screen_h

    def handle(self, ev: dict) -> None:
        if not _IS_WIN:
            return  # input injection on Linux (X11) is a future enhancement; frames still stream
        try:
            t = ev.get("t")
            if t == "m":
                self._mouse(ev)
            elif t == "scroll":
                _si.wheel(int(ev.get("dy", 0)))
            elif t == "k":
                self._key(ev)
        except Exception as exc:  # noqa: BLE001 — never let one bad event tear down the session
            log.debug("input event skipped: %s", exc)

    def _mouse(self, ev: dict) -> None:
        x = int(max(0.0, min(1.0, float(ev.get("x", 0)))) * self.w)
        y = int(max(0.0, min(1.0, float(ev.get("y", 0)))) * self.h)
        _si.move(x, y)
        e, b = ev.get("e"), int(ev.get("b", 0))
        if e == "down":
            _si.button(b, True)
        elif e == "up":
            _si.button(b, False)

    def _key(self, ev: dict) -> None:
        code = str(ev.get("code") or "")
        down = ev.get("e") != "up"
        vk = _VK.get(code)
        if vk is not None:
            _si.key_vk(vk, down)
            return
        # printable single character with no mapped code → type it as a Unicode keystroke (on key-down only)
        ch = ev.get("key") or ""
        if down and isinstance(ch, str) and len(ch) == 1 and ch.isprintable():
            _si.key_unicode(ch)
