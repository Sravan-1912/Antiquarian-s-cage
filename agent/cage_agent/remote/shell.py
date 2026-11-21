"""Live-response interactive shell on the endpoint, tunnelled over the relay (break-glass, fully audited).

shell.start → show the mandatory on-screen banner (fail closed if it cannot be shown) → spawn the OS shell in the
              logged-in user's session → open an OUTBOUND relay tunnel (end-to-end encrypted when the operator asks)
              and bridge the shell's stdio to the operator → stream the transcript to the audit trail.
shell.end   → terminate the shell and close the banner.

This is ARBITRARY command execution and deliberately bypasses the "no arbitrary execution" rule, so it is gated by
RBAC server-side, always shows the banner, and every operator command is audited. Elevated (SYSTEM/root) sessions are
not yet wired through the broker — they return needs_attention for now.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from cage_agent.remote.assist import _helper_cmd as _assist_helper_cmd, _interactive
from cage_agent.remote.rdp import E2E_MAGIC, _linux_banner_cmd, _linux_gui_session, _ws_url

log = logging.getLogger("cage_agent.shell")
_IS_WIN = sys.platform == "win32"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_AUDIT_CAP = 4000  # bytes of operator input buffered per audit flush


def _banner_cmd(p: dict) -> list[str]:
    return [*_assist_helper_cmd("indicator", p), "--kind", "shell"]


def _shell_argv() -> list[str]:
    if _IS_WIN:
        return ["powershell.exe", "-NoLogo", "-NoProfile", "-NoExit", "-Command", "-"]
    import shutil
    return [shutil.which("bash") or "/bin/sh", "-i"]


@dataclass
class _Live:
    indicator: subprocess.Popen
    stop: threading.Event = field(default_factory=threading.Event)
    tunnel: threading.Thread | None = None
    ended_by_admin: bool = False


class ShellManager:
    def __init__(self, report: Callable[[str, dict], None], event: Callable[[str, str, str | None], None],
                 server_url: str = "", ca_bundle: str | None = None,
                 device_sign: Callable[[bytes], bytes] | None = None):
        self.report = report
        self.event = event            # (session_id, event, detail) → server session event (used for the audit transcript)
        self.server_url = server_url
        self.ca_bundle = ca_bundle
        self.device_sign = device_sign
        self.live: dict[str, _Live] = {}
        self._lock = threading.Lock()

    def start(self, env: dict) -> None:
        threading.Thread(target=self._start, args=(env,), name=f"shell-{env['job_id'][:8]}", daemon=True).start()

    def _start(self, env: dict) -> None:
        p, job_id, sid = env["parameters"], env["job_id"], env["parameters"]["session_id"]
        if p.get("elevated"):
            self.report(job_id, {"status": "needs_attention", "detail": "An elevated (SYSTEM/root) live-response shell "
                                 "is not available yet; request a user-session shell."})
            return
        # Banner first — the shell is never opened without a visible indicator (same fail-closed rule as RDP/assist).
        if _IS_WIN:
            if not _interactive():
                self.report(job_id, {"status": "needs_attention", "detail": "Agent runs in session 0; the mandatory "
                                     "banner cannot be shown, so no shell session was started"})
                return
            banner_cmd = _banner_cmd(p)
        else:
            gui = _linux_gui_session()
            if gui is None:
                self.report(job_id, {"status": "needs_attention", "detail": "No active graphical desktop session; the "
                                     "mandatory live-response banner cannot be shown, so the session was refused."})
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
                target=_run_shell_tunnel,
                args=(self.server_url, self.ca_bundle, sid, token, live.stop, self.device_sign,
                      lambda data: self._audit(sid, data)),
                name=f"shell-tunnel-{sid[:8]}", daemon=True)
            live.tunnel.start()
        with self._lock:
            self.live[sid] = live
        self.report(job_id, {"status": "succeeded", "detail": "Live-response shell active (relayed); attach from the console"})
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
        self.report(env["job_id"], {"status": "succeeded", "detail": "Live-response shell ended"})

    def end_all(self) -> None:
        with self._lock:
            sessions = list(self.live.items())
        for sid, live in sessions:
            live.ended_by_admin = True
            live.stop.set()
            live.indicator.terminate()
            self.event(sid, "terminated", "Agent stopping")

    def _audit(self, sid: str, operator_input: bytes) -> None:
        # The operator's commands are the audited record; keep it bounded and let the server anchor it.
        try:
            text = operator_input.decode("utf-8", "replace").replace("\r", "")
        except Exception:  # noqa: BLE001
            return
        if text.strip():
            self.event(sid, "shell_command", text[:_AUDIT_CAP])


def _run_shell_tunnel(server_url, ca_bundle, session_id, token, stop, device_sign, audit_cb) -> None:
    url = _ws_url(server_url, session_id, token)
    ctx = None
    if url.startswith("wss://"):
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    try:
        asyncio.run(_shell_main(url, ctx, stop, device_sign, audit_cb))
    except Exception as exc:  # noqa: BLE001
        log.warning("shell tunnel stopped: %s", exc)


async def _shell_main(url, ctx, stop, device_sign, audit_cb) -> None:
    import websockets
    while not stop.is_set():
        try:
            async with websockets.connect(url, ssl=ctx, max_size=None, open_timeout=20, ping_interval=20) as ws:
                await _shell_bridge(ws, stop, device_sign, audit_cb)
        except Exception as exc:  # noqa: BLE001
            log.debug("shell tunnel reconnect after: %s", exc)
        if not stop.is_set():
            await asyncio.sleep(1)


async def _shell_bridge(ws, stop, device_sign, audit_cb) -> None:
    from cage_agent.remote import e2e
    try:
        first = await asyncio.wait_for(ws.recv(), timeout=110)
    except asyncio.TimeoutError:
        return
    first = first.encode() if isinstance(first, str) else first
    session = None
    if device_sign is not None and first.startswith(E2E_MAGIC):
        try:
            auth, session = e2e.respond(first[len(E2E_MAGIC):], device_sign)
        except e2e.E2EError as exc:
            log.warning("shell e2e handshake rejected: %s", exc)
            return
        await ws.send(auth)
        first = None
    proc = await asyncio.create_subprocess_exec(
        *_shell_argv(), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, creationflags=NO_WINDOW if _IS_WIN else 0)

    async def op_to_shell(initial: bytes | None) -> None:
        try:
            if initial:
                audit_cb(initial)
                proc.stdin.write(initial)
                await proc.stdin.drain()
            async for msg in ws:
                data = msg.encode() if isinstance(msg, str) else msg
                if session is not None:
                    data = session.open(data)
                audit_cb(data)
                proc.stdin.write(data)
                await proc.stdin.drain()
        except Exception:  # noqa: BLE001 - WS closed or shell gone: end cleanly
            return

    async def shell_to_op() -> None:
        try:
            while True:
                data = await proc.stdout.read(65536)
                if not data:
                    return
                await ws.send(session.seal(data) if session is not None else data)
        except Exception:  # noqa: BLE001
            return

    t1 = asyncio.create_task(op_to_shell(first))
    t2 = asyncio.create_task(shell_to_op())
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
    finally:
        for t in (t1, t2):
            t.cancel()
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
