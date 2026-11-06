"""Remote-assistance lifecycle on the endpoint.

assist.start → (consent prompt in the user's session unless the organisation disabled consent) → report decision →
               show the persistent indicator → launch Windows Quick Assist for the actual screen sharing.
assist.end   → close indicator and Quick Assist, report.
Indicator closed by the user, or the local timer expiring, → session event to the server; Quick Assist is closed.

Limitation (documented): when the agent runs as a service in session 0 it cannot show UI itself; launching the
helper into the user's session from the broker (WTSQueryUserToken + CreateProcessAsUser) is not yet verified, so the
request fails closed with "needs attention" rather than starting an unannounced session.
"""
from __future__ import annotations

from cage_agent.sysexe import exe  # absolute System32 paths

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger("cage_agent.assist")
QUICK_ASSIST = r"shell:AppsFolder\MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App"


def _helper_cmd(mode: str, p: dict) -> list[str]:
    base = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m"]
    target = ["session-helper"] if getattr(sys, "frozen", False) else ["cage_agent.session_helper"]
    return [*base, *target, mode, "--requester", str(p.get("requested_by", "IT administrator")),
            "--reason", str(p.get("reason", "")), "--minutes", str(p["max_minutes"]),
            "--timeout", str(p.get("consent_timeout_seconds", 120))]


def _interactive() -> bool:
    if sys.platform != "win32":
        return False
    sid = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    return sid.value != 0


@dataclass
class _Live:
    indicator: subprocess.Popen
    ended_by_admin: bool = False


class AssistManager:
    def __init__(self, report: Callable[[str, dict], None], event: Callable[[str, str, str | None], None],
                 launch_quick_assist: bool = True, broker_call: Callable[[dict], dict] | None = None):
        self.report = report          # (job_id, result) → server job result
        self.event = event            # (session_id, event, detail) → server session event
        self.launch_quick_assist = launch_quick_assist
        self.broker_call = broker_call  # privileged cleanup (Quick Assist runs at high integrity)
        self.live: dict[str, _Live] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ start
    def start(self, env: dict) -> None:
        threading.Thread(target=self._start, args=(env,), name=f"assist-{env['job_id'][:8]}", daemon=True).start()

    def _start(self, env: dict) -> None:
        p, job_id, sid = env["parameters"], env["job_id"], env["parameters"]["session_id"]
        if not _interactive():
            self.report(job_id, {"status": "needs_attention", "detail": "Agent runs in session 0; user-session helper "
                                 "launch is not available, so no session was started"})
            return
        decision, user = "not_required", None
        if p["require_consent"]:
            try:
                out = subprocess.run(_helper_cmd("consent", p), capture_output=True, text=True,
                                     timeout=p["consent_timeout_seconds"] + 30)
                parsed = json.loads(out.stdout.strip().splitlines()[-1])
                decision, user = parsed["decision"], parsed.get("user")
            except (subprocess.TimeoutExpired, ValueError, IndexError, KeyError, OSError) as exc:
                log.error("consent prompt failed: %s", exc)
                self.report(job_id, {"status": "failed", "detail": f"Consent prompt could not be shown: {exc}"})
                return
        log.info("session %s consent: %s (%s)", sid, decision, user)
        self.report(job_id, {"status": "succeeded", "detail": f"consent {decision}",
                             "current_state": {"consent": decision, "consent_user": user}})
        if decision not in ("granted", "not_required"):
            return
        try:
            ind = subprocess.Popen(_helper_cmd("indicator", p), stdout=subprocess.PIPE, text=True)
        except OSError as exc:
            self.event(sid, "helper_failed", f"indicator could not start: {exc}")
            return
        with self._lock:
            self.live[sid] = _Live(ind)
        if self.launch_quick_assist:
            try:
                subprocess.Popen([exe("explorer.exe"), QUICK_ASSIST])
            except OSError as exc:
                log.warning("Quick Assist launch failed: %s", exc)
        out, _ = ind.communicate()  # blocks until user ends, timer expires, or admin terminates
        with self._lock:
            live = self.live.pop(sid, None)
        if live and live.ended_by_admin:
            return  # end() handles cleanup and reporting
        closed = self._close_quick_assist()
        try:
            ended = json.loads(out.strip().splitlines()[-1]).get("ended")
        except (ValueError, IndexError):
            ended = "user"
        detail = "End session clicked on endpoint" if ended == "user" else "Local session timer expired"
        if not closed:  # the server answers this event with a signed assist.end the broker uses to close it
            detail += "; Quick Assist still running (elevated) — privileged cleanup requested"
        self.event(sid, "ended_by_user" if ended == "user" else "expired", detail)

    # ------------------------------------------------------------------ end
    def end(self, env: dict) -> None:
        sid = env["parameters"]["session_id"]
        with self._lock:
            live = self.live.get(sid)
            if live:
                live.ended_by_admin = True
        if live:
            live.indicator.terminate()
        closed = self._close_quick_assist()
        detail = "Session ended on endpoint" if live else "No active session on endpoint (already ended)"
        if not closed:
            # Quick Assist runs at high integrity; only the privileged broker can close it. Forward the same
            # server-signed envelope — the broker re-validates it and its only effect is closing Quick Assist.
            try:
                r = self.broker_call({"envelope": env}) if self.broker_call else {"status": "needs_attention"}
            except Exception as exc:  # noqa: BLE001
                r = {"status": "needs_attention", "detail": str(exc)}
            closed = r.get("status") == "succeeded" and not self._quick_assist_running()
            if not closed:
                self.report(env["job_id"], {"status": "needs_attention", "detail": f"{detail}; indicator closed, but "
                                            "Quick Assist is still running (elevated) and the privileged broker could "
                                            f"not close it: {r.get('detail') or r.get('status')}"})
                return
            detail += "; Quick Assist closed by broker"
        self.report(env["job_id"], {"status": "succeeded", "detail": detail})

    def end_all(self) -> None:
        with self._lock:
            sessions = list(self.live.items())
        for sid, live in sessions:
            live.ended_by_admin = True
            live.indicator.terminate()
            self.event(sid, "terminated", "Agent stopping")
        self._close_quick_assist()

    @staticmethod
    def _quick_assist_running() -> bool:
        r = subprocess.run([exe("tasklist.exe"), "/FI", "IMAGENAME eq QuickAssist.exe", "/NH"], capture_output=True, text=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return "QuickAssist.exe" in r.stdout

    def _close_quick_assist(self) -> bool:
        """Returns True only if Quick Assist is verifiably not running afterwards."""
        if not self._quick_assist_running():
            return True
        subprocess.run([exe("taskkill.exe"), "/IM", "QuickAssist.exe", "/F"], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return not self._quick_assist_running()
