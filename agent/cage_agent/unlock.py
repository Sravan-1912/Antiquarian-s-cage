"""Local relay between the lock-screen credential provider and the server (Phase 10).

The credential provider (CageCredentialProvider.dll, loaded by LogonUI.exe as SYSTEM) cannot talk to the server
itself: it has no device identity. It talks to this relay over a named pipe instead:

    {"op": "start",  "kind": "unlock"|"enroll", "windows_user": "...", "sid": "S-1-5-...", "key": "<b64, enroll>"}
        -> {"ok": true, "request_id": "...", "number": 42, "expires_at": "...", "approver": "user@org"}
    {"op": "status", "request_id": "..."}
        -> {"ok": true, "status": "pending"|"approved"|"enrolled"|"denied"|"expired", "key": "<b64, approved>"}
    errors -> {"ok": false, "code": "...", "message": "..."}

Pipe security: DACL grants SYSTEM only (no Administrators), remote clients are rejected, and outside development
mode the client's token must be SYSTEM (LogonUI runs as SYSTEM). The per-request secret that proves this
device started the request stays inside the relay; the provider only ever sees the request id.
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Callable

from cage_agent.core.communication import AuthRejected, ServerError

log = logging.getLogger("cage_agent.unlock")
PIPE_NAME = r"\\.\pipe\AntiquariansCageUnlock"


class UnlockHandler:
    """Pure request handling (unit-testable without pipes)."""

    def __init__(self, send: Callable[[str, dict], dict]):
        self.send = send  # signed POST to the server: send(path, payload) -> json
        self.secrets: dict[str, str] = {}
        self.lock = threading.Lock()

    @staticmethod
    def _err(code: str, message: str) -> dict:
        return {"ok": False, "code": code, "message": message}

    def _call(self, path: str, payload: dict) -> dict:
        try:
            return {"ok": True, **self.send(path, payload)}
        except AuthRejected as e:
            return self._err("device_rejected", f"This device is not allowed to request sign-in: {e}")
        except ServerError as e:
            text = str(e)
            try:  # server errors carry {"code","message"} as JSON after "NNN: "
                detail = json.loads(text.split(": ", 1)[1])
                return self._err(detail.get("code", "server"), detail.get("message", text))
            except (IndexError, ValueError, AttributeError):
                return self._err("offline", "The Antiquarian's Cage server could not be reached. Use your password.")

    def handle(self, req: dict) -> dict:
        op = req.get("op")
        if op == "ping":
            return {"ok": True}
        if op == "start":
            kind = req.get("kind")
            if kind not in ("unlock", "enroll") or not isinstance(req.get("sid"), str) or not isinstance(req.get("windows_user"), str):
                return self._err("bad_request", "Malformed request.")
            payload = {"kind": kind, "windows_user": req["windows_user"][:256], "sid": req["sid"][:184]}
            if kind == "enroll":
                if not isinstance(req.get("key"), str):
                    return self._err("bad_request", "Setup key missing.")
                payload["key"] = req["key"]
            out = self._call("/agent/v1/unlock/start", payload)
            if out.get("ok"):
                with self.lock:
                    self.secrets[out["request_id"]] = out.pop("secret")
            return out
        if op == "status":
            rid = req.get("request_id")
            with self.lock:
                secret = self.secrets.get(rid) if isinstance(rid, str) else None
            if secret is None:
                return self._err("unknown", "Unknown request.")
            out = self._call("/agent/v1/unlock/status", {"request_id": rid, "secret": secret})
            if not out.get("ok") or out.get("status") not in ("pending",):
                with self.lock:
                    self.secrets.pop(rid, None)  # terminal: never reusable
            return out
        return self._err("bad_request", "Unknown operation.")


def _client_sid(pipe_handle) -> str:
    """SID of the process on the other end of the pipe (impersonation at identification level is enough).
    Works from the agent's low-privilege service account, unlike opening the SYSTEM-owned LogonUI process."""
    import win32api
    import win32con
    import win32security as sec
    sec.ImpersonateNamedPipeClient(pipe_handle)
    try:
        tok = sec.OpenThreadToken(win32api.GetCurrentThread(),
                                  win32con.TOKEN_QUERY, True)
        return sec.ConvertSidToStringSid(sec.GetTokenInformation(tok, sec.TokenUser)[0])
    finally:
        sec.RevertToSelf()


class UnlockRelay:
    def __init__(self, handler: UnlockHandler, *, dev_allow_current_user: bool = False):
        self.handler = handler
        self.dev = dev_allow_current_user
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._serve, name="unlock-relay", daemon=True)
        self.thread.start()
        log.info("unlock relay listening on %s%s", PIPE_NAME, " (DEV: current user allowed)" if self.dev else "")

    def close(self) -> None:
        self.stop.set()
        from cage_broker import pipe
        pipe.wake(PIPE_NAME)

    def _serve(self) -> None:
        from cage_broker import pipe
        extra = [pipe.current_user_sid()] if self.dev else []

        allowed = {"S-1-5-18"}
        if self.dev:
            allowed.add(pipe.sec_string(pipe.current_user_sid()))

        def guarded(req: dict, handle=None) -> dict:
            try:
                who = _client_sid(handle) if handle is not None else None
            except Exception as exc:  # noqa: BLE001 - fail closed, but say why
                log.warning("unlock relay: could not identify client: %s", exc)
                who = None
            if who not in allowed:
                log.warning("unlock relay: rejected client %s", who)
                return {"ok": False, "code": "forbidden", "message": "Not allowed."}
            return self.handler.handle(req)

        pipe.serve(guarded, extra, self.stop, name=PIPE_NAME, include_admins=False, pass_handle=True)
