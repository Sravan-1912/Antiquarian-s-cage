"""Named-pipe transport between agent (client) and broker (server). Local only; DACL-restricted."""
from __future__ import annotations

import json
import logging
import threading

PIPE_NAME = r"\\.\pipe\AntiquariansCageBroker"
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
MAX_MESSAGE = 1 << 20
log = logging.getLogger("cage_broker.pipe")


class BrokerUnavailable(Exception):
    pass


def _security_attributes(extra_sids: list, include_admins: bool = True):
    import ntsecuritycon as con
    import win32security as sec
    sa = sec.SECURITY_ATTRIBUTES()
    sd = sec.SECURITY_DESCRIPTOR()
    dacl = sec.ACL()
    rights = con.GENERIC_READ | con.GENERIC_WRITE
    base = [sec.ConvertStringSidToSid("S-1-5-18")] + ([sec.ConvertStringSidToSid("S-1-5-32-544")] if include_admins else [])
    for sid in [*base, *extra_sids]:
        dacl.AddAccessAllowedAce(sec.ACL_REVISION, rights, sid)
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sa.SECURITY_DESCRIPTOR = sd
    return sa


def sid_for(account: str):
    import win32security as sec
    if account.startswith("S-1-"):
        return sec.ConvertStringSidToSid(account)
    return sec.LookupAccountName(None, account)[0]


def sec_string(sid) -> str:
    import win32security as sec
    return sec.ConvertSidToStringSid(sid)


def current_user_sid():
    import win32api
    import win32con
    import win32security as sec
    tok = sec.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    return sec.GetTokenInformation(tok, sec.TokenUser)[0]


def serve(handler, allowed_sids: list, stop: threading.Event, name: str = PIPE_NAME, *,
          include_admins: bool = True, pass_handle: bool = False) -> None:
    import pywintypes
    import win32file
    import win32pipe
    sa = _security_attributes(allowed_sids, include_admins)
    while not stop.is_set():
        h = win32pipe.CreateNamedPipe(
            name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, MAX_MESSAGE, MAX_MESSAGE, 0, sa)
        try:
            win32pipe.ConnectNamedPipe(h, None)
            if stop.is_set():
                break
            _, data = win32file.ReadFile(h, MAX_MESSAGE)
            try:
                request = json.loads(data.decode("utf-8"))
                response = handler(request, h) if pass_handle else handler(request)
            except (ValueError, UnicodeDecodeError):
                response = {"status": "rejected", "detail": "broker: malformed request"}
            win32file.WriteFile(h, json.dumps(response).encode("utf-8"))
            win32file.FlushFileBuffers(h)
        except pywintypes.error as exc:
            log.warning("pipe error: %s", exc)
        finally:
            try:
                win32pipe.DisconnectNamedPipe(h)
            except pywintypes.error:
                pass
            win32file.CloseHandle(h)


def wake(name: str = PIPE_NAME) -> None:
    """Unblock ConnectNamedPipe during shutdown."""
    try:
        call({"ping": True}, name, timeout_ms=500)
    except BrokerUnavailable:
        pass


def call(request: dict, name: str = PIPE_NAME, timeout_ms: int = 5000) -> dict:
    import pywintypes
    import win32file
    import win32pipe
    try:
        win32pipe.WaitNamedPipe(name, timeout_ms)
        h = win32file.CreateFile(name, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None,
                                 win32file.OPEN_EXISTING, 0, None)
    except pywintypes.error as exc:
        raise BrokerUnavailable(f"privileged broker not reachable ({exc.strerror})") from exc
    try:
        win32pipe.SetNamedPipeHandleState(h, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(h, json.dumps(request).encode("utf-8"))
        _, data = win32file.ReadFile(h, MAX_MESSAGE)
        return json.loads(data.decode("utf-8"))
    except pywintypes.error as exc:
        raise BrokerUnavailable(f"broker communication failed ({exc.strerror})") from exc
    finally:
        win32file.CloseHandle(h)
