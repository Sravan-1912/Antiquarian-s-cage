"""Low-level mouse/keyboard injection for remote screen control (Windows SendInput via ctypes).

Off Windows every function is a no-op (input injection on X11 is a future enhancement); on Windows the agent runs in
the interactive desktop session, so SendInput reaches that session. VK maps JS KeyboardEvent.code → Windows virtual
key; unmapped printable characters are typed as Unicode keystrokes instead.
"""
from __future__ import annotations

import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.windll.user32
    _ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

    class _MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", _ULONG_PTR)]

    class _KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", _ULONG_PTR)]

    class _UNION(ctypes.Union):
        _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT)]

    class _INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", _UNION)]

    _MOUSE, _KEYBOARD = 0, 1
    _MOVE, _LDOWN, _LUP, _RDOWN, _RUP = 0x0001, 0x0002, 0x0004, 0x0008, 0x0010
    _MDOWN, _MUP, _WHEEL = 0x0020, 0x0040, 0x0800
    _KEYUP, _UNICODE = 0x0002, 0x0004
    _BTN = {0: (_LDOWN, _LUP), 1: (_MDOWN, _MUP), 2: (_RDOWN, _RUP)}

    def _send_mouse(flags: int, data: int = 0) -> None:
        inp = _INPUT(type=_MOUSE, u=_UNION(mi=_MOUSEINPUT(0, 0, data & 0xFFFFFFFF, flags, 0, 0)))
        _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT))

    def _send_key(vk: int, scan: int, flags: int) -> None:
        inp = _INPUT(type=_KEYBOARD, u=_UNION(ki=_KEYBDINPUT(vk, scan, flags, 0, 0)))
        _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT))

    def move(x: int, y: int) -> None:
        _user32.SetCursorPos(int(x), int(y))

    def button(b: int, down: bool) -> None:
        downf, upf = _BTN.get(b, _BTN[0])
        _send_mouse(downf if down else upf)

    def wheel(dy: int) -> None:
        _send_mouse(_WHEEL, 120 if dy < 0 else -120)  # JS deltaY>0 = scroll down → negative WHEEL delta

    def key_vk(vk: int, down: bool) -> None:
        _send_key(vk, 0, 0 if down else _KEYUP)

    def key_unicode(ch: str) -> None:
        code = ord(ch)
        _send_key(0, code, _UNICODE)
        _send_key(0, code, _UNICODE | _KEYUP)
else:  # pragma: no cover - non-Windows: input injection not supported yet
    def move(x: int, y: int) -> None: ...
    def button(b: int, down: bool) -> None: ...
    def wheel(dy: int) -> None: ...
    def key_vk(vk: int, down: bool) -> None: ...
    def key_unicode(ch: str) -> None: ...


def _build_vk() -> dict[str, int]:
    m: dict[str, int] = {}
    for c in range(ord("A"), ord("Z") + 1):
        m[f"Key{chr(c)}"] = c
    for d in range(10):
        m[f"Digit{d}"] = 0x30 + d
    for i in range(1, 13):
        m[f"F{i}"] = 0x70 + (i - 1)
    m.update({
        "Enter": 0x0D, "NumpadEnter": 0x0D, "Backspace": 0x08, "Tab": 0x09, "Escape": 0x1B, "Space": 0x20,
        "Delete": 0x2E, "Insert": 0x2D, "Home": 0x24, "End": 0x23, "PageUp": 0x21, "PageDown": 0x22,
        "ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28, "CapsLock": 0x14,
        "ShiftLeft": 0x10, "ShiftRight": 0x10, "ControlLeft": 0x11, "ControlRight": 0x11,
        "AltLeft": 0x12, "AltRight": 0x12, "MetaLeft": 0x5B, "MetaRight": 0x5C,
    })
    return m


VK = _build_vk()
