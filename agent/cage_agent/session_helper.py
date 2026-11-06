"""User-session UI for remote assistance. Runs in the interactive user's desktop session.

    python -m cage_agent.session_helper consent  --requester R --reason T --minutes M --timeout S
        → prints {"decision": "granted"|"denied"|"timeout", "user": "<DOMAIN\\user>"} ; no answer = timeout = denied
    python -m cage_agent.session_helper indicator --requester R --reason T --minutes M
        → always-on-top banner with countdown and an "End session" button for the whole session;
          prints {"ended": "user"|"expired"} on exit. The agent terminates it when an administrator ends the session.

The indicator cannot be minimised away by the helper itself and is shown for the entire session; there is no
"silent" mode. Text is rendered as plain labels (no markup), so server-supplied strings cannot inject UI.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time

BG, FG, MUTED, ACCENT, DANGER = "#121316", "#eceef0", "#9a9ea4", "#10b981", "#b91c1c"


def _user() -> str:
    return f"{os.environ.get('USERDOMAIN', '')}\\{getpass.getuser()}".lstrip("\\")


def _clean(s: str, n: int) -> str:
    return "".join(ch for ch in s if ch.isprintable())[:n]


def consent(requester: str, reason: str, minutes: int, timeout: int) -> dict:
    import tkinter as tk
    result = {"decision": "timeout", "user": _user()}
    root = tk.Tk()
    root.title("Antiquarian's Cage — Remote assistance request")
    root.configure(bg=BG)
    root.attributes("-topmost", True)
    root.resizable(False, False)
    root.protocol("WM_DELETE_WINDOW", lambda: (result.update(decision="denied"), root.destroy()))
    pad = {"padx": 18, "anchor": "w"}
    tk.Label(root, text="Remote assistance request", font=("Segoe UI Semibold", 13), bg=BG, fg=FG).pack(pady=(16, 4), **pad)
    tk.Label(root, text=f"{_clean(requester, 120)} from your IT team asks to view and control this computer.",
             font=("Segoe UI", 10), bg=BG, fg=FG, wraplength=420, justify="left").pack(**pad)
    tk.Label(root, text=f"Reason: {_clean(reason, 300)}", font=("Segoe UI", 10), bg=BG, fg=MUTED, wraplength=420,
             justify="left").pack(pady=(6, 0), **pad)
    tk.Label(root, text=f"Maximum duration: {minutes} minutes. You can end the session at any time.",
             font=("Segoe UI", 9), bg=BG, fg=MUTED).pack(pady=(6, 0), **pad)
    countdown = tk.Label(root, text="", font=("Segoe UI", 9), bg=BG, fg=MUTED)
    countdown.pack(pady=(6, 0), **pad)
    row = tk.Frame(root, bg=BG)
    row.pack(fill="x", padx=18, pady=16)

    def decide(d: str) -> None:
        result["decision"] = d
        root.destroy()

    tk.Button(row, text="Decline", width=12, command=lambda: decide("denied"), bg="#2b2f34", fg=FG,
              relief="flat").pack(side="right", padx=(8, 0))
    tk.Button(row, text="Allow", width=12, command=lambda: decide("granted"), bg=ACCENT, fg="white",
              relief="flat").pack(side="right")
    deadline = time.monotonic() + timeout

    def tick() -> None:
        left = int(deadline - time.monotonic())
        if left <= 0:
            decide("timeout")
            return
        countdown.config(text=f"This request is declined automatically in {left} s.")
        root.after(500, tick)

    tick()
    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    root.geometry(f"+{(root.winfo_screenwidth() - w) // 2}+{(root.winfo_screenheight() - h) // 3}")
    root.lift()
    root.focus_force()
    root.mainloop()
    return result


def indicator(requester: str, reason: str, minutes: int) -> dict:
    import tkinter as tk
    result = {"ended": "expired"}
    root = tk.Tk()
    root.title("Remote assistance active")
    root.overrideredirect(True)  # no title bar: cannot be minimised; stays visible on top
    root.attributes("-topmost", True)
    root.configure(bg=DANGER)
    frame = tk.Frame(root, bg=DANGER)
    frame.pack(padx=12, pady=6)
    tk.Label(frame, text="●  REMOTE ASSISTANCE ACTIVE", font=("Segoe UI Semibold", 10), bg=DANGER, fg="white").pack(side="left")
    info = tk.Label(frame, text="", font=("Segoe UI", 9), bg=DANGER, fg="white")
    info.pack(side="left", padx=12)

    def end() -> None:
        result["ended"] = "user"
        root.destroy()

    tk.Button(frame, text="End session", command=end, bg="white", fg=DANGER, relief="flat", padx=8).pack(side="left")
    deadline = time.monotonic() + minutes * 60

    def tick() -> None:
        left = int(deadline - time.monotonic())
        if left <= 0:
            root.destroy()
            return
        info.config(text=f"{_clean(requester, 60)} · {left // 60:02d}:{left % 60:02d} left")
        root.attributes("-topmost", True)
        root.after(1000, tick)

    tick()
    root.update_idletasks()
    root.geometry(f"+{(root.winfo_screenwidth() - root.winfo_width()) // 2}+0")
    root.mainloop()
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cage-session-helper")
    p.add_argument("mode", choices=["consent", "indicator"])
    p.add_argument("--requester", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--minutes", type=int, required=True)
    p.add_argument("--timeout", type=int, default=120)
    a = p.parse_args(argv)
    out = consent(a.requester, a.reason, a.minutes, a.timeout) if a.mode == "consent" else \
        indicator(a.requester, a.reason, a.minutes)
    print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
