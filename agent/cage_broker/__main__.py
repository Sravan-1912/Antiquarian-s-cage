"""cage-broker CLI.

  pin --agent-config PATH       Pin the device id + command public key from the enrolled agent's config
                                (run once by an administrator at install time).
  serve [--allow ACCOUNT ...]   Run the broker in the foreground. In production it runs as the CageBroker service
                                (LocalSystem) with --allow "NT SERVICE\\CageAgent".
  serve --dev-allow-current-user  Development: also admit the current (non-admin) user. Without elevation every
                                state-changing operation correctly fails with "requires administrator rights".
"""
from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import sys
import threading
from pathlib import Path

from cage_broker import __version__
from cage_broker.core import BrokerState, handle

DEFAULT_ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AntiquariansCage" / "broker"


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cage-broker")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--state-dir", type=Path, default=DEFAULT_ROOT)
    sub = p.add_subparsers(dest="cmd", required=True)
    pin = sub.add_parser("pin")
    pin.add_argument("--agent-config", type=Path, required=True)
    s = sub.add_parser("serve")
    s.add_argument("--allow", action="append", default=[], help="Account or SID allowed to connect")
    s.add_argument("--dev-allow-current-user", action="store_true")
    s.add_argument("--pipe-name", default=None)
    s.add_argument("--exit-after-minutes", type=float, default=None,
                   help="Stop automatically (useful for a time-boxed elevated test session)")
    args = p.parse_args(argv)

    state = BrokerState(args.state_dir)
    if args.cmd == "pin":
        cfg = json.loads(args.agent_config.read_text(encoding="utf-8"))
        extra = cfg.get("extra", {})
        if not cfg.get("device_id") or not extra.get("command_key_id"):
            print("error: agent is not enrolled or has not pinned a command key yet", file=sys.stderr)
            return 2
        state.pin(cfg["device_id"], extra["command_key_id"], extra["command_public_key"])
        print(f"Pinned device {cfg['device_id']} / key {extra['command_key_id']}")
        return 0

    from cage_broker import pipe
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=[logging.StreamHandler(),
                                  logging.handlers.RotatingFileHandler(args.state_dir / "broker.log",
                                                                       maxBytes=2_000_000, backupCount=5,
                                                                       encoding="utf-8")])
    sids = [pipe.sid_for(a) for a in args.allow]
    if args.dev_allow_current_user:
        sids.append(pipe.current_user_sid())
    stop = threading.Event()
    name = args.pipe_name or pipe.PIPE_NAME
    if args.exit_after_minutes:
        def _expire():
            logging.getLogger("cage_broker").info("time box reached; stopping")
            stop.set()
            pipe.wake(name)
        threading.Timer(args.exit_after_minutes * 60, _expire).start()
    logging.getLogger("cage_broker").info("broker %s listening (pinned: %s, elevated: %s)", __version__,
                                          bool(state.pinned()), _is_admin())
    try:
        pipe.serve(lambda req: {"pong": True} if req.get("ping") else handle(state, req), sids, stop, name)
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
