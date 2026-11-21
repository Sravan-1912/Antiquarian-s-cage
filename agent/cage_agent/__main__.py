"""Command line: python -m cage_agent <command>

  collect                       Print the inventory this machine would report (no network).
  enroll --server URL --token T Enrol this endpoint using a one-time token from the console.
  run                           Run the agent loop in the foreground (the service uses the same loop).
  status                        Show enrollment state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cage_agent import __version__
from cage_agent.core import agent, configuration
from cage_agent.core.communication import AuthRejected, ServerError
from cage_agent.core.configuration import AgentPaths


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["session-helper"]:  # used by the packaged exe to show consent / indicator UI
        from cage_agent import session_helper
        return session_helper.main(argv[1:])
    p = argparse.ArgumentParser(prog="cage-agent", description="Antiquarian's Cage endpoint agent")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--data-dir", type=Path, default=configuration.DEFAULT_DATA_DIR)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("collect")
    e = sub.add_parser("enroll")
    e.add_argument("--server", required=True)
    e.add_argument("--token", required=True)
    e.add_argument("--key-scope", choices=["machine", "user"], default="machine")
    e.add_argument("--ca-bundle", help="PEM file to trust for the server's TLS certificate")
    e.add_argument("--allow-insecure-localhost", action="store_true",
                   help="Development only: permit http:// to localhost")
    e.add_argument("--service-account", help="Principal granted access to the key file (e.g. 'NT SERVICE\\CageAgent')")
    r = sub.add_parser("run")
    r.add_argument("--unlock-relay", choices=["on", "off", "dev"], default="on",
                   help="Lock-screen phone sign-in relay. 'dev' also admits the current user (testing only).")
    sub.add_parser("status")
    args = p.parse_args(argv)

    paths = AgentPaths(args.data_dir)
    if args.cmd == "collect":
        from cage_agent.collectors.inventory import collect_all
        print(json.dumps(collect_all(__version__), indent=2))
        return 0

    agent.setup_logging(paths, args.verbose)
    try:
        if args.cmd == "enroll":
            cfg = agent.enroll(paths, args.server, args.token, key_scope=args.key_scope,
                               allow_insecure_localhost=args.allow_insecure_localhost, ca_bundle=args.ca_bundle,
                               service_principal=args.service_account)
            print(f"Enrolled. Device ID: {cfg.device_id}")
            return 0
        if args.cmd == "status":
            print(json.dumps(agent.status(paths), indent=2))
            return 0
        if args.cmd == "run":
            try:
                return agent.Agent(paths, unlock_relay=args.unlock_relay).run()
            except KeyboardInterrupt:
                return 0
    except (configuration.ConfigError, AuthRejected, ServerError, PermissionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
