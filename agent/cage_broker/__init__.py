"""Antiquarian's Cage privileged broker.

Runs as a separate Windows service (LocalSystem) and is the ONLY component allowed to change system configuration.
It listens on a local named pipe whose DACL admits only SYSTEM, Administrators and the agent service SID, rejects
remote clients, and for every request:
  1. re-validates the server-signed envelope itself (pinned Ed25519 key, device id, expiry, own replay store,
     allowlist, local schema) — the unprivileged agent's opinion is never trusted;
  2. executes the matching policy module;
  3. stores rollback state in its own SYSTEM-only directory (never accepts rollback data from the agent).
"""

__version__ = "0.4.0"
