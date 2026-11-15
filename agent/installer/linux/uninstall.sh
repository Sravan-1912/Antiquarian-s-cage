#!/usr/bin/env bash
# Stop, unenrol and remove the Cage agent. Run as root.
#   sudo ./installer/linux/uninstall.sh [--purge]
# --purge also deletes /var/lib/cage-agent (the device key and config).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
PURGE=""; [[ "${1:-}" == "--purge" ]] && PURGE=1

# Revoke this device's credentials from the console first (Endpoints -> the device -> Revoke credentials / Unenrol),
# then run this script to remove the local agent.
systemctl disable --now cage-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/cage-agent.service
systemctl daemon-reload
rm -rf /opt/cage-agent
[[ -n "$PURGE" ]] && rm -rf /var/lib/cage-agent
echo "Cage agent removed.${PURGE:+ (state purged)}"
