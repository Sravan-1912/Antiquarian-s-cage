#!/usr/bin/env bash
# Install, enrol and start the Cage agent as a systemd service on Linux. Run as root.
#
#   sudo ./installer/linux/install.sh --server https://your-server --token XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
#
# Options:
#   --server URL     the Cage server (https; the console's address)
#   --token  TOKEN   one-time enrolment token from the console (Endpoints -> Enrol an endpoint)
#   --binary PATH    path to the built cage-agent binary (default: ./dist/cage-agent)
#   --insecure       allow http:// for a localhost dev server (adds --allow-insecure-localhost)
set -euo pipefail

SERVER="" TOKEN="" BINARY="" INSECURE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="$2"; shift 2;;
    --token)  TOKEN="$2";  shift 2;;
    --binary) BINARY="$2"; shift 2;;
    --insecure) INSECURE="--allow-insecure-localhost"; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
[[ -n "$SERVER" && -n "$TOKEN" ]] || { echo "Both --server and --token are required." >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
BINARY="${BINARY:-$HERE/../../dist/cage-agent}"
[[ -x "$BINARY" ]] || { echo "Agent binary not found at $BINARY (build it first with build-linux.sh)." >&2; exit 1; }

install -d -m 0755 /opt/cage-agent
install -m 0755 "$BINARY" /opt/cage-agent/cage-agent
install -d -m 0700 /var/lib/cage-agent

echo "Enrolling with $SERVER ..."
/opt/cage-agent/cage-agent enroll --server "$SERVER" --token "$TOKEN" \
    --data-dir /var/lib/cage-agent --key-scope machine $INSECURE

install -m 0644 "$HERE/cage-agent.service" /etc/systemd/system/cage-agent.service
systemctl daemon-reload
systemctl enable --now cage-agent.service
echo
systemctl --no-pager status cage-agent.service | head -n 6 || true
echo
echo "Installed and running. The endpoint should appear in the console under Endpoints shortly."
echo "Logs:   journalctl -u cage-agent -f"
echo "Remove: ./installer/linux/uninstall.sh"
