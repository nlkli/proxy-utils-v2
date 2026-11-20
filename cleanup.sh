#!/usr/bin/env bash
set -euo pipefail

NAME="sync-proxy"
DIR="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

sudo ./tor/tor-bridge-pool.py cleanup

systemctl disable --now "$NAME.service" 2>/dev/null || true
rm -f "/etc/systemd/system/$NAME.service"
systemctl daemon-reload
systemctl reset-failed
