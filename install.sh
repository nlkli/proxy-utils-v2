#!/bin/sh
set -e

NAME="sync-proxy"
DIR="$(cd "$(dirname "$0")" && pwd)"
CMD="$DIR/sync-update.py"

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -n "$NAME" ] && [ -n "$DIR" ] && [ -n "$CMD" ] || { echo "Usage: $0 <name> <directory> <command>"; exit 1; }

cat > "/etc/systemd/system/$NAME.service" <<EOF
[Unit]
Description=$NAME
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DIR
ExecStart=$CMD
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$NAME.service"
systemctl status "$NAME.service" --no-pager
