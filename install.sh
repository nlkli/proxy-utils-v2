#!/bin/sh
set -e

NAME="sync-proxy"
DIR="$(cd "$(dirname "$0")" && pwd)"
CMD="$DIR/sync-update.py $DIR/sync-tasks.json"

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

sudo apt install tor obfs4proxy -y
# install sbcli https://github.com/nlkli/sbcli ...

command -v sing-box >/dev/null 2>&1 || curl -fsSL https://sing-box.app/install.sh | sh

mkdir -p data
: > data/passwords.txt
: > data/uuids.txt

i=0
while [ "$i" -lt 200 ]; do
    sing-box generate rand --hex 16 >> data/passwords.txt
    i=$((i + 1))
done

i=0
while [ "$i" -lt 100 ]; do
    sing-box generate uuid >> data/uuids.txt
    i=$((i + 1))
done

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

./update-singbox-conf.sh

sleep 5

systemctl daemon-reload
systemctl enable --now "$NAME.service"
systemctl status "$NAME.service" --no-pager
