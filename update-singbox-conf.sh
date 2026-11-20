#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="data"
OUT_DIR="output"
SINGBOX_DIR="./singbox"
CERT_DOMAIN="dobro.ru"

LIST_URLS="$SINGBOX_DIR/list-urls.txt"
SELECTOR_SIZE=30
SUPER_SELECTOR_SIZE=12
TOR_COUNT=6
TOR_PORT=9020
SERVER_HOST=0.0.0.0

mkdir -p "$DATA_DIR" "$OUT_DIR"

"$SINGBOX_DIR/merge-lists.py" \
    "$LIST_URLS" \
    -o "$DATA_DIR/pub-links.txt"

sbcli -lZ \
    "$DATA_DIR/pub-links.txt" \
    -o "$DATA_DIR/pub-outbounds.json"

"$SINGBOX_DIR/add-selectors.py" \
    "$DATA_DIR/pub-outbounds.json" \
    -n "$SELECTOR_SIZE" \
    -s "$SUPER_SELECTOR_SIZE" \
    -o "$DATA_DIR/pub-selectors.json" \
    -S "$DATA_DIR/pub-super-selectors.json" \
    -v

"$SINGBOX_DIR/outbounds-tags.py" \
    -i "$DATA_DIR/pub-super-selectors.json" \
    -o "$DATA_DIR/pub-super-selectors-tags.txt" \
    -v

"$SINGBOX_DIR/tor-socks-outbounds.py" \
    -n "$TOR_COUNT" \
    -p "$TOR_PORT" \
    -o "$DATA_DIR/pub-tor.json" \
    -v

"$SINGBOX_DIR/outbounds-tags.py" \
    -i "$DATA_DIR/pub-tor.json" \
    -o "$DATA_DIR/pub-tor-tags.txt" \
    -v

"$SINGBOX_DIR/setup-conf.py" \
    "$SERVER_HOST" \
    --super-selector-tags "$DATA_DIR/pub-super-selectors-tags.txt" \
    --tor-tags            "$DATA_DIR/pub-tor-tags.txt" \
    --output              "$DATA_DIR/config.json" \
    --links               "$DATA_DIR/links.txt" \
    --passwords           "$DATA_DIR/passwords.txt" \
    --uuids               "$DATA_DIR/uuids.txt" \
    -v

for f in pub-outbounds.json pub-selectors.json pub-super-selectors.json pub-tor.json; do
    jq '{outbounds: .}' "$DATA_DIR/$f" > "$OUT_DIR/$f"
done

cp -v "$DATA_DIR/config.json" "$OUT_DIR/"

"$SINGBOX_DIR/gencert.sh" "$CERT_DOMAIN" "$OUT_DIR"

sing-box check -C "$OUT_DIR"

sudo systemctl restart sing-box.service

sleep 10

rm -f "$DATA_DIR/best-selector-cache.json"

./singbox-select-best.sh
