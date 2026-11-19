#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="data"
OUT_DIR="output"
SINGBOX_DIR="./singbox"
CERT_DOMAIN="dobro.ru"

CONFIG_DIRS=("$OUT_DIR")

LIST_URLS="$SINGBOX_DIR/list-urls.txt"
SELECTOR_SIZE=25
SUPER_SELECTOR_SIZE=8
TOR_COUNT=6
TOR_PORT=9020

PUB_LINKS="$DATA_DIR/pub-links.txt"
PUB_OUTBOUNDS="$DATA_DIR/pub-outbounds.json"
PUB_SELECTORS="$DATA_DIR/pub-selectors.json"
PUB_SUPER_SELECTORS="$DATA_DIR/pub-super-selectors.json"
PUB_SUPER_SELECTORS_TAGS="$DATA_DIR/pub-super-selectors-tags.txt"
PUB_TOR="$DATA_DIR/pub-tor.json"
PUB_TOR_TAGS="$DATA_DIR/pub-tor-tags.txt"
CONFIG="$DATA_DIR/config.json"
LINKS="$DATA_DIR/links.txt"

OUTBOUNDS_FILES=(
    "$PUB_OUTBOUNDS"
    "$PUB_SELECTORS"
    "$PUB_SUPER_SELECTORS"
    "$PUB_TOR"
)

mkdir -p "$DATA_DIR" "$OUT_DIR"

"$SINGBOX_DIR/merge-lists.py" "$LIST_URLS" -o "$PUB_LINKS"
# https://github.com/nlkli/sbcli
sbcli -lZ "$PUB_LINKS" -o "$PUB_OUTBOUNDS"
"$SINGBOX_DIR/add-selectors.py" "$PUB_OUTBOUNDS" -n "$SELECTOR_SIZE" -s "$SUPER_SELECTOR_SIZE" -o "$PUB_SELECTORS" -S "$PUB_SUPER_SELECTORS" -v
"$SINGBOX_DIR/outbounds-tags.py" -i "$PUB_SUPER_SELECTORS" -o "$PUB_SUPER_SELECTORS_TAGS" -v
"$SINGBOX_DIR/tor-socks-outbounds.py" -n "$TOR_COUNT" -p "$TOR_PORT" -o "$PUB_TOR" -v
"$SINGBOX_DIR/outbounds-tags.py" -i "$PUB_TOR" -o "$PUB_TOR_TAGS" -v
"$SINGBOX_DIR/setup-conf.py" --super-selector-tags "$PUB_SUPER_SELECTORS_TAGS" --tor-tags "$PUB_TOR_TAGS" --output "$CONFIG" --links "$LINKS" -v

for f in "${OUTBOUNDS_FILES[@]}"; do
    jq '{outbounds: .}' "$f" > "$OUT_DIR/$(basename "$f")"
done
cp -v "$CONFIG" "$OUT_DIR/"

CHECK_ARGS=()
for dir in "${CONFIG_DIRS[@]}"; do
    CHECK_ARGS+=(-C "$dir")
    "$SINGBOX_DIR/gencert.sh" "$CERT_DOMAIN" "$dir"
done
sing-box check "${CHECK_ARGS[@]}"

echo "stub"
