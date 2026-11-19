#!/usr/bin/env bash
set -euo pipefail

# Usage: ./gencert.sh <domain> [output_dir]
DOMAIN="${1:?Usage: $0 <domain> [output_dir]}"
OUT_DIR="${2:-.}"

mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:4096 \
    -keyout "$OUT_DIR/key.pem" \
    -out "$OUT_DIR/cert.pem" \
    -sha256 -days 36500 -nodes \
    -subj "/CN=$DOMAIN"

sudo chmod 644 "$OUT_DIR/cert.pem" "$OUT_DIR/key.pem"

echo "Generated:"
echo "  $OUT_DIR/cert.pem"
echo "  $OUT_DIR/key.pem"
