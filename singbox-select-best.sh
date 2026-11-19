#!/usr/bin/env bash
set -euo pipefail

sleep 1

./singbox/best-selector.py ./data/pub-selectors.json \
    -s ./data/pub-super-selectors.json \
    --cache ./data/best-selector-cache.json -v \
    --apply
