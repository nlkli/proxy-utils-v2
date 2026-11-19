#!/usr/bin/env bash
set -euo pipefail

./tor/merge_lists.py ./tor/list_urls.txt \
    -o ./data/tor-bridge-list.txt --limit 250

./tor/tor_bridge_tester.py ./data/tor-bridge-list.txt \
    --top 200 --out ./data/tor-top-bridge.txt -v  \
    --cache-file ./data/tor-bridge-tester_cache.json \
    --workers 10 --attempts 3 --bootstrap-timeout 30 \
    --curl-timeout 10 --download-timeout 20 \
    --download-url "https://speed.cloudflare.com/__down?bytes=200000" \
    --probe-attempts 2 --probe-timeout 3

sudo ./tor/tor-bridge-pool.py \
    apply -b ./data/tor-top-bridge.txt -n 6 -p 9020 --check
