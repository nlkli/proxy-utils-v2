#!/usr/bin/env python3
"""Generate socks outbounds for a local range of Tor SOCKS ports."""

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger("tor_socks_outbounds")

Outbound = dict[str, Any]
MAX_PORT = 65535


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError(f"port must be in 1..{MAX_PORT}")
    return port


def make_outbound(port: int) -> Outbound:
    return {
        "type": "socks",
        "tag": str(uuid.uuid4()),
        "server": "127.0.0.1",
        "server_port": port,
        "version": "5",
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-n", "--count", type=int, required=True, help="number of outbounds")
    p.add_argument("-p", "--base-port", type=_port, default=9100,
                   help="first port, next ones are incremented by 1 (default: %(default)s)")
    p.add_argument("-o", "--output", type=Path, default=Path("tor-socks-outbounds.json"),
                   help="output file (default: %(default)s)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = p.parse_args()
    if args.count < 1:
        p.error("--count must be >= 1")
    if args.base_port + args.count - 1 > MAX_PORT:
        p.error(f"ports exceed {MAX_PORT}")
    return args


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")

    outbounds = [make_outbound(args.base_port + i) for i in range(args.count)]
    args.output.write_text(json.dumps(outbounds, indent=2) + "\n", encoding="utf-8")
    log.info("wrote %d outbounds (ports %d-%d) to %s", args.count, args.base_port,
             args.base_port + args.count - 1, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
