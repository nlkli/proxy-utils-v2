#!/usr/bin/env python3
"""Split outbound tags into chunks and write a selector outbound per chunk to a separate file."""

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger("add_selectors")

Outbound = dict[str, Any]


def collect_tags(outbounds: list[Outbound]) -> list[str]:
    """Return tags of proxy outbounds, skipping existing selectors."""
    return [o["tag"] for o in outbounds if "tag" in o and o.get("type") != "selector"]


def chunked(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def make_selector(tags: list[str]) -> Outbound:
    return {"type": "selector", "tag": str(uuid.uuid4()), "outbounds": tags}


def write_json(path: Path, data: list[Outbound]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.info("wrote %s", path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path, help="JSON file with outbounds")
    p.add_argument("-n", "--chunk-size", type=int, required=True, help="tags per selector")
    p.add_argument("-o", "--output", type=Path, default=Path("selector-outbounds.json"),
                   help="selectors file (default: %(default)s)")
    p.add_argument("-S", "--super-output", type=Path, default=Path("super-selector-outbounds.json"),
                   help="super selectors file (default: %(default)s)")
    p.add_argument("-s", "--super-count", type=int, default=0,
                   help="number of super selectors, each listing all selectors; 0 = none (default)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = p.parse_args()
    if args.chunk_size < 1:
        p.error("--chunk-size must be >= 1")
    if args.super_count < 0:
        p.error("--super-count must be >= 0")
    return args


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")

    try:
        outbounds: list[Outbound] = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.error("cannot read %s: %s", args.input, e)
        return 1
    if not isinstance(outbounds, list):
        log.error("%s: top-level JSON must be a list", args.input)
        return 1

    tags = collect_tags(outbounds)
    selectors = [make_selector(c) for c in chunked(tags, args.chunk_size)]
    log.info("%d tags -> %d selectors", len(tags), len(selectors))
    for s in selectors:
        log.debug("selector %s: %d outbounds", s["tag"], len(s["outbounds"]))

    write_json(args.output, selectors)

    if args.super_count:
        selector_tags = [s["tag"] for s in selectors]
        supers = [make_selector(selector_tags) for _ in range(args.super_count)]
        write_json(args.super_output, supers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
