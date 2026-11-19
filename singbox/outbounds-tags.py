#!/usr/bin/env python3
"""Extract tags from a JSON list of outbounds into a plain text file."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger("outbounds_tags")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-i", "--input", type=Path, required=True,
                   help="input JSON file (list of objects with a 'tag' field)")
    p.add_argument("-o", "--output", type=Path, default=Path("outbounds-tags.txt"),
                   help="output text file, one tag per line (default: %(default)s)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args()


def extract_tags(data: Any) -> list[str]:
    if not isinstance(data, list):
        raise ValueError("input JSON must be a list")
    tags: list[str] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or "tag" not in item:
            raise ValueError(f"item #{i} is not an object with a 'tag' field")
        tag = item["tag"]
        if not isinstance(tag, str):
            raise ValueError(f"item #{i} has non-string 'tag': {tag!r}")
        tags.append(tag)
    return tags


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")

    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        tags = extract_tags(data)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("%s", e)
        return 1

    args.output.write_text("".join(f"{t}\n" for t in tags), encoding="utf-8")
    log.info("wrote %d tags from %s to %s", len(tags), args.input, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
