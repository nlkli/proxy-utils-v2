#!/usr/bin/env python3
"""Download files from URLs with curl and merge their lines into one file."""
import argparse
import logging
import random
import subprocess
import tempfile
import time
from pathlib import Path

log = logging.getLogger("merge_lists")


def read_lines(path: Path) -> list[str]:
    """Return stripped lines, skipping blank lines and '#' comments."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def download(url: str, dest: Path, timeout: int) -> bool:
    """Download url to dest with curl. Log and return False on failure."""
    result = subprocess.run(
        ["curl", "-fsSL", "--max-time", str(timeout), "-o", str(dest), url],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error("Failed to download %s: %s", url, result.stderr.strip())
        return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls_file", type=Path, help="file with one URL per line")
    parser.add_argument("-o", "--output", type=Path, default=Path("merged.txt"))
    parser.add_argument("-t", "--timeout", type=int, default=60, help="seconds per file")
    parser.add_argument(
        "--dedupe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="remove duplicate lines, keeping first occurrence (default: on)",
    )
    parser.add_argument(
        "--shuffle",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="shuffle the merged list (default: on)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="random seed for shuffling (default: time-based)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="maximum number of lines in the output (default: 1000)",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = parse_args()

    urls = read_lines(args.urls_file)
    with tempfile.TemporaryDirectory() as tmp:
        downloaded: list[Path] = []
        for i, url in enumerate(urls):
            dest = Path(tmp) / f"{i}.txt"
            if download(url, dest, args.timeout):
                downloaded.append(dest)

        merged = []
        for path in downloaded:
            for line in read_lines(path):
                merged.append(line)
                if len(merged) >= args.limit:
                    break
            if len(merged) >= args.limit:
                break

    if args.dedupe:
        merged = list(dict.fromkeys(merged))

    if len(merged) > args.limit:
        merged = merged[: args.limit]

    if args.shuffle:
        seed = args.seed if args.seed is not None else int(time.time())
        log.info("Shuffling with seed %d", seed)
        rng = random.Random(seed)
        rng.shuffle(merged)

    args.output.write_text("\n".join(merged) + "\n", encoding="utf-8")
    log.info("Saved %d lines from %d/%d files to %s",
             len(merged), len(downloaded), len(urls), args.output)


if __name__ == "__main__":
    main()
