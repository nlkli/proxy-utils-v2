#!/usr/bin/env python3
"""Pick the most stable outbound for every sing-box selector group via sbcli.

Strategy:
  1. Screening: one group delay test per group (cheap, covers all members).
     Members that do not answer are recorded as failures.
  2. Refinement: only the top-K candidates get extra single-proxy probes
     until each has `--min-samples` fresh samples (cached samples count).
  3. Ranking: score = median + 2 * stdev + failure_rate * timeout * 4 (lower is better),
     so stability (low jitter, no failures) outweighs raw latency.

Optionally, the ranked groups are assigned in order (round-robin) to "super groups",
selectors whose members are the groups themselves. Whenever no measurement is
available for a selector, a random member is selected instead.

Samples are cached on disk, expire after `--cache-ttl`, are capped per outbound,
and entries for tags missing from the input are dropped automatically.

Requires Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import logging
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("best-selector")

Sample = tuple[float, Optional[int]]  # (unix time, delay in ms; None = no answer)

JITTER_WEIGHT = 2.0
FAILURE_WEIGHT = 4.0


@dataclass(frozen=True)
class Score:
    tag: str
    success_rate: float
    median: float
    jitter: float
    value: float


class Sbcli:
    def __init__(self, binary: str, api: str | None, token: str | None,
                 url: str | None, timeout_ms: int) -> None:
        self.binary = binary
        self.base = [binary]
        if api:
            self.base += ["-a", api]
        if token:
            self.base += ["-T", token]
        self.probe = (["-u", url] if url else []) + ["-t", str(timeout_ms)]
        self.proc_timeout = timeout_ms / 1000 + 10

    def _run(self, *args: str) -> str | None:
        try:
            proc = subprocess.run([*self.base, *args], capture_output=True,
                                  text=True, timeout=self.proc_timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("sbcli %s failed: %s", args[0], exc)
            return None
        if proc.returncode != 0:
            log.debug("sbcli %s exit %d: %s", args, proc.returncode, proc.stderr.strip())
            return None
        return proc.stdout

    def _json(self, *args: str) -> object | None:
        out = self._run(*args)
        if out is None:
            return None
        try:
            return json.loads(out)
        except ValueError:
            log.debug("invalid JSON from sbcli %s", args)
            return None

    def group_delay(self, group: str) -> dict[str, int] | None:
        """Delays of answering members only; None if the call itself failed."""
        data = self._json("-D", group, *self.probe)
        if not isinstance(data, dict):
            return None
        return {k: v for k, v in data.items() if isinstance(v, int) and v > 0}

    def proxy_delay(self, tag: str) -> int | None:
        data = self._json("-d", tag, *self.probe)
        delay = data.get("delay") if isinstance(data, dict) else None
        return delay if isinstance(delay, int) and delay > 0 else None

    def select(self, group: str, tag: str) -> bool:
        return self._run("-s", group, tag) is not None

    def select_random(self, group: str) -> bool:
        return self._run("-S", group) is not None


class Cache:
    def __init__(self, path: Path, ttl: float, max_samples: int, url: str | None) -> None:
        self.path = path
        self.ttl = ttl
        self.max_samples = max_samples
        self.url = url or ""
        self.samples: dict[str, list[Sample]] = {}

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
            if raw["url"] != self.url:
                log.info("probe URL changed, cache discarded")
                return
            self.samples = {t: [(float(ts), d) for ts, d in rows]
                            for t, rows in raw["samples"].items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError):
            log.warning("cache unreadable, starting empty")

    def prune(self, valid_tags: set[str]) -> None:
        cutoff = time.time() - self.ttl
        pruned: dict[str, list[Sample]] = {}
        for tag, rows in self.samples.items():
            if tag not in valid_tags:
                continue
            rows = [r for r in rows if r[0] >= cutoff][-self.max_samples:]
            if rows:
                pruned[tag] = rows
        log.debug("cache pruned: %d -> %d tags", len(self.samples), len(pruned))
        self.samples = pruned

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"url": self.url, "samples": self.samples}))
        tmp.replace(self.path)

    def add(self, tag: str, delay: int | None) -> None:
        rows = self.samples.setdefault(tag, [])
        rows.append((time.time(), delay))
        del rows[:-self.max_samples]

    def count(self, tag: str) -> int:
        return len(self.samples.get(tag, []))

    def score(self, tag: str, timeout_ms: int) -> Score | None:
        rows = self.samples.get(tag, [])
        delays = [d for _, d in rows if d is not None]
        if not delays:
            return None
        rate = len(delays) / len(rows)
        median = statistics.median(delays)
        jitter = statistics.stdev(delays) if len(delays) > 1 else 0.0
        value = median + JITTER_WEIGHT * jitter + (1 - rate) * timeout_ms * FAILURE_WEIGHT
        return Score(tag, rate, median, jitter, value)


def rank(members: list[str], cache: Cache, timeout_ms: int) -> list[Score]:
    scores = (cache.score(m, timeout_ms) for m in members)
    return sorted((s for s in scores if s), key=lambda s: s.value)


def evaluate_group(group: str, members: list[str], cli: Sbcli,
                   cache: Cache, args: argparse.Namespace) -> Score | None:
    answered = cli.group_delay(group)
    if answered is None:
        log.warning("%s: group delay test failed", group)
    else:
        for tag in members:
            cache.add(tag, answered.get(tag))
        log.debug("%s: %d/%d members answered", group, len(answered), len(members))

    for cand in rank(members, cache, args.timeout)[:args.top]:
        for _ in range(args.min_samples - cache.count(cand.tag)):
            cache.add(cand.tag, cli.proxy_delay(cand.tag))

    ranking = rank(members, cache, args.timeout)
    return ranking[0] if ranking else None


def load_groups(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text())
    return {g["tag"]: list(g["outbounds"]) for g in data
            if g.get("type") == "selector" and g.get("outbounds")}


def apply_selection(cli: Sbcli, group: str, tag: str | None, enabled: bool) -> None:
    """Select `tag` in `group`, or a random member when `tag` is None."""
    target = tag or "<random>"
    if not enabled:
        log.info("%s -> %s (dry run)", group, target)
        return
    ok = cli.select(group, tag) if tag else cli.select_random(group)
    (log.info if ok else log.error)("%s -> %s %s", group, target, "applied" if ok else "FAILED")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    p.add_argument("groups_file", type=Path, help="JSON file with selector outbounds")
    p.add_argument("--sbcli", default="sbcli", help="sbcli binary (default: %(default)s)")
    p.add_argument("-a", "--api", help="controller URL (default: sbcli's own)")
    p.add_argument("-T", "--token", help="controller bearer token")
    p.add_argument("-u", "--url", help="probe URL (default: sbcli's own)")
    p.add_argument("-t", "--timeout", type=int, default=5000, help="probe timeout, ms")
    p.add_argument("--top", type=int, default=3, help="candidates to refine per group")
    p.add_argument("--min-samples", type=int, default=5,
                   help="samples required per refined candidate")
    p.add_argument("--max-samples", type=int, default=30, help="cache cap per outbound")
    p.add_argument("--cache", type=Path,
                   default=Path.home() / ".cache" / "best_outbound" / "cache.json")
    p.add_argument("--cache-ttl", type=float, default=3600, help="sample lifetime, seconds")
    p.add_argument("-s", "--super-groups", type=Path,
                   help="JSON file with super group selectors (members are groups)")
    p.add_argument("--apply", action="store_true",
                   help="apply selections (without it, only the plan is logged for super groups)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    try:
        groups = load_groups(args.groups_file)
        supers = load_groups(args.super_groups) if args.super_groups else {}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log.error("cannot read input: %s", exc)
        return 1
    if not groups:
        log.error("no selector groups found")
        return 1

    cli = Sbcli(args.sbcli, args.api, args.token, args.url, args.timeout)
    cache = Cache(args.cache, args.cache_ttl, args.max_samples, args.url)
    cache.load()
    cache.prune({m for members in groups.values() for m in members})

    best: dict[str, Score] = {}
    for i, (group, members) in enumerate(groups.items(), 1):
        score = evaluate_group(group, members, cli, cache, args)
        if score is None:
            log.warning("[%d/%d] %s: no working outbound, random pick", i, len(groups), group)
            continue
        best[group] = score
        log.info("[%d/%d] %s: best=%s median=%.0fms jitter=%.0fms ok=%.0f%%",
                 i, len(groups), group, score.tag, score.median,
                 score.jitter, score.success_rate * 100)

    cache.save()

    top = sorted(best, key=lambda g: best[g].value)
    log.info("%d/%d groups usable", len(top), len(groups))

    for group in groups:
        apply_selection(cli, group, best[group].tag if group in best else None, args.apply)

    for i, (tag, members) in enumerate(supers.items()):
        pick = top[i % len(top)] if top else None
        apply_selection(cli, tag, pick if pick in members else None, args.apply)

    return 0


if __name__ == "__main__":
    sys.exit(main())
