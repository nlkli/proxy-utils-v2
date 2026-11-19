#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

TIME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
INTERVAL_RE = re.compile(r"^[1-9][0-9]*[smhd]$")


def log(msg, file=sys.stdout):
    print(msg, file=file, flush=True)


def parse_interval(interval):
    return int(interval[:-1]) * TIME_UNITS[interval[-1]]


def is_due(last_time, interval):
    if not last_time:
        return True
    elapsed = datetime.now() - datetime.fromisoformat(last_time)
    return elapsed.total_seconds() >= parse_interval(interval)


def process_task(i, task):
    """Returns True if the task ran successfully (last_time updated)."""
    if not INTERVAL_RE.match(task["repeat"]):
        raise ValueError(f"bad repeat: {task['repeat']!r}")
    if not is_due(task.get("last_time"), task["repeat"]):
        return False

    log(f"[task {i}] start: {task['cmd']}")
    result = subprocess.run(task["cmd"], shell=True)  # stdout/stderr go straight to journal
    if result.returncode != 0:
        log(f"[task {i}] FAILED, exit code {result.returncode}", sys.stderr)
        return False

    task["last_time"] = datetime.now().isoformat(timespec="seconds")
    log(f"[task {i}] done, exit code 0")
    return True


def save(path, tasks):
    path.write_text(json.dumps(tasks, indent=2))


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <tasks.json>")

    path = Path(sys.argv[1])
    try:
        tasks = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        log(f"error: cannot read {path}: {e}", sys.stderr)
        return 1

    for i, task in enumerate(tasks):
        try:
            if process_task(i, task):
                save(path, tasks)
        except Exception as e:
            log(f"[task {i}] error: {e}", sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
