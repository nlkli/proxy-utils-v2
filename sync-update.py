#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

TIME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
INTERVAL_RE = re.compile(r"^[1-9][0-9]*[smhd]$")


def parse_interval(interval):
    unit = interval[-1]
    if unit not in TIME_UNITS:
        raise ValueError(f"bad unit: {unit!r}")
    return int(interval[:-1]) * TIME_UNITS[unit]


def is_due(last_time, interval):
    if not last_time:
        return True
    elapsed = datetime.now() - datetime.fromisoformat(last_time)
    return elapsed.total_seconds() >= parse_interval(interval)


def process_task(task):
    if not INTERVAL_RE.match(task["repeat"]):
        raise ValueError(f"bad repeat: {task['repeat']!r}")
    if is_due(task.get("last_time"), task["repeat"]):
        subprocess.run(task["cmd"], shell=True, check=False)
        task["last_time"] = datetime.now().isoformat(timespec="seconds")


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <tasks.json>")

    path = Path(sys.argv[1])
    try:
        tasks = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read {path}: {e}", file=sys.stderr)
        return 1

    for i, task in enumerate(tasks):
        try:
            process_task(task)
        except Exception as e:
            print(f"error: task[{i}]: {e}", file=sys.stderr)

    try:
        path.write_text(json.dumps(tasks, indent=2))
    except OSError as e:
        print(f"error: cannot write {path}: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
