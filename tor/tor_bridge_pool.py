#!/usr/bin/env python3
"""tor-bridge-pool: run several Tor client instances, each with its own bridges.

The bridge list is split round-robin between N instances (bridge ``i`` goes to
instance ``i % N``), so the best bridges (top of the file) are spread evenly.
Every instance is a native Debian ``tor@NAME.service`` created with
``tor-instance-create`` and exposes its own local SOCKS5 port.

Commands:
    apply    Create/update instances from a bridge file (idempotent).
    status   Show managed instances, ports and bridge counts.
    cleanup  Remove every instance managed by this tool.

Must be run as root (except with ``--dry-run`` / ``status``).
Target platform: Debian 13 with the ``tor`` and ``lyrebird`` packages.
"""

import argparse
import contextlib
import dataclasses
import fcntl
import grp
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("tor-bridge-pool")

INSTANCES_ETC = Path("/etc/tor/instances")
INSTANCES_VAR = Path("/var/lib/tor-instances")
LOCK_PATH = Path("/run/lock/tor-bridge-pool.lock")
MARKER = "# Managed by tor-bridge-pool"
TORRC_NAME = "torrc"
BRIDGES_NAME = "bridges.conf"

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_USAGE = 2

_ADDR_RE = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
_FPR_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_TRANSPORT_RE = re.compile(r"^[A-Za-z0-9_]+$")
_PREFIX_RE = re.compile(r"^[a-z][a-z0-9-]{0,15}$")
_BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%")


class ToolError(Exception):
    """Base class for expected, user-reportable errors."""


class CommandError(ToolError):
    """An external command failed, timed out or was not found."""


@dataclasses.dataclass(frozen=True, slots=True)
class Bridge:
    """A single validated bridge line (without the ``Bridge`` keyword)."""

    line: str
    transport: Optional[str]  # None for plain (non-pluggable) bridges


@dataclasses.dataclass(slots=True)
class InstanceReport:
    """Outcome of deploying one instance."""

    name: str
    port: int
    bridges: int
    action: str = "unchanged"
    error: Optional[str] = None
    bootstrap: Optional[int] = None


def parse_bridge(raw: str) -> Bridge:
    """Validate one bridge line and normalise whitespace.

    Accepted forms (an optional leading ``Bridge`` keyword is stripped)::

        IP:PORT [FINGERPRINT]
        TRANSPORT IP:PORT [FINGERPRINT] [key=value ...]

    Raises:
        ValueError: if the line is not a recognisable bridge definition.
    """
    line = raw.strip()
    if line.lower().startswith("bridge "):
        line = line[len("bridge "):]
    tokens = line.split()
    if not tokens:
        raise ValueError("empty line")

    transport: Optional[str] = None
    addr_idx = 0
    if not _ADDR_RE.match(tokens[0]):
        if (
            len(tokens) > 1
            and _TRANSPORT_RE.match(tokens[0])
            and _ADDR_RE.match(tokens[1])
        ):
            transport = tokens[0].lower()
            tokens[0] = transport
            addr_idx = 1
        else:
            raise ValueError("expected '[transport] IP:PORT ...'")

    match = _ADDR_RE.match(tokens[addr_idx])
    assert match is not None
    if not 0 < int(match.group(1)) <= 65535:
        raise ValueError("port out of range")

    rest = tokens[addr_idx + 1:]
    if transport is None and rest and not _FPR_RE.match(rest[0]):
        raise ValueError("invalid fingerprint (expected 40 hex characters)")
    return Bridge(line=" ".join(tokens), transport=transport)


def load_bridges(path: Path) -> list[Bridge]:
    """Read a bridge file; skip blanks, comments, invalid lines and duplicates."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ToolError(f"cannot read bridge file {path}: {exc}") from exc

    bridges: list[Bridge] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            bridge = parse_bridge(stripped)
        except ValueError as exc:
            LOG.warning("%s:%d: skipped invalid bridge (%s): %.80s", path, lineno, exc, stripped)
            continue
        if bridge.line in seen:
            LOG.debug("%s:%d: duplicate skipped", path, lineno)
            continue
        seen.add(bridge.line)
        bridges.append(bridge)
    return bridges


def filter_supported(bridges: Sequence[Bridge], plugins: dict[str, str]) -> list[Bridge]:
    """Drop bridges whose transport has no configured plugin binary."""
    usable: list[Bridge] = []
    missing: dict[str, int] = {}
    for bridge in bridges:
        if bridge.transport is None or bridge.transport in plugins:
            usable.append(bridge)
        else:
            missing[bridge.transport] = missing.get(bridge.transport, 0) + 1
    for transport, count in missing.items():
        LOG.warning(
            "skipped %d '%s' bridge(s): no plugin (use --transport %s=/path/to/binary)",
            count, transport, transport,
        )
    return usable


def distribute(bridges: Sequence[Bridge], instances: int) -> list[list[Bridge]]:
    """Split bridges round-robin; never returns empty groups.

    With 5 bridges and 2 instances: instance 0 gets 1,3,5; instance 1 gets 2,4.
    With fewer bridges than instances, only ``len(bridges)`` groups are made.
    """
    count = min(instances, len(bridges))
    return [list(bridges[i::count]) for i in range(count)]


def render_bridges(bridges: Sequence[Bridge]) -> str:
    """Render the ``bridges.conf`` file content."""
    body = "\n".join(f"Bridge {b.line}" for b in bridges)
    return f"{MARKER}\n{body}\n"


def render_torrc(
    *,
    name: str,
    listen: str,
    port: int,
    bridges_file: Path,
    plugins: dict[str, str],
    extra: str,
) -> str:
    """Render a minimal client-only torrc.

    ``DataDirectory``, ``User`` and ``PidFile`` are deliberately absent: the
    Debian ``tor@.service`` unit passes them on the command line.
    """
    host = f"[{listen}]" if ":" in listen and not listen.startswith("[") else listen
    lines = [
        MARKER,
        f"# Instance: {name}. Regenerated on every run; put custom options in --extra-torrc.",
        "ClientOnly 1",
        f"SocksPort {host}:{port}",
        "SafeLogging 1",
        "AvoidDiskWrites 1",
        "UseBridges 1",
    ]
    by_path: dict[str, list[str]] = {}
    for transport, path in sorted(plugins.items()):
        by_path.setdefault(path, []).append(transport)
    for path, transports in by_path.items():
        lines.append(f"ClientTransportPlugin {','.join(transports)} exec {path}")
    lines.append(f"%include {bridges_file}")
    if extra.strip():
        lines += ["# --- extra options ---", extra.rstrip()]
    return "\n".join(lines) + "\n"


def run_command(
    cmd: Sequence[str], *, timeout: float = 60.0, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run a command and capture its output.

    Raises:
        CommandError: on missing binary, timeout, or non-zero exit if ``check``.
    """
    LOG.debug("exec: %s", shlex.join(cmd))
    try:
        proc = subprocess.run(
            list(cmd), capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise CommandError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"timed out after {timeout:.0f}s: {shlex.join(cmd)}") from exc
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise CommandError(f"{shlex.join(cmd)} failed (rc={proc.returncode}): {detail}")
    return proc


def write_if_changed(
    path: Path, content: str, *, mode: int, group: Optional[str], dry_run: bool
) -> bool:
    """Atomically write ``content`` to ``path`` if it differs. Returns True if changed."""
    try:
        current: Optional[str] = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = None
    if current == content:
        return False
    if dry_run:
        LOG.info("[dry-run] would write %s", path)
        return True

    gid = -1
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            LOG.warning("group %s not found; falling back to world-readable %s", group, path.name)
            mode = 0o644

    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, mode)
        if gid != -1:
            os.chown(tmp_name, 0, gid)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise
    return True


@contextlib.contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Hold a non-blocking exclusive lock to prevent concurrent runs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToolError("another tor-bridge-pool run is in progress") from exc
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


class Systemd:
    """Thin wrapper over ``systemctl`` for ``tor@NAME.service`` units."""

    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run

    @staticmethod
    def unit(name: str) -> str:
        return f"tor@{name}.service"

    def is_active(self, name: str) -> bool:
        proc = run_command(["systemctl", "is-active", "--quiet", self.unit(name)], check=False)
        return proc.returncode == 0

    def _mutate(self, *args: str, timeout: float = 120.0, check: bool = True) -> None:
        if self.dry_run:
            LOG.info("[dry-run] systemctl %s", " ".join(args))
            return
        run_command(["systemctl", *args], timeout=timeout, check=check)

    def enable_now(self, name: str) -> None:
        self._mutate("enable", "--now", self.unit(name))

    def enable(self, name: str) -> None:
        self._mutate("enable", self.unit(name))

    def restart(self, name: str) -> None:
        self._mutate("restart", self.unit(name))

    def reload(self, name: str) -> None:
        self._mutate("reload", self.unit(name))

    def disable_now(self, name: str) -> None:
        self._mutate("disable", "--now", self.unit(name), check=False)

    def bootstrap_progress(self, name: str) -> int:
        """Return the last ``Bootstrapped N%`` seen in the current unit invocation."""
        inv = run_command(
            ["systemctl", "show", "-p", "InvocationID", "--value", self.unit(name)],
            check=False,
        ).stdout.strip()
        if not inv:
            return 0
        logs = run_command(
            ["journalctl", f"_SYSTEMD_INVOCATION_ID={inv}", "-o", "cat", "--no-pager"],
            check=False,
        ).stdout
        found = _BOOTSTRAP_RE.findall(logs)
        return int(found[-1]) if found else 0


def _is_adoptable(torrc: Path) -> bool:
    """True if the torrc is ours, or is the untouched stub from tor-instance-create."""
    try:
        text = torrc.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return True
    if MARKER in text:
        return True
    return all(not ln.strip() or ln.lstrip().startswith("#") for ln in text.splitlines())


def discover_managed(prefix: str) -> list[str]:
    """List instance names under /etc/tor/instances that carry our marker."""
    pattern = re.compile(rf"^{re.escape(prefix)}\d+$")
    names: list[str] = []
    if not INSTANCES_ETC.is_dir():
        return names
    for entry in sorted(INSTANCES_ETC.iterdir()):
        if not (entry.is_dir() and pattern.match(entry.name)):
            continue
        try:
            if MARKER in (entry / TORRC_NAME).read_text(encoding="utf-8", errors="replace"):
                names.append(entry.name)
        except OSError:
            continue
    return names


def deploy_instance(
    *,
    name: str,
    port: int,
    listen: str,
    bridges: Sequence[Bridge],
    plugins: dict[str, str],
    extra: str,
    systemd: Systemd,
    dry_run: bool,
) -> str:
    """Create or update one instance. Returns the action taken."""
    etc_dir = INSTANCES_ETC / name
    created = False
    if not etc_dir.exists():
        LOG.info("creating instance %s", name)
        if dry_run:
            LOG.info("[dry-run] tor-instance-create %s", name)
        else:
            run_command(["tor-instance-create", name])
        created = True
    elif not _is_adoptable(etc_dir / TORRC_NAME):
        raise ToolError(f"{etc_dir} exists and is not managed by this tool; refusing to touch it")

    used = {b.transport for b in bridges if b.transport}
    instance_plugins = {t: p for t, p in plugins.items() if t in used}
    group = f"_tor-{name}"

    bridges_changed = write_if_changed(
        etc_dir / BRIDGES_NAME, render_bridges(bridges),
        mode=0o640, group=group, dry_run=dry_run,
    )
    torrc_changed = write_if_changed(
        etc_dir / TORRC_NAME,
        render_torrc(
            name=name, listen=listen, port=port,
            bridges_file=etc_dir / BRIDGES_NAME, plugins=instance_plugins, extra=extra,
        ),
        mode=0o640, group=group, dry_run=dry_run,
    )

    active = (not dry_run or not created) and systemd.is_active(name)
    if not active:
        systemd.enable_now(name)
        return "created+started" if created else "started"
    systemd.enable(name)
    if torrc_changed:
        systemd.restart(name)
        return "restarted"
    if bridges_changed:
        systemd.reload(name)
        return "reloaded"
    return "unchanged"


def remove_instance(name: str, systemd: Systemd, dry_run: bool) -> None:
    """Stop and delete an instance created by this tool."""
    LOG.info("removing instance %s", name)
    systemd.disable_now(name)
    if dry_run:
        LOG.info("[dry-run] would delete %s, %s and user _tor-%s", INSTANCES_ETC / name,
                 INSTANCES_VAR / name, name)
        return
    shutil.rmtree(INSTANCES_ETC / name, ignore_errors=True)
    shutil.rmtree(INSTANCES_VAR / name, ignore_errors=True)
    run_command(["userdel", f"_tor-{name}"], check=False)


def wait_bootstrapped(systemd: Systemd, name: str, timeout: float) -> int:
    """Poll until the instance reaches 100% or ``timeout`` expires; return progress."""
    deadline = time.monotonic() + timeout
    progress = 0
    while True:
        try:
            progress = systemd.bootstrap_progress(name)
        except ToolError as exc:
            LOG.debug("bootstrap probe failed for %s: %s", name, exc)
        if progress >= 100 or time.monotonic() >= deadline:
            return progress
        time.sleep(2.0)


def preflight(*, need_root: bool) -> None:
    """Verify the environment before touching anything."""
    if need_root and os.geteuid() != 0:
        raise ToolError("root privileges required (use sudo, or --dry-run)")
    for tool in ("tor-instance-create", "systemctl"):
        if shutil.which(tool) is None:
            raise ToolError(
                f"'{tool}' not found; install with: apt install tor"
                if tool == "tor-instance-create" else f"'{tool}' not found"
            )


def resolve_plugins(overrides: Sequence[str]) -> dict[str, str]:
    """Build the transport->binary map: auto-detect obfs4, then apply overrides."""
    plugins: dict[str, str] = {}
    for binary in ("lyrebird", "obfs4proxy"):
        found = shutil.which(binary)
        if found:
            plugins["obfs4"] = found
            break
    for item in overrides:
        name, sep, path = item.partition("=")
        if not sep or not _TRANSPORT_RE.match(name) or not path:
            raise ToolError(f"invalid --transport value {item!r}; expected NAME=/path/to/binary")
        if not Path(path).is_file():
            LOG.warning("transport binary %s does not exist", path)
        plugins[name.lower()] = path
    return plugins


def cmd_apply(args: argparse.Namespace) -> int:
    """Create/update instances from the bridge file."""
    preflight(need_root=not args.dry_run)

    bridges = load_bridges(args.bridges)
    if not bridges:
        LOG.info("no valid bridges in %s; nothing to do", args.bridges)
        return EXIT_OK

    plugins = resolve_plugins(args.transport)
    if any(b.transport == "obfs4" for b in bridges) and "obfs4" not in plugins:
        LOG.warning("obfs4 bridges found but neither lyrebird nor obfs4proxy is installed "
                    "(apt install lyrebird)")
    bridges = filter_supported(bridges, plugins)
    if not bridges:
        LOG.info("no usable bridges left; nothing to do")
        return EXIT_OK

    groups = distribute(bridges, args.instances)
    if args.base_port + len(groups) - 1 > 65535:
        raise ToolError("base port + instance count exceeds 65535")

    extra = ""
    if args.extra_torrc:
        try:
            extra = args.extra_torrc.read_text(encoding="utf-8")
        except OSError as exc:
            raise ToolError(f"cannot read {args.extra_torrc}: {exc}") from exc

    if args.listen not in ("127.0.0.1", "::1", "localhost"):
        LOG.warning("SOCKS ports are bound to %s: make sure they are not exposed", args.listen)

    systemd = Systemd(args.dry_run)
    reports: list[InstanceReport] = []
    wanted = {f"{args.prefix}{i}" for i in range(len(groups))}

    lock = contextlib.nullcontext() if args.dry_run else exclusive_lock(LOCK_PATH)
    with lock:
        LOG.info("%d bridge(s) -> %d instance(s)", len(bridges), len(groups))
        for idx, group in enumerate(groups):
            report = InstanceReport(f"{args.prefix}{idx}", args.base_port + idx, len(group))
            try:
                report.action = deploy_instance(
                    name=report.name, port=report.port, listen=args.listen,
                    bridges=group, plugins=plugins, extra=extra,
                    systemd=systemd, dry_run=args.dry_run,
                )
            except (ToolError, OSError) as exc:
                LOG.error("instance %s failed: %s", report.name, exc)
                report.error = str(exc)
            reports.append(report)

        if not args.no_prune:
            for stale in sorted(set(discover_managed(args.prefix)) - wanted):
                try:
                    remove_instance(stale, systemd, args.dry_run)
                except (ToolError, OSError) as exc:
                    LOG.error("cannot remove stale instance %s: %s", stale, exc)

    if args.check and not args.dry_run:
        _run_checks(systemd, [r for r in reports if r.error is None], args.check_timeout)

    _print_report(reports)
    return EXIT_PARTIAL if any(r.error for r in reports) else EXIT_OK


def _run_checks(systemd: Systemd, reports: list[InstanceReport], timeout: float) -> None:
    """Wait for all instances to bootstrap, in parallel."""
    if not reports:
        return
    LOG.info("waiting up to %.0fs for bootstrap...", timeout)
    with ThreadPoolExecutor(max_workers=len(reports)) as pool:
        results = pool.map(lambda r: wait_bootstrapped(systemd, r.name, timeout), reports)
        for report, progress in zip(reports, results):
            report.bootstrap = progress


def _print_report(reports: Sequence[InstanceReport]) -> None:
    """Print a summary table to stdout."""
    print(f"{'INSTANCE':<14}{'SOCKS PORT':<12}{'BRIDGES':<9}{'ACTION':<18}NOTE")
    for r in reports:
        note = r.error or ("" if r.bootstrap is None else f"bootstrap {r.bootstrap}%")
        print(f"{r.name:<14}{r.port:<12}{r.bridges:<9}{r.action if not r.error else 'FAILED':<18}{note}")


def cmd_status(args: argparse.Namespace) -> int:
    """Show managed instances."""
    systemd = Systemd(dry_run=True)
    names = discover_managed(args.prefix)
    if not names:
        print("no managed instances found")
        return EXIT_OK
    print(f"{'INSTANCE':<14}{'STATE':<10}{'SOCKS':<24}{'BRIDGES':<9}BOOTSTRAP")
    for name in names:
        etc = INSTANCES_ETC / name
        torrc = (etc / TORRC_NAME).read_text(encoding="utf-8", errors="replace")
        port = re.search(r"^SocksPort\s+(\S+)", torrc, re.MULTILINE)
        try:
            count = len(re.findall(r"^Bridge\s", (etc / BRIDGES_NAME).read_text(), re.MULTILINE))
        except OSError:
            count = 0
        active = systemd.is_active(name)
        progress = f"{systemd.bootstrap_progress(name)}%" if active else "-"
        print(f"{name:<14}{'active' if active else 'inactive':<10}"
              f"{port.group(1) if port else '?':<24}{count:<9}{progress}")
    return EXIT_OK


def cmd_cleanup(args: argparse.Namespace) -> int:
    """Remove all managed instances."""
    preflight(need_root=not args.dry_run)
    systemd = Systemd(args.dry_run)
    names = discover_managed(args.prefix)
    if not names:
        LOG.info("no managed instances to remove")
        return EXIT_OK
    failed = False
    lock = contextlib.nullcontext() if args.dry_run else exclusive_lock(LOCK_PATH)
    with lock:
        for name in names:
            try:
                remove_instance(name, systemd, args.dry_run)
            except (ToolError, OSError) as exc:
                LOG.error("cannot remove %s: %s", name, exc)
                failed = True
    return EXIT_PARTIAL if failed else EXIT_OK


def _prefix_type(value: str) -> str:
    if not _PREFIX_RE.match(value):
        raise argparse.ArgumentTypeError("must match [a-z][a-z0-9-]{0,15}")
    return value


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _port(value: str) -> int:
    number = int(value)
    if not 1024 <= number <= 65535:
        raise argparse.ArgumentTypeError("must be in 1024..65535")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="tor_bridge_pool", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="errors only")
    parser.add_argument("--log-file", type=Path, help="also write logs to this file")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--prefix", type=_prefix_type, default="tbr",
                        help="instance name prefix (default: tbr -> tbr0, tbr1, ...)")
    common.add_argument("--dry-run", action="store_true",
                        help="show what would be done without changing anything")

    sub = parser.add_subparsers(dest="command", required=True)

    apply_p = sub.add_parser("apply", parents=[common], help="create/update instances")
    apply_p.add_argument("-b", "--bridges", type=Path, required=True, help="bridge list file")
    apply_p.add_argument("-n", "--instances", type=_positive_int, default=4,
                         help="number of Tor processes (default: 4)")
    apply_p.add_argument("-p", "--base-port", type=_port, default=9100,
                         help="SOCKS port of the first instance; next ones use +1 (default: 9100)")
    apply_p.add_argument("--listen", default="127.0.0.1",
                         help="SOCKS listen address (default: 127.0.0.1)")
    apply_p.add_argument("--transport", action="append", default=[], metavar="NAME=PATH",
                         help="pluggable transport binary, repeatable "
                              "(obfs4 is auto-detected: lyrebird/obfs4proxy)")
    apply_p.add_argument("--extra-torrc", type=Path,
                         help="file with extra torrc options appended to every instance")
    apply_p.add_argument("--no-prune", action="store_true",
                         help="keep managed instances that are no longer needed")
    apply_p.add_argument("--check", action="store_true",
                         help="wait until every instance bootstraps to 100%%")
    apply_p.add_argument("--check-timeout", type=float, default=120.0,
                         help="bootstrap wait limit in seconds (default: 120)")
    apply_p.set_defaults(func=cmd_apply)

    status_p = sub.add_parser("status", help="show managed instances")
    status_p.add_argument("--prefix", type=_prefix_type, default="tbr")
    status_p.set_defaults(func=cmd_status)

    clean_p = sub.add_parser("cleanup", parents=[common], help="remove all managed instances")
    clean_p.set_defaults(func=cmd_cleanup)
    return parser


def setup_logging(verbose: bool, quiet: bool, log_file: Optional[Path]) -> None:
    """Configure console (stderr) and optional file logging."""
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level, handlers=handlers,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S",
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Program entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    try:
        setup_logging(args.verbose, args.quiet, args.log_file)
    except OSError as exc:
        print(f"cannot open log file: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return int(args.func(args))
    except ToolError as exc:
        LOG.error("%s", exc)
        return EXIT_USAGE
    except KeyboardInterrupt:
        LOG.error("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
