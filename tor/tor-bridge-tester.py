#!/usr/bin/env python3
"""Rank Tor bridges by measured quality.

Pipeline
--------
1. Parse and de-duplicate bridge lines.
2. TCP preflight: drop bridges whose endpoint does not accept connections.
3. For every survivor start an isolated tor client (one bridge, its own
   DataDirectory and SocksPort) and measure, through its SOCKS5 proxy with
   curl: bootstrap time, success rate and latency of check.torproject.org
   requests, and the download time of a small file.
4. Blend the live measurement with older results from a local cache (the
   cache always carries less weight than the live check) and print the top.

Score (lower is better):

    performance = 0.35 * bootstrap + 0.35 * median_latency + 0.30 * download
    score       = performance / success_ratio

    blended     = (1 - w) * live + w * history      (w = --cache-weight < 0.5)

A bridge that fails the live check is never ranked; the failure is stored in
the cache and lowers the reliability of that bridge in later runs.

Requires Python 3.9+, tor, curl and the pluggable-transport binaries for the
transports used in the list (lyrebird, webtunnel-client, snowflake-client...).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Optional, Sequence
from urllib.parse import urlparse

LOG = logging.getLogger("tor-bridge-tester")

CHECK_URL = "https://check.torproject.org/api/ip"
DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
INTERNET_PROBES = (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443))

# Transport name -> candidate binaries (first one found in PATH wins).
DEFAULT_PLUGINS: dict[str, tuple[str, ...]] = {
    "obfs4": ("lyrebird", "obfs4proxy"),
    "meek_lite": ("lyrebird", "obfs4proxy"),
    "scramblesuit": ("obfs4proxy",),
    "webtunnel": ("webtunnel-client",),
    "snowflake": ("snowflake-client",),
    "conjure": ("conjure-client",),
}
# Transports whose bridge line address is the real TCP endpoint.
DIRECT_TRANSPORTS = frozenset({"vanilla", "obfs4", "scramblesuit"})

W_BOOTSTRAP, W_LATENCY, W_DOWNLOAD = 0.35, 0.35, 0.30
MAX_CACHE_RECORDS = 10
CACHE_VERSION = 1
DEFAULT_CACHE_FILE = (
    Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    / "tor-bridge-tester"
    / "results.json"
)

_ADDR_RE = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})$"
)
_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%(?: \(([^)]*)\))?")
_ISSUE_RE = re.compile(r"\[(?:warn|err)\]\s*(.*)")
_CURL_MARKER = "@@curl@@"
_CURL_WRITE_OUT = (
    f"\n{_CURL_MARKER}%{{http_code}} %{{time_starttransfer}} "
    "%{time_total} %{speed_download} %{size_download}"
)


class BridgeTestError(Exception):
    """A bridge failed one of the test stages; the message is user-facing."""


@dataclass(frozen=True)
class Bridge:
    line: str
    transport: str
    host: str
    port: int
    fingerprint: Optional[str] = None
    params: dict[str, str] = field(default_factory=dict)

    @property
    def is_ipv6(self) -> bool:
        return ":" in self.host

    @property
    def probe_target(self) -> Optional[tuple[str, int]]:
        """Real TCP endpoint, or None when it cannot be probed directly.

        webtunnel and meek bridge lines carry a placeholder address; the real
        endpoint is the ``url`` parameter. Snowflake has no static endpoint.
        """
        if self.transport in DIRECT_TRANSPORTS:
            return self.host, self.port
        if self.transport == "webtunnel":
            try:
                url = urlparse(self.params.get("url", ""))
                if url.hostname:
                    default = 80 if url.scheme == "http" else 443
                    return url.hostname, url.port or default
            except ValueError:
                return None
        return None

    @property
    def label(self) -> str:
        host, port = self.probe_target or (self.host, self.port)
        host = f"[{host}]" if ":" in host else host
        fingerprint = f" {self.fingerprint[:8]}" if self.fingerprint else ""
        return f"{self.transport} {host}:{port}{fingerprint}"


@dataclass(frozen=True)
class Measurement:
    """Outcome of one test run; also the record format of the cache."""

    timestamp: float
    success_ratio: float  # 0.0 means the bridge failed
    bootstrap_s: Optional[float] = None
    latency_s: Optional[float] = None
    download_s: Optional[float] = None

    @property
    def performance(self) -> Optional[float]:
        if None in (self.bootstrap_s, self.latency_s, self.download_s):
            return None
        assert self.bootstrap_s is not None
        assert self.latency_s is not None
        assert self.download_s is not None
        return (
            W_BOOTSTRAP * self.bootstrap_s
            + W_LATENCY * self.latency_s
            + W_DOWNLOAD * self.download_s
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Measurement:
        def opt(key: str) -> Optional[float]:
            value = data.get(key)
            return None if value is None else float(value)

        ratio = min(1.0, max(0.0, float(data["success_ratio"])))
        return cls(
            float(data["timestamp"]),
            ratio,
            opt("bootstrap_s"),
            opt("latency_s"),
            opt("download_s"),
        )


@dataclass
class BridgeResult:
    bridge: Bridge
    measurement: Measurement
    rtt_ms: Optional[float] = None
    successes: int = 0
    attempts: int = 0
    speed_kbs: Optional[float] = None
    error: Optional[str] = None
    live_score: Optional[float] = None
    score: Optional[float] = None
    history_count: int = 0


@dataclass(frozen=True)
class Settings:
    tor: str
    curl: str
    plugins: dict[str, str]
    attempts: int
    bootstrap_timeout: float
    curl_timeout: float
    download_timeout: float
    download_url: str


def parse_bridge_line(raw: str) -> Bridge:
    """Parse ``[Bridge] [transport] addr:port [fingerprint] [k=v ...]``."""
    tokens = raw.split()
    if tokens and tokens[0].lower() == "bridge":
        tokens = tokens[1:]
    if not tokens:
        raise ValueError("empty line")
    normalized = " ".join(tokens)

    transport = "vanilla"
    if not _ADDR_RE.match(tokens[0]):
        transport, tokens = tokens[0], tokens[1:]
    if not tokens:
        raise ValueError("missing address")

    match = _ADDR_RE.match(tokens[0])
    if match is None:
        raise ValueError(f"invalid address {tokens[0]!r}")
    host = match["host"].strip("[]")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"invalid IP address {host!r}") from None
    port = int(match["port"])
    if not 0 < port < 65536:
        raise ValueError(f"invalid port {port}")

    rest = tokens[1:]
    fingerprint: Optional[str] = None
    if rest and _FINGERPRINT_RE.match(rest[0]):
        fingerprint, rest = rest[0].upper(), rest[1:]
    params = dict(token.split("=", 1) for token in rest if "=" in token)
    return Bridge(normalized, transport, host, port, fingerprint, params)


def load_bridges(path: Path) -> list[Bridge]:
    bridges: dict[str, Bridge] = {}
    duplicates = 0
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        text = raw.strip()
        if not text or text.startswith("#") or set(text) <= {"."}:
            continue
        try:
            bridge = parse_bridge_line(text)
        except ValueError as exc:
            LOG.warning("%s:%d skipped: %s", path.name, number, exc)
            continue
        if bridge.line in bridges:
            duplicates += 1
        bridges.setdefault(bridge.line, bridge)
    LOG.info("Loaded %d unique bridges (%d duplicates ignored)", len(bridges), duplicates)
    return list(bridges.values())


def resolve_plugins(
    bridges: Sequence[Bridge], overrides: dict[str, str]
) -> dict[str, str]:
    """Locate a PT binary for every non-vanilla transport in use."""
    found: dict[str, str] = {}
    for transport in sorted({b.transport for b in bridges} - {"vanilla"}):
        candidates = (overrides[transport],) if transport in overrides else DEFAULT_PLUGINS.get(transport, ())
        path = next((p for c in candidates if (p := shutil.which(c))), None)
        if path is None:
            skipped = sum(b.transport == transport for b in bridges)
            LOG.warning(
                "No binary for transport %r, skipping %d bridge(s); install it or pass --pt %s=/path",
                transport, skipped, transport,
            )
        elif any(ch.isspace() for ch in path):
            LOG.warning("Plugin path %r contains whitespace (unsupported by torrc); skipping %r", path, transport)
        else:
            found[transport] = path
    return found


def tcp_probe(host: str, port: int, attempts: int, timeout: float) -> Optional[float]:
    """Median TCP connect time in ms, or None if every attempt failed."""
    rtts: list[float] = []
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                rtts.append((time.perf_counter() - start) * 1000)
        except OSError:
            continue
    return statistics.median(rtts) if rtts else None


def has_internet() -> bool:
    return any(tcp_probe(host, port, 1, 3.0) is not None for host, port in INTERNET_PROBES)


def preflight(
    bridges: Sequence[Bridge], attempts: int, timeout: float
) -> dict[str, Optional[float]]:
    """TCP-probe every probeable bridge; maps bridge line -> RTT (None = down)."""
    probeable = [b for b in bridges if b.probe_target is not None]
    if not probeable:
        return {}

    def probe(bridge: Bridge) -> Optional[float]:
        target = bridge.probe_target
        assert target is not None
        return tcp_probe(target[0], target[1], attempts, timeout)

    with ThreadPoolExecutor(max_workers=min(64, len(probeable))) as pool:
        rtts = list(pool.map(probe, probeable))
    return {bridge.line: rtt for bridge, rtt in zip(probeable, rtts)}


class PortAllocator:
    """Hands out distinct free loopback ports to concurrent workers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: set[int] = set()

    def allocate(self) -> int:
        with self._lock:
            while True:
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = int(sock.getsockname()[1])
                if port not in self._used:
                    self._used.add(port)
                    return port


class TorProcess:
    """One tor client with a private DataDirectory, configured for one bridge."""

    def __init__(self, settings: Settings, bridge: Bridge, socks_port: int) -> None:
        self._settings = settings
        self._bridge = bridge
        self.socks_port = socks_port
        self._workdir: Optional[Path] = None
        self._proc: Optional[subprocess.Popen[str]] = None
        self._lines: queue.Queue[Optional[str]] = queue.Queue()
        self._started_at = 0.0

    def __enter__(self) -> TorProcess:
        try:
            self._start()
        except BaseException:
            self._stop()
            raise
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self._stop()

    def _write_torrc(self, workdir: Path) -> Path:
        bridge = self._bridge
        lines = [
            f'DataDirectory "{(workdir / "data").as_posix()}"',
            f"SocksPort 127.0.0.1:{self.socks_port}",
            "ClientOnly 1",
            "UseBridges 1",
            "AvoidDiskWrites 1",
            "Log notice stdout",
        ]
        if bridge.is_ipv6:
            lines.append("ClientUseIPv6 1")
        if bridge.transport != "vanilla":
            plugin = self._settings.plugins[bridge.transport]
            lines.append(f"ClientTransportPlugin {bridge.transport} exec {plugin}")
        lines.append(f"Bridge {bridge.line}")
        torrc = workdir / "torrc"
        torrc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return torrc

    def _start(self) -> None:
        self._workdir = Path(tempfile.mkdtemp(prefix="torbridge_"))
        defaults = self._workdir / "torrc-defaults"
        defaults.touch()  # keep system-wide defaults from interfering
        torrc = self._write_torrc(self._workdir)
        self._started_at = time.monotonic()
        self._proc = subprocess.Popen(
            [self._settings.tor, "-f", str(torrc), "--defaults-torrc", str(defaults)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        if self._proc.stdout is None:
            raise BridgeTestError("cannot capture tor output")
        threading.Thread(target=self._pump, args=(self._proc.stdout,), daemon=True).start()

    def _pump(self, stream: Any) -> None:
        for line in stream:
            self._lines.put(line.rstrip())
        self._lines.put(None)  # EOF: tor exited

    def wait_bootstrapped(self, timeout: float, stop: threading.Event) -> float:
        """Block until tor reports 100%; return the elapsed seconds."""
        assert self._proc is not None
        deadline = self._started_at + timeout
        progress, stage, issue = 0, "starting", ""

        def describe(prefix: str) -> str:
            detail = f": {issue}" if issue else ""
            return f"{prefix} at {progress}% ({stage}){detail}"[:200]

        while True:
            if stop.is_set():
                raise BridgeTestError("interrupted")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeTestError(describe("bootstrap timed out"))
            try:
                line = self._lines.get(timeout=min(1.0, remaining))
            except queue.Empty:
                continue
            if line is None:
                raise BridgeTestError(describe(f"tor exited (code {self._proc.poll()})"))
            if match := _BOOTSTRAP_RE.search(line):
                progress, stage = int(match[1]), match[2] or stage
                if progress == 100:
                    return time.monotonic() - self._started_at
            elif match := _ISSUE_RE.search(line):
                issue = match[1]

    def _stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None


@dataclass(frozen=True)
class CurlResponse:
    http_code: int
    ttfb_s: float
    total_s: float
    speed_bps: float
    size_bytes: int
    body: str


def _run_interruptible(cmd: list[str], timeout: float, stop: threading.Event) -> Optional[tuple[int, str]]:
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace") as proc:
        deadline = time.monotonic() + timeout
        while True:
            try:
                out, _ = proc.communicate(timeout=0.5)
                return proc.returncode, out
            except subprocess.TimeoutExpired:
                if stop.is_set() or time.monotonic() > deadline:
                    proc.kill()
                    proc.communicate()
                    return None


def curl_get(
    settings: Settings,
    socks_port: int,
    url: str,
    *,
    timeout: float,
    identity: str,
    stop: threading.Event,
    discard_body: bool = False,
) -> Optional[CurlResponse]:
    """GET ``url`` via tor's SOCKS5 port (remote DNS).

    A distinct SOCKS username per request makes tor use a separate circuit
    (IsolateSOCKSAuth), so repeated attempts are independent samples.
    """
    cmd = [
        settings.curl, "--silent", "--location", "--max-redirs", "3",
        "--proto", "=https", "--proto-redir", "=https",
        "--max-time", str(timeout),
        "--proxy", f"socks5h://{identity}:x@127.0.0.1:{socks_port}",
        "--write-out", _CURL_WRITE_OUT,
        "--output", os.devnull if discard_body else "-",
        url,
    ]
    outcome = _run_interruptible(cmd, timeout + 5, stop)
    if outcome is None:
        return None
    code, output = outcome
    if code != 0:
        LOG.debug("curl exit code %d for %s (%s)", code, url, identity)
        return None
    body, marker, stats = output.rpartition(_CURL_MARKER)
    fields = stats.split()
    if not marker or len(fields) != 5:
        return None
    try:
        return CurlResponse(int(fields[0]), float(fields[1]), float(fields[2]), float(fields[3]), int(float(fields[4])), body)
    except ValueError:
        return None


def _is_tor_response(body: str) -> bool:
    try:
        return bool(json.loads(body).get("IsTor") is True)
    except (json.JSONDecodeError, AttributeError):
        return False


def _measure(bridge: Bridge, settings: Settings, ports: PortAllocator, stop: threading.Event, rtt_ms: Optional[float]) -> BridgeResult:
    with TorProcess(settings, bridge, ports.allocate()) as tor:
        bootstrap_s = tor.wait_bootstrapped(settings.bootstrap_timeout, stop)

        totals: list[float] = []
        for attempt in range(settings.attempts):
            if stop.is_set():
                raise BridgeTestError("interrupted")
            response = curl_get(settings, tor.socks_port, CHECK_URL, timeout=settings.curl_timeout, identity=f"check{attempt}", stop=stop)
            if response and response.http_code == 200 and _is_tor_response(response.body):
                totals.append(response.total_s)
        if not totals:
            raise BridgeTestError(f"bootstrapped in {bootstrap_s:.1f}s but 0/{settings.attempts} requests worked through Tor")

        speed_kbs: Optional[float] = None
        download_s = settings.download_timeout  # penalty when the download fails
        response = curl_get(settings, tor.socks_port, settings.download_url, timeout=settings.download_timeout, identity="download", stop=stop, discard_body=True)
        if response and response.http_code == 200 and response.size_bytes > 0:
            download_s = response.total_s
            speed_kbs = response.speed_bps / 1024

    measurement = Measurement(
        time.time(), len(totals) / settings.attempts, bootstrap_s, statistics.median(totals), download_s
    )
    return BridgeResult(bridge, measurement, rtt_ms, len(totals), settings.attempts, speed_kbs)


def test_bridge(bridge: Bridge, settings: Settings, ports: PortAllocator, stop: threading.Event, rtt_ms: Optional[float]) -> BridgeResult:
    """Run all stages for one bridge; never raises."""
    try:
        return _measure(bridge, settings, ports, stop, rtt_ms)
    except BridgeTestError as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 - one broken worker must not kill the run
        LOG.debug("Unexpected failure for %s", bridge.label, exc_info=True)
        error = f"unexpected error: {exc!r}"
    return BridgeResult(bridge, Measurement(time.time(), 0.0), rtt_ms, attempts=settings.attempts, error=error)


def live_score(measurement: Measurement) -> Optional[float]:
    performance = measurement.performance
    if performance is None or measurement.success_ratio <= 0:
        return None
    return performance / measurement.success_ratio


def blend_score(
    current: Measurement,
    history: Sequence[Measurement],
    cache_weight: float,
    half_life_s: float,
    now: float,
) -> Optional[float]:
    """Combine the live measurement with cached ones; live always dominates."""
    current_perf = current.performance
    if current_perf is None or current.success_ratio <= 0:
        return None
    if not history or cache_weight <= 0:
        return current_perf / current.success_ratio

    # Newer history counts more than older history (exponential decay).
    weights = [0.5 ** (max(0.0, now - h.timestamp) / half_life_s) for h in history]
    ratio_hist = sum(w * h.success_ratio for w, h in zip(weights, history)) / sum(weights)

    perf_weight = perf_sum = 0.0
    for weight, record in zip(weights, history):
        perf = record.performance
        if perf is not None:
            perf_weight += weight
            perf_sum += weight * perf
    performance = current_perf
    if perf_weight > 0:
        performance = (1 - cache_weight) * current_perf + cache_weight * perf_sum / perf_weight
    ratio = (1 - cache_weight) * current.success_ratio + cache_weight * ratio_hist
    return performance / ratio


class ResultCache:
    """JSON file with the recent measurements of every bridge."""

    def __init__(self, path: Optional[Path], max_age_s: float) -> None:
        self._path = path
        self._max_age_s = max_age_s
        self._records: dict[str, list[Measurement]] = {}

    def load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if raw.get("version") != CACHE_VERSION:
                raise ValueError(f"unsupported cache version {raw.get('version')!r}")
            bridges = raw["bridges"]
        except (OSError, ValueError, KeyError, AttributeError) as exc:
            LOG.warning("Ignoring unreadable cache %s: %s", self._path, exc)
            return
        cutoff = time.time() - self._max_age_s
        for line, items in bridges.items():
            kept: list[Measurement] = []
            for item in items:
                try:
                    record = Measurement.from_dict(item)
                except (KeyError, TypeError, ValueError):
                    continue
                if record.timestamp >= cutoff:
                    kept.append(record)
            if kept:
                self._records[line] = sorted(kept, key=lambda m: m.timestamp)[-MAX_CACHE_RECORDS:]
        LOG.info("Cache: history for %d bridges loaded from %s", len(self._records), self._path)

    def history(self, line: str) -> list[Measurement]:
        return list(self._records.get(line, ()))

    def add(self, line: str, measurement: Measurement) -> None:
        records = self._records.setdefault(line, [])
        records.append(measurement)
        del records[:-MAX_CACHE_RECORDS]

    def save(self) -> None:
        if self._path is None:
            return
        payload = {
            "version": CACHE_VERSION,
            "bridges": {line: [asdict(m) for m in records] for line, records in self._records.items()},
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self._path.parent, delete=False, suffix=".tmp") as tmp:
                json.dump(payload, tmp)
            os.replace(tmp.name, self._path)  # atomic: no half-written cache
        except OSError as exc:
            LOG.warning("Could not write cache %s: %s", self._path, exc)


def render_table(results: Sequence[BridgeResult]) -> str:
    header = f"{'#':>2}  {'score':>7} {'live':>7} {'boot':>6} {'lat':>6} {'speed':>10} {'ok':>4} {'rtt':>7} {'hist':>4}  bridge"
    rows = [header]
    for rank, r in enumerate(results, 1):
        m = r.measurement
        speed = f"{r.speed_kbs:.0f} KB/s" if r.speed_kbs is not None else "-"
        rtt = f"{r.rtt_ms:.0f} ms" if r.rtt_ms is not None else "-"
        rows.append(
            f"{rank:>2}  {r.score or 0:>7.1f} {r.live_score or 0:>7.1f} {m.bootstrap_s or 0:>5.1f}s "
            f"{m.latency_s or 0:>5.2f}s {speed:>10} {r.successes}/{r.attempts:<2} {rtt:>7} {r.history_count:>4}  {r.bridge.label}"
        )
    return "\n".join(rows)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number


def _cache_weight(value: str) -> float:
    number = float(value)
    if not 0 <= number < 0.5:
        raise argparse.ArgumentTypeError("must be in [0, 0.5) so the live check always dominates")
    return number


def _plugin_spec(value: str) -> tuple[str, str]:
    transport, sep, path = value.partition("=")
    if not sep or not transport or not path:
        raise argparse.ArgumentTypeError("expected TRANSPORT=PATH")
    return transport, path


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Rank Tor bridges by measured quality.")
    p.add_argument("bridge_file", type=Path, help="file with one bridge line per row")
    p.add_argument("--top", type=_positive_int, default=5, help="how many bridges to report (default: 5)")
    p.add_argument("--workers", type=_positive_int, default=4, help="parallel tor processes (default: 4; use 1 for accurate speed numbers)")
    p.add_argument("--attempts", type=_positive_int, default=3, help="check requests per bridge (default: 3)")
    p.add_argument("--bootstrap-timeout", type=_positive_float, default=90.0)
    p.add_argument("--curl-timeout", type=_positive_float, default=30.0)
    p.add_argument("--download-timeout", type=_positive_float, default=60.0)
    p.add_argument("--download-url", default=DEFAULT_DOWNLOAD_URL, help="HTTPS file used for the speed test")
    p.add_argument("--tor", default="tor", help="tor executable")
    p.add_argument("--curl", default="curl", help="curl executable")
    p.add_argument("--pt", type=_plugin_spec, action="append", default=[], metavar="TRANSPORT=PATH", help="pluggable transport binary (repeatable)")
    p.add_argument("--no-preflight", action="store_true", help="skip the TCP reachability check")
    p.add_argument("--probe-attempts", type=_positive_int, default=3)
    p.add_argument("--probe-timeout", type=_positive_float, default=5.0)
    p.add_argument("--no-cache", action="store_true", help="neither read nor write the cache")
    p.add_argument("--cache-file", type=Path, default=DEFAULT_CACHE_FILE)
    p.add_argument("--cache-weight", type=_cache_weight, default=0.3, help="share of the score taken from cached history, 0 <= w < 0.5 (default: 0.3)")
    p.add_argument("--cache-max-age-days", type=_positive_float, default=7.0)
    p.add_argument("--out", type=Path, help="write the top bridge lines to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    tor, curl = shutil.which(args.tor), shutil.which(args.curl)
    if tor is None or curl is None:
        LOG.error("Required executable not found in PATH: %s", "tor" if tor is None else "curl")
        return 2
    try:
        bridges = load_bridges(args.bridge_file)
    except OSError as exc:
        LOG.error("Cannot read bridge file: %s", exc)
        return 2

    plugins = resolve_plugins(bridges, dict(args.pt))
    bridges = [b for b in bridges if b.transport == "vanilla" or b.transport in plugins]
    if not bridges:
        LOG.error("Nothing to test")
        return 1

    max_age_s = args.cache_max_age_days * 86400
    cache = ResultCache(None if args.no_cache else args.cache_file, max_age_s)
    cache.load()
    try:
        return _test_all(args, Settings(tor, curl, plugins, args.attempts, args.bootstrap_timeout, args.curl_timeout, args.download_timeout, args.download_url), bridges, cache, max_age_s / 2)
    finally:
        cache.save()


def _test_all(args: argparse.Namespace, settings: Settings, bridges: list[Bridge], cache: ResultCache, half_life_s: float) -> int:
    rtts: dict[str, Optional[float]] = {}
    candidates = bridges
    if not args.no_preflight:
        rtts = preflight(bridges, args.probe_attempts, args.probe_timeout)
        down = [b for b in bridges if b.line in rtts and rtts[b.line] is None]
        up_count = sum(rtt is not None for rtt in rtts.values())
        if rtts and up_count == 0 and not has_internet():
            LOG.error("No bridge answered and the internet check failed: you look offline (cache not updated)")
            return 1
        now = time.time()
        for bridge in down:
            LOG.debug("Unreachable: %s", bridge.label)
            cache.add(bridge.line, Measurement(now, 0.0))
        candidates = [b for b in bridges if b not in down]
        if rtts:
            LOG.info("Preflight: %d/%d bridges accept TCP connections", up_count, len(rtts))

    if not candidates:
        LOG.error("No reachable bridges to test")
        return 1

    LOG.info("Testing %d bridges with %d worker(s)", len(candidates), args.workers)
    ports, stop = PortAllocator(), threading.Event()
    results: list[BridgeResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures: dict[Future[BridgeResult], Bridge] = {
            pool.submit(test_bridge, b, settings, ports, stop, rtts.get(b.line)): b for b in candidates
        }
        try:
            for done, future in enumerate(as_completed(futures), 1):
                result = future.result()
                history = cache.history(result.bridge.line)
                result.history_count = len(history)
                result.live_score = live_score(result.measurement)
                result.score = blend_score(result.measurement, history, args.cache_weight, half_life_s, time.time())
                cache.add(result.bridge.line, result.measurement)
                results.append(result)
                if result.score is None:
                    LOG.info("[%d/%d] FAIL %s: %s", done, len(candidates), result.bridge.label, result.error)
                else:
                    m = result.measurement
                    LOG.info(
                        "[%d/%d] OK   %s score=%.1f live=%.1f boot=%.1fs lat=%.2fs ok=%d/%d hist=%d",
                        done, len(candidates), result.bridge.label, result.score, result.live_score or 0,
                        m.bootstrap_s or 0, m.latency_s or 0, result.successes, result.attempts, result.history_count,
                    )
        except KeyboardInterrupt:
            stop.set()
            for future in futures:
                future.cancel()
            raise

    ranked = sorted((r for r in results if r.score is not None), key=lambda r: r.score or 0.0)
    if not ranked:
        LOG.error("No bridge passed the live check")
        return 1
    if all(r.speed_kbs is None for r in ranked):
        LOG.warning("The speed test failed for every bridge; check --download-url (score includes a timeout penalty)")

    top = ranked[: args.top]
    print(f"\nTop {len(top)} of {len(ranked)} working bridges (lower score is better):\n")
    print(render_table(top))
    print("\n" + "\n".join(r.bridge.line for r in top))
    if args.out:
        try:
            args.out.write_text("\n".join(r.bridge.line for r in top) + "\n", encoding="utf-8")
            LOG.info("Saved top bridges to %s", args.out)
        except OSError as exc:
            LOG.error("Cannot write %s: %s", args.out, exc)
            return 2
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    try:
        return run(args)
    except KeyboardInterrupt:
        LOG.warning("Interrupted; partial results were saved to the cache")
        return 130


if __name__ == "__main__":
    sys.exit(main())
