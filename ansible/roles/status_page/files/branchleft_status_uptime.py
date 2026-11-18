"""Keep the status page's probe samples for 90 days and work out each component's uptime from them.

Gatus v5.37.0 shows uptime for at most 30 days: it keeps hourly uptime rows for 30 days and
deletes anything older than 32 days (storage/store/sql), and its uptime API and badges accept
`30d`, `7d`, `24h` and `1h` only. So the 90-day figure is made here, from samples this program
records itself, and is never typed by hand.

Two commands, both reading and writing one SQLite file:

- `collect` asks the page for the latest results of every endpoint and records each probe
  sample once, keyed by endpoint and instant, so reading the same result twice records it once.
- `report` prints, for every endpoint, the samples in the last 90 days, how many passed, the
  uptime that gives, and how much of the window the samples cover.

The page keeps the last 100 results per endpoint (one a minute), so `collect` must run at least
every 100 minutes to miss none. A stretch with no sample is not counted as up or down: it lowers
`coverage_percent` and leaves `uptime_percent` alone, so a gap in recording is visible and is
never read as an outage or as a pass.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import urllib.request
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

WINDOW_DAYS = 90
SECONDS_PER_DAY = 86_400
# The page probes every 60 s (hetzner/status/render.ts, PROBE_INTERVAL).
PROBE_INTERVAL_SECONDS = 60
# The page keeps this many results per endpoint, and answers no more than that for one request.
RESULTS_PER_REQUEST = 100

DEFAULT_URL = "http://127.0.0.1:8303/api/v1/endpoints/statuses"
DEFAULT_DB = Path("/var/lib/branchleft/status-uptime/samples.db")
REQUEST_TIMEOUT_SECONDS = 20

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    endpoint_key TEXT NOT NULL,
    unix_time    INTEGER NOT NULL,
    success      INTEGER NOT NULL CHECK (success IN (0, 1)),
    PRIMARY KEY (endpoint_key, unix_time)
) WITHOUT ROWID
"""


class StatusPayloadError(ValueError):
    """The page answered something that is not a list of endpoint statuses."""

    NOT_A_LIST = "the statuses body is not a list"
    NOT_AN_OBJECT = "an endpoint status is not an object"
    NO_KEY_OR_RESULTS = "an endpoint status has no key or no results list"
    BAD_RESULT = "a result has no timestamp or no success flag"

    def __init__(self, problem: str, key: str = "") -> None:
        """Say which problem, and for which endpoint when one is known."""
        super().__init__(f"{key}: {problem}" if key else problem)


@dataclass(frozen=True)
class Sample:
    """One probe of one endpoint: when it ran, and whether every condition held."""

    endpoint_key: str
    unix_time: int
    success: bool


@dataclass(frozen=True)
class Uptime:
    """The uptime of one endpoint over the window, from the samples held."""

    endpoint_key: str
    samples: int
    successes: int
    uptime_percent: float
    expected_samples: int
    coverage_percent: float
    first_sample: str | None


def _unix_time(timestamp: str) -> int:
    """Return the whole second of an RFC 3339 instant such as 2026-11-18T22:47:32.195683651Z."""
    return int(datetime.fromisoformat(timestamp).timestamp())


def parse_statuses(payload: object) -> list[Sample]:
    """Return every sample in the body of `/api/v1/endpoints/statuses`.

    Raises:
        StatusPayloadError: the body is not a list of endpoints with keyed results.
    """
    if not isinstance(payload, list):
        raise StatusPayloadError(StatusPayloadError.NOT_A_LIST)
    samples: list[Sample] = []
    for endpoint in payload:
        if not isinstance(endpoint, dict):
            raise StatusPayloadError(StatusPayloadError.NOT_AN_OBJECT)
        key = endpoint.get("key")
        results = endpoint.get("results")
        if not isinstance(key, str) or not isinstance(results, list):
            raise StatusPayloadError(StatusPayloadError.NO_KEY_OR_RESULTS)
        for result in results:
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("timestamp"), str)
                or not isinstance(result.get("success"), bool)
            ):
                raise StatusPayloadError(StatusPayloadError.BAD_RESULT, key)
            samples.append(Sample(key, _unix_time(result["timestamp"]), result["success"]))
    return samples


def open_store(path: Path) -> sqlite3.Connection:
    """Open the sample store, creating it and its directory when absent."""
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(_SCHEMA)
    connection.commit()
    return connection


def record(connection: sqlite3.Connection, samples: list[Sample]) -> int:
    """Store the samples not held yet, and return how many were new.

    A sample already held is left as it was: its first reading is the one that stands.
    """
    before = connection.total_changes
    connection.executemany(
        "INSERT OR IGNORE INTO samples (endpoint_key, unix_time, success) VALUES (?, ?, ?)",
        [(s.endpoint_key, s.unix_time, int(s.success)) for s in samples],
    )
    connection.commit()
    return connection.total_changes - before


def uptimes(
    connection: sqlite3.Connection, now: int, window_days: int = WINDOW_DAYS
) -> list[Uptime]:
    """Return each endpoint's uptime over the `window_days` ending at `now`, sorted by key.

    The window holds the samples after `now - window` up to and including `now`.
    """
    window = window_days * SECONDS_PER_DAY
    expected = window // PROBE_INTERVAL_SECONDS
    rows = connection.execute(
        "SELECT endpoint_key, COUNT(*), SUM(success), MIN(unix_time) FROM samples "
        "WHERE unix_time > ? AND unix_time <= ? GROUP BY endpoint_key ORDER BY endpoint_key",
        (now - window, now),
    ).fetchall()
    found: list[Uptime] = []
    for key, total, passed, first in rows:
        found.append(
            Uptime(
                endpoint_key=str(key),
                samples=int(total),
                successes=int(passed),
                uptime_percent=round(100 * int(passed) / int(total), 4),
                expected_samples=expected,
                coverage_percent=round(100 * min(int(total), expected) / expected, 2),
                first_sample=datetime.fromtimestamp(int(first), UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        )
    return found


def fetch_statuses(url: str) -> object:
    """Ask the page for the latest results of every endpoint and return the decoded body."""
    request = urllib.request.Request(  # noqa: S310 - the URL is the page's own, set by the caller
        f"{url}?page=1&pageSize={RESULTS_PER_REQUEST}", headers={"Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
        body: object = json.load(response)
    return body


def _collect(url: str, db: Path) -> int:
    samples = parse_statuses(fetch_statuses(url))
    connection = open_store(db)
    try:
        new = record(connection, samples)
    finally:
        connection.close()
    print(f"read {len(samples)} samples, recorded {new} new")
    return 0


def _report(db: Path, now: int) -> int:
    connection = open_store(db)
    try:
        found = uptimes(connection, now)
    finally:
        connection.close()
    document = {
        "window_days": WINDOW_DAYS,
        "generated_at": datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoints": [asdict(item) for item in found],
    }
    print(json.dumps(document, indent=2))
    return 0


def main(argv: list[str]) -> int:
    """Run `collect` or `report`; return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect", help="record the page's latest probe samples")
    collect.add_argument("--url", default=DEFAULT_URL)
    collect.add_argument("--db", type=Path, default=DEFAULT_DB)
    report = commands.add_parser("report", help="print the 90-day uptime of every endpoint")
    report.add_argument("--db", type=Path, default=DEFAULT_DB)
    report.add_argument("--now", type=int, default=None, help="unix time; default is the clock")
    args = parser.parse_args(argv)
    if args.command == "collect":
        return _collect(args.url, args.db)
    return _report(args.db, int(datetime.now(UTC).timestamp()) if args.now is None else args.now)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
