"""Keep the status page's probe samples for 90 days and work out each component's uptime from them.

Gatus v5.37.0 shows uptime for at most 30 days: it keeps hourly uptime rows for 30 days and
deletes anything older than 32 days (storage/store/sql), and its uptime API and badges accept
`30d`, `7d`, `24h` and `1h` only. So the 90-day figure is made here, from samples this program
records itself, and is never typed by hand.

The samples live in one directory, one append-only file per endpoint, a line `<unix time>
<TAB><1 or 0>` for each probe. Two commands read and write it:

- `collect` asks the page for the latest results of every endpoint and appends each probe
  sample once. A sample at or before the last one held for its endpoint is not appended, so
  reading the same result twice records it once, and the first reading of an instant stands.
- `report` prints, for every endpoint, the samples in the last 90 days, how many passed, the
  uptime that gives, and how much of the window the samples cover. With `--out FILE` it writes
  the same document to that file in one step (a temporary file, then a rename), so a reader of the
  file never sees half of it.

The page keeps the last 100 results per endpoint (one a minute), so `collect` must run at least
every 100 minutes to miss none. A stretch with no sample is not counted as up or down: it lowers
`coverage_percent` and leaves `uptime_percent` alone, so a gap in recording is visible and is
never read as an outage or as a pass.
"""

from __future__ import annotations

import argparse
import json
import os
import re
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
DEFAULT_DIR = Path("/var/lib/branchleft/status-uptime/samples")
REQUEST_TIMEOUT_SECONDS = 20

# An endpoint key becomes a file name, so only the characters Gatus writes in a key are allowed.
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class StatusPayloadError(ValueError):
    """The page answered something that is not a list of endpoint statuses."""

    NOT_A_LIST = "the statuses body is not a list"
    NOT_AN_OBJECT = "an endpoint status is not an object"
    NO_KEY_OR_RESULTS = "an endpoint status has no key or no results list"
    BAD_KEY = "an endpoint key is not a safe file name"
    BAD_RESULT = "a result has no timestamp or no success flag"

    def __init__(self, problem: str, key: str = "") -> None:
        """Say which problem, and for which endpoint when one is known."""
        super().__init__(f"{key}: {problem}" if key else problem)


class StoreError(ValueError):
    """A sample file holds a line that is not `<unix time><TAB><1 or 0>`."""

    def __init__(self, file: str, line: int) -> None:
        """Name the file and the line, counted from 1."""
        super().__init__(f"{file}:{line}: not `<unix time><TAB><1 or 0>`")


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
        if _KEY.fullmatch(key) is None:
            raise StatusPayloadError(StatusPayloadError.BAD_KEY, key)
        for result in results:
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("timestamp"), str)
                or not isinstance(result.get("success"), bool)
            ):
                raise StatusPayloadError(StatusPayloadError.BAD_RESULT, key)
            samples.append(Sample(key, _unix_time(result["timestamp"]), result["success"]))
    return samples


def open_store(directory: Path) -> Path:
    """Create the sample directory when absent, and return it."""
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _read(path: Path) -> list[tuple[int, bool]]:
    """Return the `(unix time, success)` pairs of one endpoint's file, in file order.

    Raises:
        StoreError: a line is not `<unix time><TAB><1 or 0>`.
    """
    pairs: list[tuple[int, bool]] = []
    for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
        when, _, flag = line.partition("\t")
        if not when.isdigit() or flag not in {"0", "1"}:
            raise StoreError(path.name, number)
        pairs.append((int(when), flag == "1"))
    return pairs


def record(directory: Path, samples: list[Sample]) -> int:
    """Append the samples not held yet, and return how many were new.

    A sample at or before the last one held for its endpoint is left out, so the first reading
    of an instant stands and an overlapping read adds nothing.
    """
    by_key: dict[str, list[Sample]] = {}
    for sample in samples:
        by_key.setdefault(sample.endpoint_key, []).append(sample)
    added = 0
    for key, found in by_key.items():
        path = directory / f"{key}.tsv"
        held = _read(path) if path.exists() else []
        last = held[-1][0] if held else -1
        fresh: dict[int, bool] = {}
        for sample in sorted(found, key=lambda item: item.unix_time):
            if sample.unix_time > last and sample.unix_time not in fresh:
                fresh[sample.unix_time] = sample.success
        if fresh:
            with path.open("a", encoding="ascii") as handle:
                handle.write("".join(f"{when}\t{int(ok)}\n" for when, ok in fresh.items()))
            added += len(fresh)
    return added


def uptimes(directory: Path, now: int, window_days: int = WINDOW_DAYS) -> list[Uptime]:
    """Return each endpoint's uptime over the `window_days` ending at `now`, sorted by key.

    The window holds the samples after `now - window` up to and including `now`. An endpoint
    with no sample in the window is left out: it has no figure, which is not a figure of 100.
    """
    window = window_days * SECONDS_PER_DAY
    expected = window // PROBE_INTERVAL_SECONDS
    found: list[Uptime] = []
    for path in sorted(directory.glob("*.tsv")):
        inside = [(when, ok) for when, ok in _read(path) if now - window < when <= now]
        if not inside:
            continue
        passed = sum(1 for _, ok in inside if ok)
        first = min(when for when, _ in inside)
        found.append(
            Uptime(
                endpoint_key=path.stem,
                samples=len(inside),
                successes=passed,
                uptime_percent=round(100 * passed / len(inside), 4),
                expected_samples=expected,
                coverage_percent=round(100 * min(len(inside), expected) / expected, 2),
                first_sample=datetime.fromtimestamp(first, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
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


def _collect(url: str, directory: Path) -> int:
    samples = parse_statuses(fetch_statuses(url))
    new = record(open_store(directory), samples)
    print(f"read {len(samples)} samples, recorded {new} new")
    return 0


def _publish(path: Path, text: str) -> None:
    """Write `text` to `path` in one step: a reader sees the old report or the new, not half."""
    temporary = path.with_name(f".{path.name}.new")
    temporary.write_text(text, encoding="ascii")
    temporary.chmod(0o644)
    os.replace(temporary, path)


def _report(directory: Path, now: int, out: Path | None) -> int:
    document = {
        "window_days": WINDOW_DAYS,
        "generated_at": datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoints": [asdict(item) for item in uptimes(open_store(directory), now)],
    }
    text = json.dumps(document, indent=2) + "\n"
    if out is None:
        sys.stdout.write(text)
    else:
        _publish(out, text)
    return 0


def main(argv: list[str]) -> int:
    """Run `collect` or `report`; return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect", help="record the page's latest probe samples")
    collect.add_argument("--url", default=DEFAULT_URL)
    collect.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    report = commands.add_parser("report", help="print the 90-day uptime of every endpoint")
    report.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    report.add_argument("--now", type=int, default=None, help="unix time; default is the clock")
    report.add_argument(
        "--out", type=Path, default=None, help="write the report here, not to stdout"
    )
    args = parser.parse_args(argv)
    if args.command == "collect":
        return _collect(args.url, args.dir)
    now = int(datetime.now(UTC).timestamp()) if args.now is None else args.now
    return _report(args.dir, now, args.out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
