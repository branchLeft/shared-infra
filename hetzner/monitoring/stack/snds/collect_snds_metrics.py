#!/usr/bin/env python3
"""Fetches Microsoft SNDS's per-IP reputation data and writes it as a
node_exporter textfile-collector file, so Prometheus picks up complaint rate
and reputation status the same way it picks up every other host metric on
`edge1` -- through the `node` scrape target this stack already has, with no
new scrape job.

SNDS refreshes at most once a day, so this is invoked by a systemd timer
(`../../systemd/snds-collector.timer`) rather than run continuously. A run
that fails to fetch or parse leaves the previous textfile untouched -- the
last known-good snapshot keeps serving `snds_complaint_rate` and
`snds_reputation_status` at their last real values, while
`snds_collector_last_success_timestamp_seconds` stops advancing and
`SNDSCollectorStale` (`../../render.ts`) pages once that gap is wide enough to
matter. Overwriting the file with nothing on a transient failure would trade
a stale-but-real reading for a silent gap indistinguishable from "no
complaints" -- the wrong failure mode for a sender-reputation signal.

The credential is a bearer token, not a long-lived key: Microsoft retired the
static `?key=` automated-access URL in June 2026 in favour of an OAuth
bearer token tied to the SNDS portal login, and that token is not
long-lived. Obtaining and rotating it is `RUNBOOK-monitoring.md`'s job, not
this script's -- `SNDS_BEARER_TOKEN` is read from the environment exactly
once per run and never written anywhere.
"""

from __future__ import annotations

import ipaddress
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

SNDS_API_URL_DEFAULT = "https://sendersupport.olc.protection.outlook.com/snds/api/ipstatus"
REQUEST_TIMEOUT_SECONDS = 30

VALID_STATUSES = frozenset({"green", "yellow", "red"})

# Rows use this to mean "SNDS did not compute a rate", historically because
# volume was too low for one to be meaningful. Mapped to "no series" rather
# than to a rate of 0.0 -- a computed zero and "not enough data to compute
# anything" are different claims, and collapsing them would let this collector
# assert a clean reputation on data that never said that.
NO_RATE_TOKENS = frozenset({"", "none", "n/a", "-"})


@dataclass(frozen=True)
class IpReputation:
    ip: str
    status: str | None
    complaint_rate: float | None
    volume: int | None


def _parse_complaint_rate(raw: str) -> float | None:
    """`None`/blank means "not enough volume to compute one" -- see
    `NO_RATE_TOKENS`. A trailing `%` is a percentage; anything else is
    already a fraction. Unparseable text is treated the same as absent
    rather than raising, because one malformed field must not cost the rest
    of the line's otherwise-good data (status, volume) -- see
    `parse_snds_response`'s per-line isolation.
    """
    token = raw.strip()
    if token.lower() in NO_RATE_TOKENS:
        return None
    try:
        if token.endswith("%"):
            return float(token[:-1]) / 100.0
        return float(token)
    except ValueError:
        return None


def _parse_volume(raw: str) -> int | None:
    token = raw.strip()
    if not token:
        return None
    try:
        return int(float(token))
    except ValueError:
        return None


def parse_snds_response(text: str) -> list[IpReputation]:
    """Parses SNDS's per-IP status feed into validated records.

    Deliberately defensive rather than schema-strict: Microsoft's 2026
    migration moved this from a documented key-based `data.txt` download to a
    REST endpoint that has been observed returning headerless CSV with no
    committed schema, so the parser tolerates an optional header row, ragged
    field counts, and per-line failures rather than assuming today's observed
    shape is a contract. A line that fails validation is skipped and reported
    to stderr, not fatal to the run -- one bad row (a truncated line, a
    non-IP first field) must not blank out every IP's data for the day.

    Column order, when present: IP address, filter-result status
    (green/yellow/red), complaint rate, message volume. The last two are
    optional -- a two-column line still yields a status-only record.
    """
    records: list[IpReputation] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(",")]
        ip_field = fields[0]
        if ip_field.lower() in ("ip address", "ip"):
            continue  # an optional header row, not data

        try:
            ip = str(ipaddress.ip_address(ip_field))
        except ValueError:
            print(
                f"collect_snds_metrics: line {lineno}: {ip_field!r} is not a valid IP address, skipped",
                file=sys.stderr,
            )
            continue

        status = fields[1].strip().lower() if len(fields) > 1 and fields[1].strip() else None
        if status is not None and status not in VALID_STATUSES:
            print(
                f"collect_snds_metrics: line {lineno}: unrecognised status {status!r} for {ip}, treated as absent",
                file=sys.stderr,
            )
            status = None

        complaint_rate = _parse_complaint_rate(fields[2]) if len(fields) > 2 else None
        volume = _parse_volume(fields[3]) if len(fields) > 3 else None

        records.append(IpReputation(ip=ip, status=status, complaint_rate=complaint_rate, volume=volume))

    return records


def render_prometheus_text(records: list[IpReputation], now: float) -> str:
    """Pure formatting -- the textfile-collector exposition format node_exporter
    reads. IPs and statuses are both validated in `parse_snds_response` before
    they ever reach a label value here (a fixed status enum, an
    `ipaddress`-round-tripped address), so no escaping is needed for either;
    an unvalidated value in either position could otherwise break the
    exposition format or inject an extra line.
    """
    lines = [
        "# HELP snds_complaint_rate Microsoft SNDS complaint rate for the sending IP, from its last daily snapshot (fraction 0-1). Absent when SNDS reported no computed rate.",
        "# TYPE snds_complaint_rate gauge",
    ]
    for r in records:
        if r.complaint_rate is not None:
            lines.append(f'snds_complaint_rate{{ip="{r.ip}"}} {r.complaint_rate}')

    lines += [
        "# HELP snds_message_volume Message volume Microsoft SNDS reported for the sending IP in its last daily snapshot.",
        "# TYPE snds_message_volume gauge",
    ]
    for r in records:
        if r.volume is not None:
            lines.append(f'snds_message_volume{{ip="{r.ip}"}} {r.volume}')

    lines += [
        "# HELP snds_reputation_status Microsoft SNDS filter-result status for the sending IP (1 on the row matching its last reported status; green/yellow/red).",
        "# TYPE snds_reputation_status gauge",
    ]
    for r in records:
        if r.status is not None:
            lines.append(f'snds_reputation_status{{ip="{r.ip}",status="{r.status}"}} 1')

    lines += [
        "# HELP snds_collector_last_success_timestamp_seconds Unix time this collector last fetched and parsed SNDS data successfully.",
        "# TYPE snds_collector_last_success_timestamp_seconds gauge",
        f"snds_collector_last_success_timestamp_seconds {now}",
    ]
    return "\n".join(lines) + "\n"


def fetch_snds_data(url: str, token: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> str:
    """The only network call in this module, kept separate from parsing so the
    parser (the security-sensitive half -- untrusted response text) is
    testable with no network at all.
    """
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def write_textfile_atomically(path: pathlib.Path, content: str) -> None:
    """`node_exporter --collector.textfile.directory` polls this directory and
    reads whatever file it finds -- a write that is not atomic can be read
    mid-write as a truncated or malformed scrape. Writing to a sibling
    temporary file and renaming into place is atomic on the same filesystem
    (`os.replace`), matching the recommended pattern for this collector.
    """
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(content)
    # Not a secret -- explicit 0644 rather than trusting root's umask, since
    # node-exporter reads this bind mount as its own container-side user
    # (65534), not as whoever wrote the file.
    tmp_path.chmod(0o644)
    os.replace(tmp_path, path)


def main(argv: list[str]) -> int:
    del argv
    token = os.environ.get("SNDS_BEARER_TOKEN")
    if not token:
        print(
            "collect_snds_metrics: SNDS_BEARER_TOKEN is unset -- set it in "
            "/etc/branchleft/monitoring.env. Leaving any existing textfile "
            "output untouched.",
            file=sys.stderr,
        )
        return 1

    url = os.environ.get("SNDS_API_URL", SNDS_API_URL_DEFAULT)
    output_path = pathlib.Path(
        os.environ.get("SNDS_OUTPUT_PATH", "/var/lib/branchleft/snds-exporter/snds.prom")
    )

    try:
        raw = fetch_snds_data(url, token)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"collect_snds_metrics: fetch failed: {exc}", file=sys.stderr)
        return 1

    records = parse_snds_response(raw)
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    write_textfile_atomically(output_path, render_prometheus_text(records, time.time()))
    print(f"collect_snds_metrics: wrote {len(records)} IP record(s) to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
