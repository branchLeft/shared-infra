#!/usr/bin/env python3
"""Fetches Microsoft SNDS's per-IP reputation data and writes it as a
node_exporter textfile-collector file, so Prometheus picks up complaint rate
and reputation status the same way it picks up every other host metric on
`edge1` -- through the `node` scrape target this stack already has, with no
new scrape job.

SNDS refreshes at most once a day, so this is invoked by a systemd timer
(`../../systemd/snds-collector.timer`) rather than run continuously. A run
that fails to fetch or parse leaves the previous reputation textfile
untouched -- the last known-good snapshot keeps serving
`snds_complaint_rate` and `snds_reputation_status` at their last real
values. Overwriting the file with nothing on a transient failure would trade
a stale-but-real reading for a silent gap indistinguishable from "no
complaints" -- the wrong failure mode for a sender-reputation signal.

That preservation is also what makes a failing collector look healthy on a
dashboard, so health is published SEPARATELY and unconditionally, into its
own textfile (`HEALTH_FILENAME`) that every run rewrites whether it
succeeded or not. node_exporter reads every `*.prom` in its textfile
directory, so the two files scrape as one set: reputation values stay at
their last real reading while `snds_collector_last_run_success` goes to 0 on
the very next run after a break. Inferring the failure from a timestamp that
stopped advancing takes 36 hours; reading it off a gauge takes one scrape.

CREDENTIAL. `SNDS_DATA_URL` is a complete SNDS "Automated Data Access" URL
with its access key embedded in the query string -- the whole URL is the
secret, which is why nothing here ever prints it (see `redact`). Microsoft
issues it from the SNDS portal's automated-access page and expires it after
30 days; rotation is `RUNBOOK-monitoring.md`'s job, not this script's. The
portal's other automated path, an OAuth bearer token, is deliberately not
used: it lives about 8 hours with no `refresh_token`, which cannot serve a
6-hourly unattended collector at all. RUNBOOK-monitoring.md's SNDS
section carries the history and the rotation procedure.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

REQUEST_TIMEOUT_SECONDS = 30

REPUTATION_FILENAME = "snds.prom"
HEALTH_FILENAME = "snds_collector_health.prom"
LINK_STATE_FILENAME = "snds-link-state.json"

VALID_STATUSES = frozenset({"green", "yellow", "red"})

# Rows use this to mean "SNDS did not compute a rate", historically because
# volume was too low for one to be meaningful. Mapped to "no series" rather
# than to a rate of 0.0 -- a computed zero and "not enough data to compute
# anything" are different claims, and collapsing them would let this collector
# assert a clean reputation on data that never said that.
NO_RATE_TOKENS = frozenset({"", "none", "n/a", "-"})

REDACTED = "<redacted-snds-url>"


@dataclass(frozen=True)
class IpReputation:
    ip: str
    status: str | None
    complaint_rate: float | None
    volume: int | None


def redact(message: str, url: str) -> str:
    """Strips a data URL, and its access key alone, out of text bound for a
    log.

    Every failure path here interpolates an exception whose text this module
    does not control -- `URLError` wraps arbitrary OS errors, and a redirect
    or a proxy can put the request URL into one. The URL carries the access
    key in its query string, so a single un-redacted error line would put a
    live credential into the systemd journal, where it persists and is read
    by anyone diagnosing exactly this failure.

    Both the whole URL and each query-parameter value are replaced, because
    the two leak independently: an error naming the full URL is caught by the
    first, and one quoting only the key (`?key=...` echoed back in a
    portal-side message) by the second.
    """
    if not url:
        return message
    out = message.replace(url, REDACTED)
    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return out
    for _name, value in urllib.parse.parse_qsl(query, keep_blank_values=False):
        # A short value cannot be an access key and may well be a literal
        # substring of ordinary prose ("data", "1"), so replacing it would
        # corrupt the message without protecting anything.
        if len(value) >= 8:
            out = out.replace(value, REDACTED)
    return out


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
    migration moved this from a documented key-based `data.txt` download to
    an automated-access CSV whose columns are documented only by example, so
    the parser tolerates an optional header row, ragged field counts, and
    per-line failures rather than assuming today's observed shape is a
    contract. A line that fails validation is skipped and reported to
    stderr, not fatal to the run -- one bad row (a truncated line, a non-IP
    first field) must not blank out every IP's data for the day.

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


def render_health_text(now: float, succeeded: bool, link_first_seen: float | None) -> str:
    """The half of the output that is written even when everything else
    failed. Kept separate from `render_prometheus_text` because the two have
    opposite write rules: reputation values are preserved across a failure,
    health values are rewritten by it.

    `snds_access_link_first_seen_timestamp_seconds` is what makes the 30-day
    expiry a scheduled chore instead of an outage: an alert on its age fires
    days before Microsoft starts answering 404, whereas every other signal
    here can only report the outage after it has already begun.
    """
    lines = [
        "# HELP snds_collector_last_attempt_timestamp_seconds Unix time this collector last ran, whether or not the run succeeded.",
        "# TYPE snds_collector_last_attempt_timestamp_seconds gauge",
        f"snds_collector_last_attempt_timestamp_seconds {now}",
        "# HELP snds_collector_last_run_success Whether this collector's most recent run fetched and parsed SNDS data (1) or failed (0).",
        "# TYPE snds_collector_last_run_success gauge",
        f"snds_collector_last_run_success {1 if succeeded else 0}",
    ]
    if link_first_seen is not None:
        lines += [
            "# HELP snds_access_link_first_seen_timestamp_seconds Unix time the SNDS automated-access URL currently in use was first seen by this collector. Microsoft expires each link 30 days after it is generated.",
            "# TYPE snds_access_link_first_seen_timestamp_seconds gauge",
            f"snds_access_link_first_seen_timestamp_seconds {link_first_seen}",
        ]
    return "\n".join(lines) + "\n"


def read_link_first_seen(state_path: pathlib.Path, url: str, now: float) -> float:
    """When the URL currently in `SNDS_DATA_URL` was first seen here.

    Microsoft dates the 30-day expiry from when the link was generated and
    exposes that date nowhere in the response, so the age has to be observed
    rather than read. Deriving it from a rotation timestamp an operator
    maintains by hand was rejected: the failure mode is an operator who
    pastes a new URL and forgets the date, leaving an expiry alert quietly
    asserting a freshness that is not true. First-seen is observed from the
    URL itself and cannot drift from it.

    The state file stores a SHA-256 of the URL, never the URL: this file sits
    beside a world-readable textfile output, and the URL is a credential.
    Hash equality is all that is needed to answer "is this the same link as
    last time".

    An unreadable, missing or malformed state file is treated as a first
    sighting. That is the conservative direction: the age restarts at zero,
    so an expiry alert is late rather than falsely early -- and a stale link
    that outlives the miscount is still caught by the 404 handling and by
    `snds_collector_last_run_success`.
    """
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    try:
        state = json.loads(state_path.read_text())
        if state.get("url_sha256") == digest:
            first_seen = state.get("first_seen")
            if isinstance(first_seen, (int, float)):
                return float(first_seen)
    except (OSError, ValueError, AttributeError):
        pass

    try:
        state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        tmp_path = state_path.with_suffix(state_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps({"url_sha256": digest, "first_seen": now}))
        tmp_path.chmod(0o600)
        os.replace(tmp_path, state_path)
    except OSError as exc:
        print(
            f"collect_snds_metrics: could not record the access link's first-seen time: {exc}",
            file=sys.stderr,
        )
    return now


class UnexpectedResponseShapeError(RuntimeError):
    """Raised when SNDS answers HTTP 200 with a body that is not the
    plain-text/CSV feed this collector parses -- a login page, a consent
    screen, or a portal-side error rendered as HTML. `urlopen` raises
    `HTTPError` on 4xx/5xx, but a 200 status says nothing about payload
    shape: an HTML body parsed line-by-line as CSV yields zero records, not
    an error, so the caller cannot tell "no data today" from "wrong page"
    without this check. Raising here -- rather than letting the caller
    discover an empty record list downstream -- lets `main` treat this
    exactly like a fetch failure: no textfile write, no advanced timestamp.
    """


class AccessLinkRejectedError(RuntimeError):
    """Raised for the two status codes Microsoft documents as being about the
    access key itself.

    Split out from a generic fetch failure because the operator response is
    different and the message has to say so: 404 means the key is expired or
    never existed *or* that there is simply no data for the requested day --
    Microsoft returns one code for both, which no amount of parsing here can
    disambiguate -- and 400 means the key is malformed. Both are cleared by
    regenerating the link in the portal, neither by waiting.
    """


_UNEXPECTED_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})

# Documented on the SNDS portal's own automated-access page: 404 for a
# non-existent or expired key (and, ambiguously, for a day with no data), 400
# for a malformed one.
_ACCESS_KEY_STATUS_CODES = {
    404: (
        "HTTP 404 -- the automated-access link is expired or was never valid, "
        "or SNDS simply has no data for the requested day. Microsoft returns "
        "the same code for both, so this cannot be told apart from the "
        "response alone: check the link's age first (it expires 30 days after "
        "it is generated) and regenerate it in the portal if in doubt"
    ),
    400: (
        "HTTP 400 -- SNDS rejected the automated-access link as malformed. "
        "Regenerate it from the portal's automated-access page; a truncated "
        "paste into monitoring.env is the usual cause"
    ),
}


def _looks_like_markup(text: str) -> bool:
    """A body-shape fallback for when `Content-Type` is missing, wrong, or
    stripped by a proxy in front of the real response -- SNDS's HTML failure
    pages open with a doctype or an `<html>` tag, which its CSV feed never
    does. This runs in addition to, not instead of, the `Content-Type`
    check: a header is the cheaper and more precise signal when the server
    sets it correctly, but a shape check on the actual bytes is what still
    catches the case where it doesn't.
    """
    stripped = text.lstrip()
    return stripped[:15].lower().startswith(("<!doctype html", "<html"))


def fetch_snds_data(url: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> str:
    """The only network call in this module, kept separate from parsing so the
    parser (the security-sensitive half -- untrusted response text) is
    testable with no network at all.

    The URL carries its own access key; there is no header to set. Validates
    the response's shape before returning it: an HTTP 200 with an HTML body
    (`_UNEXPECTED_CONTENT_TYPES`, `_looks_like_markup`) is not a successful
    fetch of the feed this collector expects, even though `urlopen` raises
    nothing for it. See `UnexpectedResponseShapeError`.
    """
    request = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get_content_type()
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # `exc.msg` is the server's own reason phrase -- text this collector
        # does not control, reaching a log line that also has to stay free of
        # the access key. Redacted rather than trusted, and the exception is
        # never interpolated whole: `HTTPError` carries the full request URL
        # on `.url`, and `from None` keeps a chained traceback from printing
        # it even though `str(exc)` alone would not.
        detail = redact(str(exc.msg), url)
        explanation = _ACCESS_KEY_STATUS_CODES.get(exc.code)
        if explanation is not None:
            raise AccessLinkRejectedError(f"{explanation} (server said: {detail})") from None
        raise urllib.error.URLError(f"HTTP {exc.code} ({detail})") from None

    if content_type in _UNEXPECTED_CONTENT_TYPES or _looks_like_markup(body):
        raise UnexpectedResponseShapeError(
            f"expected the SNDS CSV/plain-text feed, got what looks like an "
            f"HTML page (Content-Type: {content_type!r}) -- a login, "
            "consent, or portal-side error page served as HTTP 200"
        )

    return body


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


def _publish_health(
    output_dir: pathlib.Path, now: float, succeeded: bool, link_first_seen: float | None
) -> None:
    """Health is best-effort by design: a collector that cannot write its own
    health file must not therefore fail a run that otherwise fetched real
    data. The write failure goes to the journal, and the absent gauge is
    itself caught by `SNDSCollectorStale`'s `absent(...)` branch.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        write_textfile_atomically(
            output_dir / HEALTH_FILENAME, render_health_text(now, succeeded, link_first_seen)
        )
    except OSError as exc:
        print(f"collect_snds_metrics: could not write the health textfile: {exc}", file=sys.stderr)


def main(argv: list[str]) -> int:
    del argv
    output_dir = pathlib.Path(
        os.environ.get("SNDS_OUTPUT_DIR", "/var/lib/branchleft/snds-exporter")
    )
    now = time.time()

    url = os.environ.get("SNDS_DATA_URL")
    if not url:
        print(
            "collect_snds_metrics: SNDS_DATA_URL is unset -- set it in "
            "/etc/branchleft/monitoring.env to the automated-access URL from "
            "the SNDS portal. Leaving any existing reputation output "
            "untouched.",
            file=sys.stderr,
        )
        _publish_health(output_dir, now, succeeded=False, link_first_seen=None)
        return 1

    link_first_seen = read_link_first_seen(output_dir / LINK_STATE_FILENAME, url, now)

    try:
        raw = fetch_snds_data(url)
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        UnexpectedResponseShapeError,
        AccessLinkRejectedError,
    ) as exc:
        print(f"collect_snds_metrics: fetch failed: {redact(str(exc), url)}", file=sys.stderr)
        _publish_health(output_dir, now, succeeded=False, link_first_seen=link_first_seen)
        return 1

    records = parse_snds_response(raw)
    output_path = output_dir / REPUTATION_FILENAME
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    write_textfile_atomically(output_path, render_prometheus_text(records, now))
    _publish_health(output_dir, now, succeeded=True, link_first_seen=link_first_seen)
    print(f"collect_snds_metrics: wrote {len(records)} IP record(s) to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
