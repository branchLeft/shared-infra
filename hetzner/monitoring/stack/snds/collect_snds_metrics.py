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
import re
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

    # Both the decoded and the raw form of every parameter value. `parse_qsl`
    # percent-decodes, so it alone produces a needle that never matches a
    # server or proxy echoing the request line back verbatim -- and a key
    # containing any of `/+=`, which a base64-shaped one usually does, is
    # exactly the case that reaches a log in its encoded form.
    candidates: list[str] = []
    for _name, value in urllib.parse.parse_qsl(query, keep_blank_values=False):
        candidates.append(value)
    for raw_pair in query.split("&"):
        _, _, raw_value = raw_pair.partition("=")
        candidates.append(raw_value)

    # A short value cannot be an access key and may well be a literal
    # substring of ordinary prose ("data", "1"), so replacing it would
    # corrupt the message without protecting anything.
    for value in sorted(set(candidates), key=len, reverse=True):
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
    # SNDS reports "< 0.1%" for a healthy IP -- its most common value, and one
    # float() cannot parse. Mapping it to None would put every clean IP in the
    # "no rate computed" bucket, which is the opposite of what SNDS said: it
    # computed a rate and reported it as below a bound. The bound itself is
    # the value, which keeps the series present and leaves
    # SNDSComplaintRateHigh's own `> 0.001` comparison to decide.
    if token.startswith(("<", ">")):
        token = token[1:].strip()
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


def _looks_like_a_header(first_field: str) -> bool:
    """Whether the feed's first row names its columns rather than carrying data.

    Matched by shape rather than against a list of spellings. A fixed list
    (`ip address`, `ip`) fails open in the direction that matters: a header
    spelled `ip_address` or `Sending IP` is counted as a data line, skipped
    for not being an address, and on a day with no other rows that makes
    `every_line_was_skipped` true -- a schema alarm raised by a quiet day.
    A first field that is not an address but reads as a column name is a
    header whatever Microsoft calls it.
    """
    token = first_field.strip()
    if not token:
        return False
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]*", token))
    return False


@dataclass(frozen=True)
class ParsedFeed:
    """What a parse found, including what it threw away.

    The discard count is the load-bearing part. `records` alone cannot
    distinguish a day on which SNDS reported nothing from a response whose
    every row failed validation, and those are opposite claims: the first is
    a quiet day, the second is a feed this parser no longer understands.
    Collapsing them is what lets a schema change read as a clean reputation.
    """

    records: list[IpReputation]
    data_lines: int
    skipped_lines: int

    @property
    def every_line_was_skipped(self) -> bool:
        return self.data_lines > 0 and self.skipped_lines == self.data_lines

    @property
    def yielded_nothing_the_alerts_can_read(self) -> bool:
        """Records parsed, but not one carries a status or a rate.

        `every_line_was_skipped` only catches a reorder that displaces the IP
        out of field 0. The reorder that actually happens does not: SNDS's
        automated-access CSV carries activity timestamps and command counts
        between the address and the filter result, so every row still starts
        with a valid IP, every row parses, and the two columns the alerts
        read come back empty -- with a command count landing in
        `snds_message_volume`, which also satisfies (and so disables)
        SNDSComplaintRateHigh's `unless on(ip) snds_message_volume` fallback.
        Zero records is not this case: no rows at all is a quiet day.
        """
        return bool(self.records) and not any(
            r.status is not None or r.complaint_rate is not None for r in self.records
        )


def parse_snds_feed(text: str) -> ParsedFeed:
    """Parses SNDS's per-IP status feed into validated records.

    Deliberately defensive rather than schema-strict: Microsoft's 2026
    migration moved this from a documented key-based `data.txt` download to
    an automated-access CSV whose columns are documented only by example, so
    the parser tolerates an optional header row, ragged field counts, and
    per-line failures rather than assuming today's observed shape is a
    contract. A line that fails validation is skipped and reported to
    stderr, not fatal to the run -- one bad row (a truncated line, a non-IP
    first field) must not blank out every IP's data for the day.

    Tolerating every line is a different matter, which is why the counts
    come back with the records: if Microsoft reorders the columns so that
    the first field is no longer an address, every row is skipped
    individually and this returns zero records without a single fatal error.
    The caller needs to be able to tell that from an empty feed.

    Column order, when present: IP address, filter-result status
    (green/yellow/red), complaint rate, message volume. The last two are
    optional -- a two-column line still yields a status-only record.
    """
    records: list[IpReputation] = []
    data_lines = 0
    skipped_lines = 0
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(",")]
        ip_field = fields[0]
        if not records and data_lines == 0 and _looks_like_a_header(ip_field):
            continue  # a header row, not data
        data_lines += 1

        try:
            ip = str(ipaddress.ip_address(ip_field))
        except ValueError:
            print(
                f"collect_snds_metrics: line {lineno}: {ip_field!r} is not a valid IP address, skipped",
                file=sys.stderr,
            )
            skipped_lines += 1
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

    return ParsedFeed(records=records, data_lines=data_lines, skipped_lines=skipped_lines)


def parse_snds_response(text: str) -> list[IpReputation]:
    """The records alone, for callers that do not need the discard counts."""
    return parse_snds_feed(text).records


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
    lines += [
        "# HELP snds_link_state_readable Whether this collector could persist the access link's first-seen time (1) or not (0). At 0 the link-age gauge below is absent and the expiry alert cannot fire.",
        "# TYPE snds_link_state_readable gauge",
        f"snds_link_state_readable {0 if link_first_seen is None else 1}",
    ]
    if link_first_seen is not None:
        lines += [
            "# HELP snds_access_link_first_seen_timestamp_seconds Unix time the SNDS automated-access URL currently in use was first seen by this collector. Microsoft expires each link 30 days after it is generated.",
            "# TYPE snds_access_link_first_seen_timestamp_seconds gauge",
            f"snds_access_link_first_seen_timestamp_seconds {link_first_seen}",
        ]
    return "\n".join(lines) + "\n"


def read_link_first_seen(state_path: pathlib.Path, url: str, now: float) -> float | None:
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

    An unreadable or malformed state file is treated as a first sighting:
    the age restarts at zero, so an expiry alert is late rather than falsely
    early, and a stale link that outlives the miscount is still caught by the
    404 handling and by `snds_collector_last_run_success`. A state file that
    cannot be WRITTEN is a different matter and returns `None` -- see below.
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
        # Not merely "the age restarts at zero". A write that keeps failing
        # restarts it on EVERY run, so the age never reaches 25 days and
        # SNDSAccessLinkExpiringSoon -- the only alert here that fires before
        # an outage rather than after one -- can never fire at all. A stderr
        # line nobody reads is not a signal, so the failure is published.
        return None
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


class MalformedDataUrlError(RuntimeError):
    """The configured URL is not a fetchable http(s) URL at all.

    Separate from `AccessLinkRejectedError`, which is the server's verdict on
    a well-formed URL: this one never leaves the host, so no status code
    exists to report and the remedy is a re-paste rather than a rotation.
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
    # Checked before `Request()` rather than after, because `Request()` itself
    # raises ValueError on a URL with no usable scheme -- outside any handler
    # that knows the URL is a credential, and carrying the whole URL in the
    # exception text. A truncated paste into monitoring.env is the anticipated
    # operator error here (see the 400 message below), and the subset of it
    # that never reaches the server must not be the one path that logs the key.
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise MalformedDataUrlError(
            f"SNDS_DATA_URL does not start with http:// or https:// (scheme: "
            f"{scheme or 'none'!r}) -- it is probably a truncated paste; "
            "re-copy the whole URL from the portal's automated-access page"
        )

    try:
        request = urllib.request.Request(url)
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


def _collect(output_dir: pathlib.Path, now: float) -> tuple[int, float | None]:
    """One run's real work. `(exit_code, link_first_seen)`.

    Split from `main` so that `main` can publish health for *every* way this
    can end, including the ways it can raise. Anything raised here reaches
    `main`'s own handler with the URL still in scope to redact against.
    """
    url = os.environ.get("SNDS_DATA_URL")
    if not url:
        print(
            "collect_snds_metrics: SNDS_DATA_URL is unset -- set it in "
            "/etc/branchleft/monitoring.env to the automated-access URL from "
            "the SNDS portal. Leaving any existing reputation output "
            "untouched.",
            file=sys.stderr,
        )
        return 1, None

    link_first_seen = read_link_first_seen(output_dir / LINK_STATE_FILENAME, url, now)

    try:
        raw = fetch_snds_data(url)
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        UnexpectedResponseShapeError,
        AccessLinkRejectedError,
        MalformedDataUrlError,
    ) as exc:
        print(f"collect_snds_metrics: fetch failed: {redact(str(exc), url)}", file=sys.stderr)
        return 1, link_first_seen

    feed = parse_snds_feed(raw)

    # A response whose every row failed validation is not a quiet day, and
    # writing it out would replace real reputation values with an empty file
    # that reads exactly like "no complaints on record". The most likely cause
    # is Microsoft changing the feed's column order, which this parser cannot
    # detect any other way: each row is skipped individually and nothing
    # raises. A genuinely empty feed (no data lines at all) is still a
    # success, because a quiet day must not page.
    if feed.every_line_was_skipped:
        print(
            "collect_snds_metrics: every one of the "
            f"{feed.data_lines} data line(s) failed validation -- treating "
            "this as a failed run rather than as an empty reputation "
            "snapshot. The feed's shape has probably changed; the skipped-line "
            "warnings above name the first field that stopped parsing. "
            "Leaving the previous reputation output untouched.",
            file=sys.stderr,
        )
        return 1, link_first_seen

    if feed.yielded_nothing_the_alerts_can_read:
        print(
            f"collect_snds_metrics: parsed {len(feed.records)} row(s), but not "
            "one carried a filter result or a complaint rate -- the two "
            "columns every reputation alert reads. Treating this as a failed "
            "run rather than publishing a snapshot that would read as a clean "
            "reputation. The column order has probably changed; compare a live "
            "response against the order RUNBOOK-monitoring.md's SNDS section "
            "documents. Leaving the previous reputation output untouched.",
            file=sys.stderr,
        )
        return 1, link_first_seen

    output_path = output_dir / REPUTATION_FILENAME
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    write_textfile_atomically(output_path, render_prometheus_text(feed.records, now))
    print(f"collect_snds_metrics: wrote {len(feed.records)} IP record(s) to {output_path}")
    return 0, link_first_seen


def main(argv: list[str]) -> int:
    del argv
    output_dir = pathlib.Path(
        os.environ.get("SNDS_OUTPUT_DIR", "/var/lib/branchleft/snds-exporter")
    )
    now = time.time()
    link_first_seen: float | None = None

    try:
        exit_code, link_first_seen = _collect(output_dir, now)
    except Exception as exc:
        # Broad, and deliberately not re-raising. Two things must
        # hold however this run dies: the access key must not reach the
        # journal, and `snds_collector_last_run_success` must not be left at
        # whatever the last good run wrote. A gauge frozen at 1 by a crash is
        # worse than no gauge -- it actively asserts health, and every alert
        # in the group reads it. An unredacted traceback is suppressed for the
        # same reason: the URL is a credential and a traceback can carry it.
        # `Exception`, not `BaseException`: swallowing KeyboardInterrupt and
        # SystemExit would turn an operator's Ctrl-C into a written
        # "last run failed", and no test distinguished the two -- narrowing
        # from BaseException to Exception left all of them green.
        print(
            "collect_snds_metrics: run failed with an unexpected "
            f"{type(exc).__name__}: "
            f"{redact(str(exc), os.environ.get('SNDS_DATA_URL') or '')}",
            file=sys.stderr,
        )
        _publish_health(output_dir, now, succeeded=False, link_first_seen=link_first_seen)
        return 1

    _publish_health(output_dir, now, succeeded=exit_code == 0, link_first_seen=link_first_seen)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
