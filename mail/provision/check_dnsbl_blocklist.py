#!/usr/bin/env python3
"""Checks the mail host's public IP against the major DNSBLs (DNS-based
blocklists) and raises a clear, actionable signal the moment any of them
lists it. A listed address silently kills deliverability for every sender
behind this host, which is exactly the kind of failure that must not wait
for someone to notice complaints.

Query mechanics (verified against each list's own docs and live DNS, not
assumed identical -- see mail/RUNBOOK-mx1-provision.md's "DNSBL blocklist
monitoring" section for the executed checks): every list in this set uses
the same reversed-octet query -- `<reversed IP>.<zone>` -- and answers with
either NXDOMAIN (not listed) or one or more A records in 127.0.0.0/8
(listed; the last octet encodes the sub-list/reason and differs per list,
irrelevant to this script beyond logging it). Spamhaus additionally
documents a distinct 127.255.255.0/24 range for *query* errors (e.g. "this
resolver is a public/open one and is blocked") that must never be read as
a reputation signal -- applied defensively to every zone here, since no
other list in this set is known to use that range for a real listing.

Self-test before trusting a "not listed" result: every run also queries
each zone for the industry-standard always-listed test address 127.0.0.2
(confirmed live for Spamhaus/Barracuda/SpamCop/UCEPROTECT). If that
sentinel doesn't come back listed, the zone isn't answering meaningfully --
dead, unreachable, or rate-limiting this host -- and the real target's
result for that zone is reported as inconclusive rather than clean. This
is not hypothetical: dnsbl.sorbs.net currently has no DNS delegation at
all (NXDOMAIN at the .net level, confirmed live) despite being in the
minimum DNSBL set here, so without this self-test the SORBS entry would
silently and permanently report "clean" while providing zero real signal.
See the RUNBOOK for the live evidence.

Queries go to the host's own local recursive resolver (127.0.0.1, unbound,
installed by 65-install-local-resolver.sh) addressed explicitly rather than
through the system resolver: Spamhaus answers 127.255.255.254 ("query
blocked") to anything reaching it from a high-volume shared resolver, which
a hosting provider's default resolvers and every public one are. If that local resolver is
down or broken every lookup fails, the zone self-test below fails with it,
and the run reports inconclusive -- never a false clean.

Uses only the standard library, consistent with this directory's other
scripts (see configure_stalwart.py's docstring for why) -- including the
DNS query itself, which is why there is a small wire-format encoder and
parser here rather than a dnspython dependency.

Usage:
    python3 check_dnsbl_blocklist.py            # run a live check, alert on findings
    python3 check_dnsbl_blocklist.py --status    # print the last recorded state, no query
"""
from __future__ import annotations

import argparse
import enum
import ipaddress
import json
import logging
import logging.handlers
import os
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Callable, Iterable

# The address to check. `DNSBL_TARGET_IP` wins when set; otherwise the mail
# host's own hostname is resolved at run time, so this file carries no address
# of its own and the check follows the host if it ever moves. Resolution
# happens in main() rather than here: a module-level DNS call would make an
# import fail on a machine with no network, including the unit tests.
TARGET_HOST = os.environ.get("DNSBL_TARGET_HOST", "mx1.branchleft.co.uk")
TARGET_IP = os.environ.get("DNSBL_TARGET_IP", "")
STATE_PATH = os.environ.get("DNSBL_STATE_PATH", "/root/.dnsbl-check-state.json")
RESOLVE_TIMEOUT_SECONDS = int(os.environ.get("DNSBL_RESOLVE_TIMEOUT_SECONDS", "10"))
SYSLOG_ADDRESS = os.environ.get("DNSBL_SYSLOG_ADDRESS", "/dev/log")

# The local recursive resolver, addressed explicitly -- see module docstring.
# An IP, never a hostname: resolving the resolver's own name would put the
# system resolver back in the path.
RESOLVER_ADDRESS = os.environ.get("DNSBL_RESOLVER_ADDRESS", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("DNSBL_RESOLVER_PORT", "53"))

# The address every DNSBL in this set either documents, or is understood by
# long-standing convention across the industry, as permanently listed --
# used to self-test that a zone is actually answering before trusting a
# "not listed" result for the real target. See module docstring.
SENTINEL_LISTED_IP = "127.0.0.2"

# Spamhaus-documented meta/error codes (query blocked/rate-limited -- not
# reputation data). Applied to every zone defensively; see module docstring.
QUERY_ERROR_PREFIX = "127.255.255."


class Verdict(str, enum.Enum):
    LISTED = "listed"
    NOT_LISTED = "not_listed"
    QUERY_ERROR = "query_error"
    LOOKUP_FAILED = "lookup_failed"
    ZONE_UNRESPONSIVE = "zone_unresponsive"


# Verdicts that mean "this needs a human's attention", as opposed to
# NOT_LISTED, which is the routine, no-news-is-good-news case.
ACTIONABLE_VERDICTS = frozenset(
    {Verdict.LISTED, Verdict.QUERY_ERROR, Verdict.LOOKUP_FAILED, Verdict.ZONE_UNRESPONSIVE}
)


@dataclass(frozen=True)
class DnsblSpec:
    key: str
    name: str
    zone: str
    delisting_url: str


# The minimum set worth checking. Delisting URLs point at each list's own current
# process -- deliberately not summarised or second-guessed here, since that
# guidance is list-specific and changes (see RUNBOOK).
DNSBLS: tuple[DnsblSpec, ...] = (
    DnsblSpec("spamhaus_zen", "Spamhaus ZEN", "zen.spamhaus.org", "https://check.spamhaus.org/"),
    DnsblSpec(
        "barracuda",
        "Barracuda Reputation Block List",
        "b.barracudacentral.org",
        "https://www.barracudacentral.org/rbl/removal-request",
    ),
    DnsblSpec("spamcop", "SpamCop Blocking List", "bl.spamcop.net", "https://www.spamcop.net/bl.shtml"),
    DnsblSpec("sorbs", "SORBS", "dnsbl.sorbs.net", "http://www.sorbs.net/lookup.shtml"),
    DnsblSpec(
        "uceprotect_l1",
        "UCEPROTECT Level 1",
        "dnsbl-1.uceprotect.net",
        "http://www.uceprotect.net/en/rblcheck.php",
    ),
)


@dataclass(frozen=True)
class ResolutionOutcome:
    """The raw result of one DNS A-record lookup, before any DNSBL-specific
    interpretation. `ok=True, addresses=()` is a confirmed NXDOMAIN (not
    listed) -- distinct from `ok=False`, a lookup that failed for some other
    reason (timeout, SERVFAIL, network error) and proves nothing either way.
    """

    ok: bool
    addresses: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class CheckResult:
    spec: DnsblSpec
    verdict: Verdict
    addresses: tuple[str, ...] = ()
    detail: str = ""


def reverse_ipv4(ip: str) -> str:
    """Pure: the reversed-octet form every DNSBL query name starts with.
    Raises ValueError for anything that isn't a plain IPv4 address -- every
    zone in this set is IPv4-only; an IPv6 target needs a different,
    nibble-reversed query form this script doesn't implement."""
    addr = ipaddress.IPv4Address(ip)
    return ".".join(reversed(addr.exploded.split(".")))


def build_query_name(ip: str, zone: str) -> str:
    """Pure: the full hostname queried for a DNSBL lookup."""
    return f"{reverse_ipv4(ip)}.{zone}"


def classify_outcome(outcome: ResolutionOutcome) -> Verdict:
    """Pure: turn a raw resolution outcome into a verdict, checked in an
    order that can never mistake a query-error code for a real listing."""
    if not outcome.ok:
        return Verdict.LOOKUP_FAILED
    if not outcome.addresses:
        return Verdict.NOT_LISTED
    if all(addr.startswith(QUERY_ERROR_PREFIX) for addr in outcome.addresses):
        return Verdict.QUERY_ERROR
    return Verdict.LISTED


def evaluate_dnsbl(
    spec: DnsblSpec, sentinel_outcome: ResolutionOutcome, target_outcome: ResolutionOutcome
) -> CheckResult:
    """Pure: combine a zone's self-test (sentinel_outcome, for
    SENTINEL_LISTED_IP) with the real target's lookup into one verdict. The
    self-test gates whether the target result can be trusted at all -- a
    zone that doesn't list the sentinel is providing no real signal, and the
    target is reported ZONE_UNRESPONSIVE rather than a possibly-false
    NOT_LISTED. See module docstring for why this matters (SORBS)."""
    sentinel_verdict = classify_outcome(sentinel_outcome)
    if sentinel_verdict != Verdict.LISTED:
        return CheckResult(
            spec,
            Verdict.ZONE_UNRESPONSIVE,
            detail=(
                f"self-test sentinel {SENTINEL_LISTED_IP} did not come back listed "
                f"(got {sentinel_verdict.value}) -- zone may be dead, unreachable, or "
                "rate-limiting this host; target result not trusted this run"
            ),
        )

    target_verdict = classify_outcome(target_outcome)
    if target_verdict == Verdict.QUERY_ERROR:
        return CheckResult(
            spec,
            Verdict.QUERY_ERROR,
            target_outcome.addresses,
            "zone returned a query-error code (e.g. public-resolver block), not a reputation signal",
        )
    if target_verdict == Verdict.LOOKUP_FAILED:
        return CheckResult(spec, Verdict.LOOKUP_FAILED, detail=target_outcome.error or "DNS lookup failed")
    return CheckResult(spec, target_verdict, target_outcome.addresses)


def build_alert(
    previous_state: dict[str, str], results: Iterable[CheckResult]
) -> tuple[dict[str, str], list[str]]:
    """Pure: given the last-known verdict per DNSBL key (from the persisted
    state file) and this run's results, return the state to persist next and
    the alert lines to log now. LISTED is logged every run it's true (a
    listing is never "routine"), marked NEW LISTING the first run it's seen
    versus STILL LISTED afterwards, so the two are never confused. Anything
    else actionable (a failed or self-test-failed lookup) is logged every
    run too -- an inconclusive check is not evidence of "clean" and must
    never look like the quiet, all-NOT_LISTED case."""
    new_state: dict[str, str] = {}
    alerts: list[str] = []
    for result in results:
        new_state[result.spec.key] = result.verdict.value
        was_listed = previous_state.get(result.spec.key) == Verdict.LISTED.value

        if result.verdict == Verdict.LISTED:
            marker = "STILL LISTED" if was_listed else "NEW LISTING"
            codes = ", ".join(result.addresses) or "(no codes returned)"
            alerts.append(
                f"{marker}: {result.spec.name} ({result.spec.zone}) lists {codes} -- "
                f"delisting process: {result.spec.delisting_url}"
            )
        elif result.verdict in ACTIONABLE_VERDICTS:
            alerts.append(
                f"CHECK INCONCLUSIVE: {result.spec.name} ({result.spec.zone}) -- {result.detail}"
            )
    return new_state, alerts


def run_checks(
    ip: str,
    dnsbls: Iterable[DnsblSpec],
    resolver: Callable[[str, int], ResolutionOutcome],
    previous_state: dict[str, str],
) -> tuple[dict[str, str], list[str], list[CheckResult]]:
    """Orchestration, but still no real I/O of its own -- `resolver` is
    injected so this can be exercised end-to-end (wiring included) against a
    fake resolver in tests, the same way evaluate_dnsbl/build_alert are
    tested against canned outcomes alone."""
    results = []
    for spec in dnsbls:
        sentinel_outcome = resolver(build_query_name(SENTINEL_LISTED_IP, spec.zone), RESOLVE_TIMEOUT_SECONDS)
        target_outcome = resolver(build_query_name(ip, spec.zone), RESOLVE_TIMEOUT_SECONDS)
        results.append(evaluate_dnsbl(spec, sentinel_outcome, target_outcome))
    new_state, alerts = build_alert(previous_state, results)
    return new_state, alerts, results


_DNS_TYPE_A = 1
_DNS_CLASS_IN = 1
_DNS_FLAG_RESPONSE = 0x8000
_DNS_FLAG_TRUNCATED = 0x0200
_DNS_FLAG_RECURSION_DESIRED = 0x0100
_DNS_RCODE_NOERROR = 0
_DNS_RCODE_NXDOMAIN = 3
_DNS_RCODE_NAMES = {1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED"}
# Larger than any DNSBL answer; unbound's default advertised EDNS buffer is
# smaller still, so a reply that doesn't fit is a truncation to retry over
# TCP, not something to read as data.
_MAX_UDP_RESPONSE = 4096
_MAX_COMPRESSION_JUMPS = 32


class _MalformedResponse(Exception):
    pass


def _encode_name(hostname: str) -> bytes:
    """Pure: a hostname in DNS wire format (length-prefixed labels, root
    terminator)."""
    labels = [label for label in hostname.strip(".").split(".") if label]
    if not labels:
        raise ValueError("empty hostname")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        encoded.append(len(raw))
        encoded += raw
    encoded.append(0)
    return bytes(encoded)


def _read_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Pure: decode the name at `offset`, following compression pointers,
    and return it with the offset of whatever follows the name *in situ*
    (which is not where a followed pointer ended up)."""
    labels: list[str] = []
    after_name = offset
    followed_pointer = False
    jumps = 0
    while True:
        if offset >= len(payload):
            raise _MalformedResponse("name runs past the end of the message")
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise _MalformedResponse("truncated compression pointer")
            if not followed_pointer:
                after_name = offset + 2
                followed_pointer = True
            jumps += 1
            if jumps > _MAX_COMPRESSION_JUMPS:
                raise _MalformedResponse("compression pointer loop")
            offset = ((length & 0x3F) << 8) | payload[offset + 1]
            continue
        if length & 0xC0:
            raise _MalformedResponse("reserved label type")
        offset += 1
        if length == 0:
            return ".".join(labels), (after_name if followed_pointer else offset)
        if offset + length > len(payload):
            raise _MalformedResponse("label runs past the end of the message")
        labels.append(payload[offset : offset + length].decode("ascii", "replace"))
        offset += length


def build_query(hostname: str, query_id: int) -> bytes:
    """Pure: a single recursion-desired A query in DNS wire format."""
    header = struct.pack(">HHHHHH", query_id, _DNS_FLAG_RECURSION_DESIRED, 1, 0, 0, 0)
    return header + _encode_name(hostname) + struct.pack(">HH", _DNS_TYPE_A, _DNS_CLASS_IN)


def parse_response(payload: bytes, query_id: int, hostname: str) -> ResolutionOutcome:
    """Pure: interpret a raw DNS response. Only NXDOMAIN and NOERROR-with-no-A
    produce the `ok=True, addresses=()` that upstream reads as "not listed" --
    every other outcome, including anything malformed or unexpected, is
    ok=False, because a lookup that proves nothing must never be mistaken for
    a clean one."""
    try:
        if len(payload) < 12:
            raise _MalformedResponse("response is shorter than a DNS header")
        response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", payload[:12])
        if response_id != query_id:
            raise _MalformedResponse(f"response id {response_id} does not match query id {query_id}")
        if not flags & _DNS_FLAG_RESPONSE:
            raise _MalformedResponse("message is not a response")

        offset = 12
        question_name = ""
        for index in range(qdcount):
            name, offset = _read_name(payload, offset)
            if index == 0:
                question_name = name
            offset += 4
        if qdcount and question_name.lower() != hostname.strip(".").lower():
            raise _MalformedResponse(f"response answers a different question ({question_name!r})")

        rcode = flags & 0x000F
        if rcode == _DNS_RCODE_NXDOMAIN:
            return ResolutionOutcome(ok=True, addresses=())
        if rcode != _DNS_RCODE_NOERROR:
            name = _DNS_RCODE_NAMES.get(rcode, f"rcode {rcode}")
            return ResolutionOutcome(ok=False, error=f"{hostname}: resolver returned {name}")

        addresses: list[str] = []
        for _ in range(ancount):
            _record_name, offset = _read_name(payload, offset)
            if offset + 10 > len(payload):
                raise _MalformedResponse("answer record header runs past the end of the message")
            rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", payload[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(payload):
                raise _MalformedResponse("answer record data runs past the end of the message")
            rdata = payload[offset : offset + rdlength]
            offset += rdlength
            if rtype == _DNS_TYPE_A and rclass == _DNS_CLASS_IN and rdlength == 4:
                addresses.append(".".join(str(octet) for octet in rdata))

        if not addresses and flags & _DNS_FLAG_TRUNCATED:
            return ResolutionOutcome(ok=False, error=f"{hostname}: truncated response with no usable answer")
        return ResolutionOutcome(ok=True, addresses=tuple(sorted(set(addresses))))
    except _MalformedResponse as exc:
        return ResolutionOutcome(ok=False, error=f"{hostname}: {exc}")


def resolver_socket_family(address: str) -> int:
    """Pure: the socket family for a resolver address. Raises ValueError for
    anything that isn't a literal IP -- a hostname here would be resolved by
    the system resolver, putting back the very hop this bypasses."""
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def resolve_a_records(hostname: str, timeout_seconds: int) -> ResolutionOutcome:
    """I/O: ask RESOLVER_ADDRESS directly for `hostname`'s A records over
    UDP. The resolver is addressed explicitly rather than inherited from
    /etc/resolv.conf because Spamhaus answers a query-error code, not
    reputation data, to queries arriving via a shared upstream resolver (see
    module docstring and QUERY_ERROR_PREFIX).

    A dead or unreachable resolver surfaces here as ok=False, which the zone
    self-test in evaluate_dnsbl turns into an inconclusive run rather than a
    clean one.
    """
    timeout = max(1, timeout_seconds)
    query_id = int.from_bytes(os.urandom(2), "big")
    try:
        family = resolver_socket_family(RESOLVER_ADDRESS)
        query = build_query(hostname, query_id)
    except ValueError as exc:
        return ResolutionOutcome(ok=False, error=f"{hostname}: {exc}")

    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # Connected UDP: the kernel then drops anything not from this
            # resolver, and a refused port surfaces as an error instead of a
            # silent timeout.
            sock.connect((RESOLVER_ADDRESS, RESOLVER_PORT))
            sock.send(query)
            payload = sock.recv(_MAX_UDP_RESPONSE)
    except socket.timeout:
        return ResolutionOutcome(
            ok=False,
            error=f"{hostname}: no reply from {RESOLVER_ADDRESS}:{RESOLVER_PORT} within {timeout}s",
        )
    except OSError as exc:
        return ResolutionOutcome(ok=False, error=f"{hostname}: {RESOLVER_ADDRESS}:{RESOLVER_PORT}: {exc}")

    return parse_response(payload, query_id, hostname)


def _load_state(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        # A corrupt state file must not crash the check or silently pretend
        # everything was clean before -- start fresh (every DNSBL reports as
        # if newly listed at worst, which is the safe direction to be wrong
        # in) but say so loudly.
        logging.getLogger("dnsbl-check").error("state file %s unreadable (%s), starting fresh", path, exc)
        return {}


def _save_state(path: str, state: dict[str, str]) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)


def _syslog_socket_reachable(address: str) -> bool:
    """SysLogHandler's own constructor doesn't reliably fail when `address`
    isn't a live socket -- on some platforms (confirmed: macOS, no /dev/log)
    it connects lazily on the first emit() instead, so a bare try/except
    around construction misses the failure and it surfaces later as a
    logging-internals traceback on stderr rather than a clean fallback.
    Probing the connection directly, up front, avoids that regardless of
    platform."""
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            probe.connect(address)
        finally:
            probe.close()
        return True
    except OSError:
        return False


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("dnsbl-check")
    logger.setLevel(logging.INFO)
    if _syslog_socket_reachable(SYSLOG_ADDRESS):
        handler: logging.Handler = logging.handlers.SysLogHandler(address=SYSLOG_ADDRESS)
        handler.setFormatter(logging.Formatter("dnsbl-check: %(levelname)s %(message)s"))
    else:
        # No live /dev/log -- off-box, in CI, or a container without a
        # syslog socket. Fall back to stderr so the check still runs rather
        # than crashing; cron captures stderr into its own mail/log path
        # either way.
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s dnsbl-check: %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


def _print_status(state: dict[str, str]) -> int:
    if not state:
        print("check_dnsbl_blocklist: no recorded state yet -- run without --status first")
        return 0
    by_key = {spec.key: spec for spec in DNSBLS}
    for key, verdict in sorted(state.items()):
        spec = by_key.get(key)
        label = spec.name if spec else key
        print(f"{label}\t{verdict}")
    return 0


def resolve_target_address(hostname: str) -> str:
    """The IPv4 address to check, from the mail host's own hostname.

    A hostname with more than one A record has no single answer here, and
    quietly checking whichever one the resolver returned first would report a
    clean result for an address that is not the one sending mail. Raise
    instead; the caller turns it into an inconclusive run, never a clean one.
    """
    addresses = sorted({info[4][0] for info in socket.getaddrinfo(hostname, None, socket.AF_INET)})
    if len(addresses) != 1:
        raise ValueError(f"{hostname} resolves to {len(addresses)} IPv4 addresses: {addresses}")
    return addresses[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--status", action="store_true", help="print the last recorded state and exit, without querying DNS"
    )
    args = parser.parse_args(argv)

    if args.status:
        return _print_status(_load_state(STATE_PATH))

    logger = _configure_logging()
    try:
        target = TARGET_IP or resolve_target_address(TARGET_HOST)
        previous_state = _load_state(STATE_PATH)
        new_state, alerts, results = run_checks(target, DNSBLS, resolve_a_records, previous_state)
        _save_state(STATE_PATH, new_state)
    except Exception:
        # Anything unhandled here (disk pressure, permissions drift, a
        # future bug in resolve_a_records) must still reach journald -- the
        # RUNBOOK tells the platform owner that `journalctl -t dnsbl-check
        # -p err -b` is the authoritative "does anything need attention"
        # check, and a crash that only reaches stderr defeats the entire
        # point of an unattended check: nobody should have to remember to
        # look. logger.exception embeds the traceback in the log record
        # itself, not just a one-line summary.
        logger.exception("dnsbl check crashed before completing")
        return 1

    if alerts:
        for line in alerts:
            logger.error(line)
        logger.error(
            "dnsbl check for %s: %d of %d list(s) need attention", target, len(alerts), len(results)
        )
        return 1

    logger.info("dnsbl check for %s: clean on all %d list(s)", target, len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
