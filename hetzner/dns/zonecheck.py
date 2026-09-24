#!/usr/bin/env python3
"""Capture a DNS zone from its authoritative servers, and compare two sets of
authoritative servers against the checked-in zone file record by record.

    zonecheck.py capture --server ns1049.ui-dns.de --out zone.json
    zonecheck.py compare --left ns1049.ui-dns.de,ns1067.ui-dns.com \\
                         --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com

Every query goes straight to a named server with recursion off, and every
answer must carry the authoritative-answer flag. Asking a recursive resolver
instead would answer from whichever provider the registry currently delegates
to, so both sides of a comparison would silently be the same side.

**The registrar refuses zone transfers**, so no enumeration is exhaustive: a
name is only captured if it is on the probe list. `probe_names` in the zone
file is that list, and every name on it is compared on both sides, present or
absent -- a name present at one provider and NXDOMAIN at the other is a diff
like any other. The cutover runbook pairs this with a count check against the
registrar's own record listing, which is the only exhaustive view there is.

**An empty diff is only reported after the check has proved it can fail.**
Two controls run on every comparison. The apex NS set must differ between the
two sides -- each provider serves its own -- which proves the two server lists
really are different servers. And the comparison is re-run once with one
record in the expected zone deliberately altered, which must be reported as a
diff; if it is not, the run fails rather than printing an all-clear.

Needs `dig` on PATH and nothing outside the standard library.

Exit codes: 0 no differences, 1 differences, 2 a server did not answer
authoritatively, 3 a control failed.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable

DEFAULT_ZONE_FILE = pathlib.Path(__file__).resolve().parent / "zone.json"

# Every type the zone may carry, including ones it does not use today: a type
# that is never queried can differ between providers without any diff.
PROBE_TYPES = (
    "A",
    "AAAA",
    "CAA",
    "CNAME",
    "HTTPS",
    "MX",
    "NS",
    "PTR",
    "SRV",
    "SVCB",
    "TLSA",
    "TXT",
)

# Owned by whichever provider serves the zone, so they differ by construction.
PROVIDER_OWNED = {("@", "NS"), ("@", "SOA")}

# Rdata fields holding a domain name, which DNS compares case-insensitively.
_NAME_FIELDS = {"CNAME": [0], "NS": [0], "PTR": [0], "MX": [1], "SRV": [3]}

# Older dig releases (macOS ships 9.10) do not know these mnemonics and read
# them as a second query *name*, which the server then refuses. The generic
# TYPEnn spelling is understood by every release.
_QUERY_TOKEN = {"HTTPS": "TYPE65", "SVCB": "TYPE64"}

_STATUS = re.compile(r"status: ([A-Z]+)")
_FLAGS = re.compile(r";; flags: ([a-z ]*);")


class QueryError(Exception):
    """A server that did not give an authoritative answer."""


@dataclass(frozen=True)
class Answer:
    rcode: str
    records: frozenset[tuple[int, str]]  # (ttl, normalised rdata)

    def values(self) -> frozenset[str]:
        return frozenset(rdata for _, rdata in self.records)


Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _run_dig(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def fqdn(name: str, zone: str) -> str:
    zone = zone.rstrip(".").lower()
    if name == "@":
        return f"{zone}."
    return f"{name.lower()}.{zone}."


def normalise_rdata(rtype: str, rdata: str) -> str:
    """One canonical spelling per record value, so equal records compare equal.

    TXT is left exactly as served: its character-string boundaries are part
    of the value, and a provider re-splitting a long record is a real change
    worth seeing, not noise to fold away.
    """
    rdata = rdata.strip()
    if rtype == "TXT":
        return rdata
    if rtype == "AAAA":
        return str(ipaddress.IPv6Address(rdata))
    if rtype == "A":
        return str(ipaddress.IPv4Address(rdata))
    parts = rdata.split()
    for index in _NAME_FIELDS.get(rtype, []):
        if index < len(parts):
            name = parts[index].lower()
            parts[index] = name if name.endswith(".") else name + "."
    if rtype == "CAA" and len(parts) >= 2:
        parts[1] = parts[1].lower()
    return " ".join(parts)


def parse_dig(output: str, qname: str, qtype: str) -> tuple[str, set[str], set[tuple[int, str]]]:
    """(rcode, header flags, answer records of exactly qname/qtype)."""
    rcode = None
    flags: set[str] = set()
    records: set[tuple[int, str]] = set()
    for line in output.splitlines():
        if line.startswith(";"):
            status = _STATUS.search(line)
            if status:
                rcode = status.group(1)
            flag_match = _FLAGS.search(line)
            if flag_match:
                flags = set(flag_match.group(1).split())
            continue
        fields = line.split(None, 4)
        if len(fields) < 5 or fields[2] != "IN":
            continue
        owner, ttl, _, rtype, rdata = fields
        # A query for one type can carry others in the answer (a CNAME chain);
        # they belong to a different comparison.
        if owner.lower() != qname.lower() or rtype not in (qtype, _QUERY_TOKEN.get(qtype)):
            continue
        records.add((int(ttl), normalise_rdata(qtype, rdata)))
    if rcode is None:
        raise QueryError(output.strip().splitlines()[-1] if output.strip() else "no output from dig")
    return rcode, flags, records


def split_server(spec: str) -> tuple[str, int]:
    host, sep, port = spec.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return spec, 53


def query(server: str, name: str, rtype: str, run: Runner = _run_dig) -> Answer:
    host, port = split_server(server)
    argv = [
        "dig",
        "+norec",
        "+noall",
        "+comments",
        "+answer",
        "+time=3",
        "+tries=2",
        "-p",
        str(port),
        f"@{host}",
        name,
        _QUERY_TOKEN.get(rtype, rtype),
    ]
    result = run(argv)
    try:
        rcode, flags, records = parse_dig(result.stdout, name, rtype)
    except QueryError as error:
        raise QueryError(f"{server} {name} {rtype}: {error}") from None
    if rcode not in ("NOERROR", "NXDOMAIN"):
        raise QueryError(f"{server} {name} {rtype}: {rcode}")
    if "aa" not in flags:
        raise QueryError(
            f"{server} {name} {rtype}: answer is not authoritative -- "
            "this server does not serve the zone"
        )
    return Answer(rcode, frozenset(records))


# --------------------------------------------------------------------------
# The zone file
# --------------------------------------------------------------------------


@dataclass
class Zone:
    name: str
    rrsets: dict[tuple[str, str], tuple[int, frozenset[str]]]
    probe_names: list[str]
    extra: dict = field(default_factory=dict)

    def names(self) -> list[str]:
        seen = {name for name, _ in self.rrsets} | set(self.probe_names)
        return sorted(seen, key=lambda n: (n != "@", n))

    def expected_rcode(self, name: str) -> str:
        """NOERROR for a name that holds records or has a name below it."""
        suffix = "." + name
        for owner, _ in self.rrsets:
            if owner == name or (name != "@" and owner.endswith(suffix)):
                return "NOERROR"
        return "NXDOMAIN" if name != "@" else "NOERROR"


def load_zone(path: pathlib.Path) -> Zone:
    data = json.loads(path.read_text())
    rrsets: dict[tuple[str, str], tuple[int, frozenset[str]]] = {}
    for entry in data["rrsets"]:
        key = (entry["name"], entry["type"])
        if key in rrsets:
            raise ValueError(f"{path}: {key[0]} {key[1]} appears twice")
        if key in PROVIDER_OWNED:
            raise ValueError(f"{path}: {key[0]} {key[1]} is owned by the serving provider")
        values = frozenset(normalise_rdata(entry["type"], value) for value in entry["values"])
        rrsets[key] = (int(entry["ttl"]), values)
    extra = {k: v for k, v in data.items() if k not in ("zone", "rrsets", "probe_names")}
    return Zone(data["zone"], rrsets, list(data.get("probe_names", [])), extra)


def zone_to_json(zone: Zone) -> str:
    rrsets = [
        {"name": name, "type": rtype, "ttl": ttl, "values": sorted(values)}
        for (name, rtype), (ttl, values) in sorted(
            zone.rrsets.items(), key=lambda item: (item[0][0] != "@", item[0])
        )
    ]
    data = dict(zone.extra)
    data.update({"zone": zone.name, "rrsets": rrsets, "probe_names": sorted(set(zone.probe_names))})
    return json.dumps(data, indent=2) + "\n"


# --------------------------------------------------------------------------
# Capture and compare
# --------------------------------------------------------------------------


def capture(zone_name: str, server: str, names: Iterable[str], run: Runner = _run_dig) -> Zone:
    rrsets: dict[tuple[str, str], tuple[int, frozenset[str]]] = {}
    for name in names:
        for rtype in PROBE_TYPES:
            if (name, rtype) in PROVIDER_OWNED:
                continue
            answer = query(server, fqdn(name, zone_name), rtype, run)
            if not answer.records:
                continue
            ttls = {ttl for ttl, _ in answer.records}
            if len(ttls) != 1:
                raise ValueError(f"{name} {rtype} is served with mixed TTLs {sorted(ttls)}")
            rrsets[(name, rtype)] = (ttls.pop(), answer.values())
    return Zone(zone_name, rrsets, list(names))


@dataclass(frozen=True)
class Diff:
    server: str
    name: str
    rtype: str
    expected: str
    got: str

    def __str__(self) -> str:
        return f"{self.server}  {self.name} {self.rtype}\n    expected: {self.expected}\n    got:      {self.got}"


def _describe(values: Iterable[str]) -> str:
    values = sorted(values)
    return " | ".join(values) if values else "(none)"


def diff_server(zone: Zone, server: str, answers: dict[tuple[str, str], Answer], check_ttl: bool) -> list[Diff]:
    diffs: list[Diff] = []
    for name in zone.names():
        rcode_answer = answers[(name, PROBE_TYPES[0])]
        expected_rcode = zone.expected_rcode(name)
        if rcode_answer.rcode != expected_rcode:
            diffs.append(Diff(server, name, "rcode", expected_rcode, rcode_answer.rcode))
        for rtype in PROBE_TYPES:
            if (name, rtype) in PROVIDER_OWNED:
                continue
            got = answers[(name, rtype)]
            ttl, expected_values = zone.rrsets.get((name, rtype), (None, frozenset()))
            if got.values() != expected_values:
                diffs.append(Diff(server, name, rtype, _describe(expected_values), _describe(got.values())))
            elif check_ttl and expected_values and {t for t, _ in got.records} != {ttl}:
                got_ttls = sorted({t for t, _ in got.records})
                diffs.append(Diff(server, name, f"{rtype} ttl", str(ttl), ", ".join(map(str, got_ttls))))
    return diffs


def fetch(zone: Zone, server: str, run: Runner) -> dict[tuple[str, str], Answer]:
    keys = [(name, rtype) for name in zone.names() for rtype in PROBE_TYPES]
    # Serially this is several minutes per server; eight in flight stays well
    # inside what an authoritative server answers without rate limiting.
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = pool.map(lambda key: query(server, fqdn(key[0], zone.name), key[1], run), keys)
        return dict(zip(keys, results))


def altered_copy(zone: Zone) -> tuple[Zone, tuple[str, str]]:
    """The zone with one record's value changed -- the control case."""
    key = sorted(zone.rrsets, key=lambda k: (k[0] != "@", k))[0]
    ttl, values = zone.rrsets[key]
    control = copy.deepcopy(zone)
    control.rrsets[key] = (ttl, frozenset({"control-case-altered-value"}))
    return control, key


@dataclass
class Report:
    diffs: list[Diff]
    control_failures: list[str]


def compare(
    zone: Zone,
    left: list[str],
    right: list[str],
    run: Runner = _run_dig,
    check_ttl: bool = False,
) -> Report:
    """Every server on both sides against the zone file, plus both controls.

    Comparing each server with the file rather than the two sides with each
    other is what makes the diff record-by-record: a record both providers
    lost would otherwise agree with itself.
    """
    control_failures: list[str] = []
    apex = fqdn("@", zone.name)
    left_ns = {s: query(s, apex, "NS", run).values() for s in left}
    right_ns = {s: query(s, apex, "NS", run).values() for s in right}
    for l_server, l_ns in left_ns.items():
        for r_server, r_ns in right_ns.items():
            if l_ns == r_ns:
                control_failures.append(
                    f"{l_server} and {r_server} serve the same apex NS set, so they are not "
                    "two different providers -- a comparison between them proves nothing"
                )

    diffs: list[Diff] = []
    control, control_key = altered_copy(zone)
    for server in [*left, *right]:
        answers = fetch(zone, server, run)
        diffs.extend(diff_server(zone, server, answers, check_ttl))
        caught = [d for d in diff_server(control, server, answers, check_ttl) if (d.name, d.rtype) == control_key]
        if not caught:
            control_failures.append(
                f"{server}: a deliberately altered {control_key[0]} {control_key[1]} was not "
                "reported, so an empty diff from this server would mean nothing"
            )
    return Report(diffs, control_failures)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _servers(value: str) -> list[str]:
    servers = [s.strip() for s in value.split(",") if s.strip()]
    if not servers:
        raise argparse.ArgumentTypeError("at least one server")
    return servers


def main(argv: list[str] | None = None, run: Runner = _run_dig) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture", help="read the zone from one authoritative server")
    cap.add_argument("--server", required=True)
    cap.add_argument("--zone-file", type=pathlib.Path, default=DEFAULT_ZONE_FILE,
                     help="its zone name and probe_names are reused; its records are not")
    cap.add_argument("--out", type=pathlib.Path, required=True)

    cmp_ = sub.add_parser("compare", help="diff two sets of authoritative servers against the zone file")
    cmp_.add_argument("--zone-file", type=pathlib.Path, default=DEFAULT_ZONE_FILE)
    cmp_.add_argument("--left", type=_servers, required=True)
    cmp_.add_argument("--right", type=_servers, required=True)
    cmp_.add_argument("--check-ttl", action="store_true",
                      help="also report TTLs that differ from the zone file")

    args = parser.parse_args(argv)
    try:
        existing = load_zone(args.zone_file)
        if args.command == "capture":
            zone = capture(existing.name, args.server, existing.names(), run)
            zone.extra = existing.extra
            args.out.write_text(zone_to_json(zone))
            print(f"captured {len(zone.rrsets)} rrsets across {len(zone.names())} names from {args.server}")
            return 0
        report = compare(existing, args.left, args.right, run, args.check_ttl)
    except QueryError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2

    for failure in report.control_failures:
        print(f"CONTROL FAILED {failure}", file=sys.stderr)
    for diff in report.diffs:
        print(f"DIFF {diff}")
    if report.control_failures:
        return 3
    if report.diffs:
        print(f"{len(report.diffs)} difference(s)")
        return 1
    servers = len(args.left) + len(args.right)
    print(
        f"no differences: {len(existing.rrsets)} rrsets, {len(existing.names())} names, "
        f"{len(PROBE_TYPES)} types, {servers} servers; both controls caught"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
