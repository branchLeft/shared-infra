#!/usr/bin/env python3
"""Lists IPs that Stalwart's built-in scan-ban has blocked, and clears them on request; reasoning is in list_and_clear_blocked_ips.md.
Usage:
    python3 list_and_clear_blocked_ips.py                    # list only
    python3 list_and_clear_blocked_ips.py --list-only         # same, explicit
    python3 list_and_clear_blocked_ips.py --ip 1.2.3.4        # clear one IP
    python3 list_and_clear_blocked_ips.py --ip 1.2.3.4 --ip 5.6.7.8
    python3 list_and_clear_blocked_ips.py --reason portScanning   # clear every entry with that reason
    python3 list_and_clear_blocked_ips.py --reason portScanning --ip 1.2.3.4   # union of both selectors
    python3 list_and_clear_blocked_ips.py --all               # clear every blocked IP
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from typing import Any

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)


def select_ids_to_clear(
    blocked: list[dict[str, Any]], ips: list[str], reasons: list[str], clear_all: bool
) -> list[str]:
    """Pure selection logic: which blocked-entry ids to destroy, given the
    live blocked list and the caller's --ip/--reason/--all choice. Raises
    ValueError if the request is ambiguous or unsafe rather than guessing --
    no all-clear without `clear_all` explicitly set, no silent no-op for an
    --ip that isn't actually blocked, and no silent no-op when a selection
    matches nothing overall (a caller mistake -- e.g. a typo'd reason --
    worth surfacing, not swallowing). --ip and --reason are a union: both
    selectors may be used together, each contributing whatever it matches.
    """
    if clear_all and (ips or reasons):
        raise ValueError("pass --all or --ip/--reason, not both")
    if not clear_all and not ips and not reasons:
        raise ValueError(
            "no selection: pass --ip <addr>, --reason <reason> (either repeatable), or --all"
        )

    if clear_all:
        return [entry["id"] for entry in blocked]

    by_address = {entry["address"]: entry["id"] for entry in blocked}
    selected: set[str] = set()

    if ips:
        missing = [ip for ip in ips if ip not in by_address]
        if missing:
            raise ValueError(f"not currently blocked, nothing to clear: {', '.join(missing)}")
        selected.update(by_address[ip] for ip in ips)

    if reasons:
        # Checked independently of `ips` -- a matching --ip must never mask
        # a --reason that matches nothing (or vice versa).
        by_reason = {entry["id"] for entry in blocked if entry["reason"] in reasons}
        if not by_reason:
            raise ValueError(f"no blocked entries match reason(s): {', '.join(reasons)}")
        selected.update(by_reason)

    return list(selected)


def _jmap_call(auth: tuple[str, str], method: str, args: dict) -> dict:
    body = json.dumps(
        {"using": ["urn:ietf:params:jmap:core"], "methodCalls": [[method, args, "0"]]}
    ).encode()
    req = urllib.request.Request(f"{BASE_URL}/jmap", data=body, method="POST")
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        response = json.loads(resp.read())
    name, result, _ = response["methodResponses"][0]
    if name == "error":
        raise RuntimeError(f"{method} failed: {result}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-only", action="store_true", help="list, clear nothing")
    parser.add_argument(
        "--ip", action="append", default=[], metavar="ADDR", help="clear this IP (repeatable)"
    )
    parser.add_argument(
        "--reason",
        action="append",
        default=[],
        metavar="REASON",
        help="clear every blocked entry with this reason (repeatable)",
    )
    parser.add_argument("--all", action="store_true", help="clear every blocked IP")
    args = parser.parse_args()

    with open(CREDENTIALS_PATH, encoding="utf-8") as f:
        username, secret = f.read().strip().split(":", 1)
    auth = (username, secret)

    blocked = _jmap_call(auth, "x:BlockedIp/get", {})["list"]
    if not blocked:
        print("no blocked IPs")
        return 0

    for entry in blocked:
        print(f"{entry['address']}\treason={entry['reason']}\tsince={entry['createdAt']}")

    if args.list_only:
        return 0

    try:
        ids = select_ids_to_clear(blocked, args.ip, args.reason, args.all)
    except ValueError as exc:
        print(f"list_and_clear_blocked_ips: {exc}", file=sys.stderr)
        return 1

    _jmap_call(auth, "x:BlockedIp/set", {"destroy": ids})
    # BlockedIp is enforced from an in-memory cache separate from the
    # registry object -- destroying the object alone leaves the live block
    # in place until this reload runs too.
    try:
        _jmap_call(auth, "x:Action/set", {"create": {"a1": {"@type": "ReloadBlockedIps"}}})
    except (OSError, http.client.HTTPException) as exc:
        message = (
            f"list_and_clear_blocked_ips: {describe_cause(exc)} while reloading the block list; "
            "the selected entries were already deleted from the registry but the live block list "
            "was not reloaded, so those IPs may still be blocked, and running --ip again will "
            "report them as not blocked; check the server before relying on the clear"
        )
        print(" ".join(message.split()), file=sys.stderr)
        return 1
    print(f"cleared {len(ids)} blocked IP(s)")
    return 0


# The failures that mean the server gave no answer. HTTPError is a URLError
# too, so describe_failure checks for it first; IncompleteRead is not an
# OSError, hence HTTPException by name.
NO_ANSWER_ERRORS = (
    urllib.error.URLError,
    ConnectionError,
    TimeoutError,
    socket.timeout,
    socket.gaierror,
    http.client.HTTPException,
)


def describe_cause(exc: Exception) -> str:
    """The exception class and message of a failed API call; a URLError is
    described by the failure it wraps. Never includes the request headers or
    the response body.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return f"{type(exc).__name__}: HTTP {exc.code} {exc.reason}"
    cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    cause_class = type(cause) if isinstance(cause, BaseException) else type(exc)
    return f"{cause_class.__name__}: {cause}"


def describe_failure(exc: Exception) -> str:
    """One line for a failure of main(), by what it says about the server:
    an HTTP error status (it answered), no answer at all (a restart is the
    likely cause), or anything else an OSError can be (a local file or
    binary, never blamed on the server).
    """
    if isinstance(exc, urllib.error.HTTPError):
        line = (
            f"list_and_clear_blocked_ips: the Stalwart API at {BASE_URL} answered HTTP {exc.code} "
            f"{exc.reason}; the server is up, so check the request and the credential"
        )
    elif isinstance(exc, NO_ANSWER_ERRORS):
        line = (
            f"list_and_clear_blocked_ips: no answer from the Stalwart API at {BASE_URL}: "
            f"{describe_cause(exc)}; the container may still be restarting; "
            "wait a few seconds and run it again"
        )
    else:
        line = f"list_and_clear_blocked_ips: {type(exc).__name__}: {exc}"
    return " ".join(line.split())


def run() -> int:
    """Runs main(). Returns 1 after printing one stderr line for an HTTP
    error status, a missing answer from the server or any other OSError;
    every other exception propagates unchanged.
    """
    try:
        return main()
    except (OSError, http.client.HTTPException) as exc:
        print(describe_failure(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run())
