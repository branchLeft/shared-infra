#!/usr/bin/env python3
"""Lists IPs Stalwart's own built-in scan-ban has blocked, and optionally
clears specific ones -- see mail/RUNBOOK-mx1-provision.md's "Scan-ban"
section for why this fires on nothing more hostile than an operator's own
verification commands, and why a blanket clear is dangerous: a genuinely
malicious scanner blocked alongside an operator's own false-positive would
get released too.

Usage:
    python3 list_and_clear_blocked_ips.py                    # list only
    python3 list_and_clear_blocked_ips.py --list-only         # same, explicit
    python3 list_and_clear_blocked_ips.py --ip 1.2.3.4        # clear one IP
    python3 list_and_clear_blocked_ips.py --ip 1.2.3.4 --ip 5.6.7.8
    python3 list_and_clear_blocked_ips.py --all               # clear every blocked IP
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.request
from typing import Any

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)


def select_ids_to_clear(
    blocked: list[dict[str, Any]], ips: list[str], clear_all: bool
) -> list[str]:
    """Pure selection logic: which blocked-entry ids to destroy, given the
    live blocked list and the caller's --ip/--all choice. Raises ValueError
    if the request is ambiguous or unsafe rather than guessing -- no
    all-clear without `clear_all` explicitly set, and no silent no-op for
    an --ip that isn't actually blocked (that's a caller mistake worth
    surfacing, not swallowing).
    """
    if clear_all and ips:
        raise ValueError("pass --all or --ip, not both")
    if not clear_all and not ips:
        raise ValueError("no selection: pass --ip <addr> (repeatable) or --all")

    if clear_all:
        return [entry["id"] for entry in blocked]

    by_address = {entry["address"]: entry["id"] for entry in blocked}
    missing = [ip for ip in ips if ip not in by_address]
    if missing:
        raise ValueError(f"not currently blocked, nothing to clear: {', '.join(missing)}")
    return [by_address[ip] for ip in ips]


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
        ids = select_ids_to_clear(blocked, args.ip, args.all)
    except ValueError as exc:
        print(f"list_and_clear_blocked_ips: {exc}", file=sys.stderr)
        return 1

    _jmap_call(auth, "x:BlockedIp/set", {"destroy": ids})
    # BlockedIp is enforced from an in-memory cache separate from the
    # registry object -- destroying the object alone leaves the live block
    # in place until this reload runs too.
    _jmap_call(auth, "x:Action/set", {"create": {"a1": {"@type": "ReloadBlockedIps"}}})
    print(f"cleared {len(ids)} blocked IP(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
