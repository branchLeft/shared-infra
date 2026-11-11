#!/usr/bin/python3 -I
"""Reports the sending state on Stalwart. Read-only: sends only `/get` methods.

    python3 -I - < read_sending_state.py      (on mx1, as root; takes no arguments)

Prints sorted `domain`, `dkim`, `mailbox` lines, then the postmaster, abuse
and complaints role-address summaries. Never prints a credential, a private
key, a public key or any other field. See read_sending_state.md.
"""

from __future__ import annotations

import base64
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any

BASE_URL = "http://127.0.0.1:8080"
CREDENTIALS_PATH = "/root/.stalwart-admin-credentials"
MAIL_DOMAIN = "branchleft.co.uk"

# Every method this script sends. Each name must end in "/get"; assert_read_only
# refuses anything else before a byte is sent.
READ_CALLS: list[list[Any]] = [
    ["x:Domain/get", {"properties": ["id", "name"]}, "domains"],
    [
        "x:DkimSignature/get",
        {"properties": ["id", "domainId", "selector", "stage"]},
        "keys",
    ],
    ["x:Account/get", {"properties": ["name", "domainId"]}, "accounts"],
]

_SAFE_ERROR_TYPE = re.compile(r"[A-Za-z0-9_:./-]{1,60}")


class ReadError(Exception):
    """A failure whose message is safe to print: it names no credential and no response body."""


def _load_credentials() -> tuple[str, str]:
    try:
        with open(CREDENTIALS_PATH, encoding="utf-8") as f:
            raw = f.read().strip()
    except OSError:
        raise ReadError("the admin credential file is missing or unreadable") from None
    if ":" not in raw:
        raise ReadError("the admin credential file is malformed")
    username, secret = raw.split(":", 1)
    return username, secret


def assert_read_only(calls: list[list[Any]]) -> None:
    for call in calls:
        method = call[0]
        if not isinstance(method, str) or not method.endswith("/get"):
            raise ReadError("refusing to send a method that is not a read")


def _build_opener() -> urllib.request.OpenerDirector:
    # An empty ProxyHandler: http_proxy and HTTP_PROXY in the environment are
    # ignored, so the loopback call never leaves the host by a proxy.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _jmap(auth: tuple[str, str], calls: list[list[Any]]) -> list[list[Any]]:
    assert_read_only(calls)
    body = json.dumps(
        {"using": ["urn:ietf:params:jmap:core"], "methodCalls": calls}
    ).encode()
    req = urllib.request.Request(f"{BASE_URL}/jmap", data=body, method="POST")
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    with _build_opener().open(req, timeout=30) as resp:
        payload = json.loads(resp.read())
    return payload["methodResponses"]


def _results(responses: list[list[Any]]) -> dict[str, dict[str, Any]]:
    expected = {call[2]: call[0] for call in READ_CALLS}
    results: dict[str, dict[str, Any]] = {}
    for method, result, call_id in responses:
        if method == "error":
            kind = result.get("type") if isinstance(result, dict) else None
            safe = (
                kind
                if isinstance(kind, str) and _SAFE_ERROR_TYPE.fullmatch(kind)
                else "unknown"
            )
            raise ReadError(f"the Stalwart API refused the read ({safe})")
        if expected.get(call_id) != method or not isinstance(result, dict):
            raise ReadError("the Stalwart API answered with an unexpected shape")
        results[call_id] = result
    if set(results) != set(expected):
        raise ReadError("the Stalwart API did not answer every read")
    return results


def _items(result: dict[str, Any]) -> list[dict[str, Any]]:
    items = result.get("list")
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise ReadError("the Stalwart API answered with an unexpected shape")
    return items


def _text(value: Any) -> str:
    return value if isinstance(value, str) else "?"


def _domain_name(domain_id: Any, name_by_id: dict[str, str]) -> str:
    name = name_by_id.get(domain_id) if isinstance(domain_id, str) else None
    if name is None:
        raise ReadError("an account or DKIM key names a domain that was not read")
    return name


def build_lines(results: dict[str, dict[str, Any]]) -> list[str]:
    """Pure: the output lines for the three reads, sorted, then the role summaries."""
    domains = _items(results["domains"])
    keys = _items(results["keys"])
    accounts = _items(results["accounts"])

    name_by_id = {_text(d.get("id")): _text(d.get("name")) for d in domains}
    body = [f"domain {name}" for name in name_by_id.values()]
    body += [
        f"dkim {_domain_name(k.get('domainId'), name_by_id)} {_text(k.get('selector'))} {_text(k.get('stage'))}"
        for k in keys
    ]
    # An account with no domain, or one naming a domain that was not read, is
    # skipped and counted rather than failing the whole report.
    mailboxes: set[str] = set()
    unmatched = 0
    for account in accounts:
        domain_id = account.get("domainId")
        if not isinstance(domain_id, str) or domain_id not in name_by_id:
            unmatched += 1
            continue
        mailboxes.add(f"{_text(account.get('name'))}@{name_by_id[domain_id]}")
    body += [f"mailbox {address}" for address in mailboxes]

    def role(local: str) -> str:
        return (
            "present as mailbox" if f"{local}@{MAIL_DOMAIN}" in mailboxes else "absent"
        )

    return sorted(body) + [
        f"accounts without a matching domain: {unmatched}",
        f"postmaster: {role('postmaster')}",
        f"abuse: {role('abuse')}",
        f"complaints: {role('complaints')}",
        "aliases: not read (only mailbox accounts were read, so postmaster absent means no mailbox, not no alias)",
    ]


def main() -> int:
    try:
        auth = _load_credentials()
        results = _results(_jmap(auth, READ_CALLS))
        lines = build_lines(results)
    except ReadError as exc:
        print(f"read_sending_state: {exc}", file=sys.stderr)
        return 1
    except urllib.error.HTTPError as exc:
        print(
            f"read_sending_state: the Stalwart API answered HTTP {exc.code}",
            file=sys.stderr,
        )
        return 1
    except urllib.error.URLError:
        print(
            "read_sending_state: could not reach the Stalwart API on loopback",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # noqa: BLE001 - a traceback could carry the URL or a response body
        print(
            f"read_sending_state: unexpected {type(exc).__name__}, nothing printed",
            file=sys.stderr,
        )
        return 1
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
