#!/usr/bin/env python3
"""Checks the DKIM-Signature headers of one sent message from a PublicPress
sender: exactly one signature, made with the sender's own domain
(d=publicpress.co.uk). Reads a raw message from a file (or stdin with -),
prints PASS or FAIL, exits 0 or 1. Makes no network connection and never
prints a signature value: only the d= tag and the count.
Why the signing domain is set where it is: RUNBOOK-mx1-provision.md, "DKIM records to publish".
"""

from __future__ import annotations

import email
import sys
from email import policy

PUBLICPRESS_DOMAIN = "publicpress.co.uk"


def parse_tags(value: str) -> dict[str, str]:
    """A DKIM-Signature value as its tag=value pairs. Folding whitespace is
    stripped, so a header folded across lines reads the same as one line."""
    tags: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            key, tag_value = part.split("=", 1)
            tags[key.strip()] = tag_value.strip()
    return tags


def dkim_signatures(raw: bytes) -> list[dict[str, str]]:
    message = email.message_from_bytes(raw, policy=policy.default)
    return [parse_tags(str(value)) for value in message.get_all("DKIM-Signature", [])]


def verdict(raw: bytes, sender_domain: str) -> tuple[bool, str]:
    """PASS only for exactly one DKIM-Signature whose d= is the sender's domain.
    Any second signature, including one for another domain, fails."""
    signatures = dkim_signatures(raw)
    if len(signatures) != 1:
        return False, f"FAIL: {len(signatures)} DKIM-Signature headers, expected 1"
    signing_domain = signatures[0].get("d", "")
    if signing_domain != sender_domain:
        return (
            False,
            f"FAIL: signed with d={signing_domain}, expected d={sender_domain}",
        )
    return True, f"PASS: one DKIM-Signature, d={sender_domain}"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(
            "usage: check_dkim_signature_scope.py <message-file | ->", file=sys.stderr
        )
        return 2
    if args[0] == "-":
        raw = sys.stdin.buffer.read()
    else:
        with open(args[0], "rb") as handle:
            raw = handle.read()
    ok, line = verdict(raw, PUBLICPRESS_DOMAIN)
    print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
