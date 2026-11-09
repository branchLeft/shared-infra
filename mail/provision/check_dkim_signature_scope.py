#!/usr/bin/env python3
"""Checks the DKIM-Signature headers of one sent message from a PublicPress
sender: exactly one signature, made with the sender's own domain
(d=publicpress.co.uk). Reads a raw message from a file (or stdin with -),
prints PASS or FAIL, exits 0 or 1. Makes no network connection and never
prints a signature value: only the d= tag, tag names and counts.
Why the signing domain is set where it is: RUNBOOK-mx1-provision.md, "DKIM records to publish".
"""

from __future__ import annotations

import re
import sys

PUBLICPRESS_DOMAIN = "publicpress.co.uk"

# An RFC 5322 field name: printable ASCII other than colon, with no space
# before the colon. A line that does not start with one is not a header.
_FIELD_NAME = re.compile(r"^([!-9;-~]+):")


def tag_pairs(value: str) -> list[tuple[str, str]]:
    """A DKIM-Signature value as (tag, value) pairs in order, duplicates kept.
    Folding whitespace is stripped, so a header folded across lines reads the
    same as one line."""
    pairs: list[tuple[str, str]] = []
    for part in value.split(";"):
        if "=" in part:
            key, tag_value = part.split("=", 1)
            pairs.append((key.strip(), tag_value.strip()))
    return pairs


def parse_tags(value: str) -> dict[str, str]:
    """The tags as a dict. Use tag_pairs to see duplicates."""
    return dict(tag_pairs(value))


def header_fields(raw: bytes) -> tuple[list[tuple[str, str]], str | None]:
    """The header fields as (lower-cased name, unfolded value), read up to the
    first blank line. Returns a problem line when a header line is malformed,
    rather than ending the header block early and dropping what follows."""
    fields: list[tuple[str, str]] = []
    text = raw.decode("latin-1").replace("\r\n", "\n")
    for number, line in enumerate(text.split("\n"), start=1):
        if line == "":
            break
        if line[0] in " \t":
            if not fields:
                return fields, f"line {number}: a folded line with no header before it"
            name, value = fields[-1]
            fields[-1] = (name, f"{value} {line.strip()}")
            continue
        match = _FIELD_NAME.match(line)
        if match is None:
            return (
                fields,
                f"line {number}: not a header line (no field name before a colon)",
            )
        fields.append((match.group(1).lower(), line[match.end() :].strip()))
    return fields, None


def dkim_signatures(raw: bytes) -> tuple[list[list[tuple[str, str]]], str | None]:
    """Each DKIM-Signature as its tag pairs, and a problem line if a header is malformed."""
    fields, problem = header_fields(raw)
    signatures = [
        tag_pairs(value) for name, value in fields if name == "dkim-signature"
    ]
    return signatures, problem


def verdict(raw: bytes, sender_domain: str) -> tuple[bool, str]:
    """PASS only for exactly one DKIM-Signature whose d= is the sender's domain,
    with no duplicate tag in it and no malformed header line in the message."""
    signatures, problem = dkim_signatures(raw)
    if problem is not None:
        return False, f"FAIL: {problem}"
    if len(signatures) != 1:
        return False, f"FAIL: {len(signatures)} DKIM-Signature headers, expected 1"
    pairs = signatures[0]
    names = [name for name, _ in pairs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        return False, f"FAIL: duplicate tag {duplicates[0]}= in the DKIM-Signature"
    signing_domain = dict(pairs).get("d", "")
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
