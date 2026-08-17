#!/usr/bin/env python3
"""Normalize a `gcloud compute security-policies export` capture for commit.

Usage:
    normalize-cloud-armor-baseline.py <raw-export.json> <normalized-out.json>
    normalize-cloud-armor-baseline.py --self-test

Takes the JSON produced by:
    gcloud compute security-policies export branchleft-edge-armor \
        --project=branchleft-prod --global \
        --file-name=<raw-export.json> --file-format=json

and writes a deterministic, diffable form. **Exit 0 means the output file is
byte-identical to what a fresh capture on an unchanged policy would produce
and to what this repo's own `prettier` would write** -- either claim being
false is treated as a failure, not a warning, because the artifact's entire
purpose is that its diff is trustworthy (see `_format_with_prettier`):

* Drops fields GCP assigns and rewrites on every read regardless of policy
  content (`id`, `fingerprint`, `creationTimestamp`, `selfLink`, `kind`,
  `labelFingerprint`) -- keeping them would make every re-capture show a diff
  with no semantic change behind it.
* Sorts `rules` by `priority` -- the export order is not guaranteed to be
  priority order, and this repo's own incident history
  (RUNBOOK-edge-state-move.md appendix A) is a case where priority-indexed
  identity is what matters, not array position.
* Serializes with sorted object keys and a trailing newline, then runs the
  repo's own prettier over the result. If prettier can't run, this script
  exits non-zero rather than silently writing a file whose only difference
  from the committed baseline is formatting -- a difference indistinguishable
  from real drift at the one moment (a wind-down parity check on a fresh
  clone) this artifact is least likely to have `node_modules` installed.

Also refuses to write anything (exit non-zero) if **any string field of any
rule, at any depth** -- not a fixed list of "the fields an IP usually lives
in" -- contains an IP or CIDR literal other than the wildcard `*`. Cloud
Armor rules can name a specific address three ways this script has to treat
as equally likely: a `config.srcIpRanges` list entry, an IP/CIDR literal
inside a `match.expr.expression` CEL string (`inIpRange(origin.ip, '...')`),
or free text in a hand-written `description` -- exactly where an operator
adding a one-off allowlist rule is most likely to note who or what it is
for. Detection works by finding IP/CIDR-shaped substrings anywhere in a
string and validating each with `ipaddress.ip_network`, so it is not tied to
a specific address notation: IPv4, compressed or IPv4-mapped IPv6, and CIDR
forms of any of those all match, because the underlying risk (a person or
tenant identified by address) is the same regardless of how the address is
written. Any of those found makes this repo's engineer-as-if-public bar the
reason to stop, not the mechanism. `--redact-ips` replaces the offending
substrings with a placeholder; without the flag the script exits non-zero
and writes nothing. The refusal message never echoes the address itself --
only where it was found and how many -- the one path meant to keep an
identifying address out of the committed file should not put it in CI logs
and pre-commit output instead.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

_VOLATILE_POLICY_FIELDS = {
    "id",
    "fingerprint",
    "creationTimestamp",
    "selfLink",
    "kind",
    "labelFingerprint",
}

_VOLATILE_RULE_FIELDS = {"kind"}

_REDACTED = "REDACTED-see-CLOUD-ARMOR-BASELINE.md"

# A run of hex/dot/colon characters, optionally followed by a CIDR suffix.
# Deliberately wide -- not an attempt to describe "what an IP looks like" --
# because the real filter is downstream: every candidate is handed to
# ipaddress.ip_network, which is the actual authority on what is and is not
# a valid IPv4/IPv6 address or network, in any notation (compressed,
# IPv4-mapped, CIDR). Matching first and validating second means a new
# address shape this script's author didn't think of is still caught, as
# long as Python's own stdlib parser accepts it.
_IP_CANDIDATE_PATTERN = re.compile(r"[0-9a-fA-F:.]{2,}(?:/\d{1,3})?")


def _is_ip_literal(candidate: str) -> bool:
    # A bare "." or ":" run with no digits (or nothing at all) isn't a
    # candidate worth asking ipaddress about.
    if "." not in candidate and ":" not in candidate:
        return False
    try:
        ipaddress.ip_network(candidate, strict=False)
        return True
    except ValueError:
        return False


def _find_ip_literals(text: str) -> list[str]:
    """Every IP/CIDR substring embedded anywhere in free text."""
    return [
        match.group(0) for match in _IP_CANDIDATE_PATTERN.finditer(text) if _is_ip_literal(match.group(0))
    ]


def _redact_text(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        return _REDACTED if _is_ip_literal(match.group(0)) else match.group(0)

    return _IP_CANDIDATE_PATTERN.sub(_replace, text)


def _iter_strings(value: object):
    """Yield every string found in a JSON-like structure, at any depth.

    Skips non-string, non-container leaves (None, numbers, bools) rather
    than erroring on them -- a rule field that is present but null (Cloud
    Armor's export can do this) must not crash the scan.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)


def _redact_strings(value: object) -> object:
    """Return a copy of a JSON-like structure with every IP/CIDR-bearing
    string redacted. A no-op (structurally, though it still copies) on a
    structure with nothing to redact."""
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {k: _redact_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_strings(v) for v in value]
    return value


class NonWildcardIpReferences(ValueError):
    """Something in the capture names a specific IP/CIDR, not just '*'.

    Deliberately does not put the address itself in the message -- see the
    module docstring's last paragraph.
    """

    def __init__(self, location: object, count: int):
        self.location = location
        self.count = count
        super().__init__(f"{location} has {count} non-wildcard IP/CIDR reference(s)")


def normalize(raw: dict, *, redact_ips: bool = False) -> dict:
    """Return a deterministic, commit-ready form of a security-policy export.

    Raises NonWildcardIpReferences if any string field (policy-level or
    within a rule, at any depth) names a specific IP/CIDR and redact_ips is
    False. Never mutates `raw`.
    """
    policy = {k: v for k, v in raw.items() if k not in _VOLATILE_POLICY_FIELDS}

    # Policy-level fields (name, description, labels, ...) other than
    # `rules` -- a hand-edited policy description is as capable of naming an
    # address as a rule's is.
    policy_level = {k: v for k, v in policy.items() if k != "rules"}
    policy_level_refs = [ip for s in _iter_strings(policy_level) for ip in _find_ip_literals(s)]
    if policy_level_refs:
        if not redact_ips:
            raise NonWildcardIpReferences("policy-level field (not a rule)", len(policy_level_refs))
        for key in policy_level:
            policy[key] = _redact_strings(policy[key])

    rules = []
    for rule in policy.get("rules", []):
        ip_refs = [ip for s in _iter_strings(rule) for ip in _find_ip_literals(s)]
        if ip_refs:
            if not redact_ips:
                raise NonWildcardIpReferences(f"rule priority={rule.get('priority')}", len(ip_refs))
            rule = _redact_strings(rule)
        cleaned = {k: v for k, v in rule.items() if k not in _VOLATILE_RULE_FIELDS}
        rules.append(cleaned)

    rules.sort(key=lambda r: r.get("priority", 0))
    policy["rules"] = rules
    return policy


def _format_with_prettier(path: Path) -> bool:
    """Run this repo's prettier over `path` in place. Returns True on success.

    The pre-commit `prettier` hook (`.pre-commit-config.yaml`) would reformat
    this file anyway -- collapsing an array like `["*"]` onto one line, among
    other things -- so skipping this step produces a file that differs from
    what actually gets committed. `main()` treats a False return here as a
    hard failure (see its own comment) rather than a warning: the pre-commit
    hook is a safety net for *committing*, but this artifact's purpose is
    being *diffed*, including by someone running these commands on a fresh
    clone with no `node_modules` -- exactly where a silent formatting-only
    diff would be mistaken for live drift.
    """
    repo_root = Path(__file__).resolve().parent.parent
    try:
        subprocess.run(
            ["npx", "--no-install", "prettier", "--write", str(path)],
            check=True,
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"::error::could not run prettier on {path}: {error}")
        return False


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()

    redact_ips = "--redact-ips" in argv
    positional = [a for a in argv[1:] if a != "--redact-ips"]
    if len(positional) != 2:
        print(__doc__)
        return 2

    raw_path, out_path = positional
    try:
        with open(raw_path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        print(f"::error::cannot read raw export: {error}")
        return 1

    try:
        normalized = normalize(raw, redact_ips=redact_ips)
    except NonWildcardIpReferences as error:
        print(
            f"::error::{error}. This may identify a person or tenant rather "
            "than a public range. Review it by hand (the raw export file, "
            "not this message, has the actual value), then either drop it "
            "from the capture or re-run with --redact-ips once you've "
            "confirmed redaction is the right call."
        )
        return 1

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(normalized, handle, indent=2, sort_keys=True)
        handle.write("\n")

    if not _format_with_prettier(Path(out_path)):
        print(
            f"::error::{out_path} was written but NOT formatted with prettier. "
            "It is valid JSON but will NOT match the repo's committed "
            "formatting, and a diff against the committed baseline would show "
            "a spurious formatting change instead of a clean/dirty verdict -- "
            "exactly the false signal this artifact exists to prevent. Make "
            "`npx prettier` available (`npm ci` in the repo root) and re-run "
            "before trusting any diff against this output."
        )
        return 3

    print(f"OK: wrote normalized policy ({len(normalized.get('rules', []))} rules) to {out_path}")
    return 0


def self_test() -> int:
    failed = False

    def check(condition: bool, message: str) -> None:
        nonlocal failed
        if not condition:
            print(f"FAIL: {message}")
            failed = True

    # Volatile fields dropped, rules sorted by priority, key order stable.
    raw = {
        "name": "branchleft-edge-armor",
        "id": "1234567890",
        "fingerprint": "abc123==",
        "creationTimestamp": "2026-08-04T00:00:00Z",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/branchleft-prod/...",
        "kind": "compute#securityPolicy",
        "type": "CLOUD_ARMOR",
        "rules": [
            {"priority": 2000, "action": "throttle", "kind": "compute#securityPolicyRule"},
            {"priority": 1000, "action": "deny(403)", "kind": "compute#securityPolicyRule"},
        ],
    }
    normalized = normalize(raw)
    check(
        "id" not in normalized and "fingerprint" not in normalized and "selfLink" not in normalized,
        "volatile policy fields survived normalization",
    )
    check(
        [r["priority"] for r in normalized["rules"]] == [1000, 2000],
        "rules were not sorted by priority",
    )
    check(
        not any("kind" in r for r in normalized["rules"]),
        "volatile rule field 'kind' survived normalization",
    )

    # Re-normalizing an already-normalized policy is a no-op (idempotent —
    # a re-capture of an unchanged live policy must diff clean).
    check(normalize(normalized) == normalized, "normalize() is not idempotent")

    # A wildcard-only rule passes through untouched.
    wildcard_only = {
        "name": "p",
        "rules": [{"priority": 2000, "match": {"config": {"srcIpRanges": ["*"]}}}],
    }
    result = normalize(wildcard_only)
    check(
        result["rules"][0]["match"]["config"]["srcIpRanges"] == ["*"],
        "wildcard srcIpRanges was altered",
    )

    # A non-wildcard IPv4 range (config.srcIpRanges shape) refuses to
    # normalize without --redact-ips, and the refusal does not embed the
    # address in the exception's own message string.
    ipv4_allowlisted = {
        "name": "p",
        "rules": [
            {"priority": 900, "match": {"config": {"srcIpRanges": ["203.0.113.4/32", "*"]}}}
        ],
    }
    try:
        normalize(ipv4_allowlisted)
        check(False, "non-wildcard IPv4 srcIpRanges did not raise without --redact-ips")
    except NonWildcardIpReferences as error:
        check(
            error.location == "rule priority=900" and error.count == 1,
            f"unexpected IPv4 error detail: {error.location!r}, count={error.count}",
        )
        check("203.0.113.4" not in str(error), "the offending IPv4 address leaked into the exception message")

    before = json.dumps(ipv4_allowlisted)
    redacted = normalize(ipv4_allowlisted, redact_ips=True)
    check(json.dumps(ipv4_allowlisted) == before, "normalize() mutated its input")
    check(
        redacted["rules"][0]["match"]["config"]["srcIpRanges"] == [_REDACTED, "*"],
        f"unexpected redacted IPv4 ranges: {redacted['rules'][0]['match']['config']['srcIpRanges']}",
    )

    # IP/CIDR literals embedded in match.expr.expression (the
    # inIpRange()/== shape a custom Cloud Armor rule uses).
    expr_rule = {
        "name": "p",
        "rules": [
            {
                "priority": 800,
                "match": {
                    "expr": {
                        "expression": (
                            "inIpRange(origin.ip, '203.0.113.4/32') "
                            "|| origin.ip == '198.51.100.7'"
                        )
                    }
                },
            }
        ],
    }
    try:
        normalize(expr_rule)
        check(False, "IPv4 literal in match.expr.expression did not raise without --redact-ips")
    except NonWildcardIpReferences as error:
        check(
            error.location == "rule priority=800" and error.count == 2,
            f"unexpected expr-shape error detail: {error.location!r}, count={error.count}",
        )
    got = normalize(expr_rule, redact_ips=True)["rules"][0]["match"]["expr"]["expression"]
    check(
        "203.0.113.4" not in got and "198.51.100.7" not in got and got.count(_REDACTED) == 2,
        f"IPv4 literal(s) survived expression redaction: {got}",
    )

    # IPv4-mapped IPv6 and bare IPv6 literals -- the shape round one's fix
    # missed entirely (F1): the old pattern's IPv6 branch could not contain
    # a dot, so '::ffff:203.0.113.4' matched neither branch and passed
    # through undetected and unredacted.
    for label, literal, expect_count in (
        ("IPv4-mapped IPv6 address", "::ffff:203.0.113.4", 1),
        ("IPv4-mapped IPv6 CIDR", "::ffff:203.0.113.0/120", 1),
        ("compressed IPv6 address", "2001:db8::1", 1),
        ("IPv6 CIDR", "2001:db8::/32", 1),
    ):
        rule = {
            "name": "p",
            "rules": [
                {"priority": 700, "match": {"expr": {"expression": f"origin.ip == '{literal}'"}}}
            ],
        }
        try:
            normalize(rule)
            check(False, f"{label} ({literal!r}) did not raise without --redact-ips")
        except NonWildcardIpReferences as error:
            check(error.count == expect_count, f"unexpected count for {label}: {error.count}")
        redacted_expr = normalize(rule, redact_ips=True)["rules"][0]["match"]["expr"]["expression"]
        check(literal not in redacted_expr, f"{label} survived redaction: {redacted_expr}")

    # A non-IP string literal in an expression (a hostname, a ruleset name)
    # must not be mistaken for an IP and must not trip the guard.
    host_rule = {
        "name": "p",
        "rules": [
            {
                "priority": 1100,
                "match": {
                    "expr": {"expression": "request.headers['host'].lower() == 'blog.branchleft.co.uk'"}
                },
            }
        ],
    }
    try:
        normalize(host_rule)
    except NonWildcardIpReferences as error:
        check(False, f"a hostname literal was mistaken for an IP: {error}")

    # F2: an IP embedded in free text in a field that is neither
    # config.srcIpRanges nor match.expr.expression -- a hand-written rule
    # `description`, the field an operator is most likely to actually use to
    # note who/what an allowlist entry is for.
    description_rule = {
        "name": "p",
        "rules": [
            {"priority": 600, "description": "allow home IP 198.51.100.42", "action": "allow"}
        ],
    }
    try:
        normalize(description_rule)
        check(False, "an IP embedded in a rule's description did not raise without --redact-ips")
    except NonWildcardIpReferences as error:
        check(error.count == 1, f"unexpected description-field error detail: count={error.count}")
    redacted_description = normalize(description_rule, redact_ips=True)["rules"][0]["description"]
    check("198.51.100.42" not in redacted_description, f"IP survived description redaction: {redacted_description}")

    # Same idea one level up: a policy-level field (not inside `rules` at
    # all) naming an address.
    policy_description_raw = {
        "name": "p",
        "description": "temporary allowlist for 198.51.100.42 while on VPN",
        "rules": [{"priority": 2147483647, "action": "allow"}],
    }
    try:
        normalize(policy_description_raw)
        check(False, "an IP in a policy-level field did not raise without --redact-ips")
    except NonWildcardIpReferences as error:
        check(error.location == "policy-level field (not a rule)", f"unexpected policy-level error location: {error.location!r}")
    redacted_policy = normalize(policy_description_raw, redact_ips=True)
    check("198.51.100.42" not in redacted_policy["description"], "IP survived policy-level description redaction")

    # F7: a null (not missing) expr.expression must not crash the scan --
    # Cloud Armor's export can hold a present-but-null field.
    try:
        normalize({"name": "p", "rules": [{"priority": 500, "match": {"expr": {"expression": None}}}]})
    except Exception as error:  # noqa: BLE001 -- this is exactly the "must not raise at all" assertion
        check(False, f"a null expr.expression crashed normalize(): {error!r}")

    # _format_with_prettier reports failure (never raises) when prettier
    # can't run.
    with mock.patch("subprocess.run", side_effect=FileNotFoundError("no npx")):
        check(
            _format_with_prettier(Path("/tmp/does-not-matter.json")) is False,
            "_format_with_prettier did not report failure when subprocess.run raised",
        )

    # F4: main() must surface a prettier failure as a hard, non-zero exit --
    # not print success and return 0 while leaving an unformatted file that
    # would show a spurious diff against the committed baseline. Round one's
    # fix made the helper report failure; it did not check main() actually
    # acted on that report, which is how F4 shipped.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        raw_path = Path(tmp) / "raw.json"
        out_path = Path(tmp) / "out.json"
        raw_path.write_text(json.dumps({"name": "p", "rules": []}), encoding="utf-8")
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("no npx")):
            exit_code = main(["prog", str(raw_path), str(out_path)])
        check(exit_code != 0, f"main() returned {exit_code} (expected non-zero) when prettier was unavailable")
        check(out_path.exists(), "main() should still write the (unformatted) file before failing loud")

    if failed:
        print("\nnormalize-cloud-armor-baseline.py self-test FAILED")
    else:
        print("OK: normalize-cloud-armor-baseline.py self-test passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
