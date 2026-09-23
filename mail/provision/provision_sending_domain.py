#!/usr/bin/env python3
"""Reconciles a sending domain on Stalwart: the domain object and its one
DKIM signing key, then prints the DNS records that key needs published.

    python3 provision_sending_domain.py <domain> [--selector bl] [--dkim-only] [--json]

The same call serves the demo sending domain and a tenant's domain -- only
the name differs. `--dkim-only` is for a domain whose MX and SPF belong to
someone else (a tenant's), so only the DKIM record is ours to publish.

**It never touches a key that already exists.** A domain that already has
the selector's key is a no-op; a domain with any *other* key, or one whose
keys Stalwart manages itself, is refused before any write -- adding a key
there would make Stalwart sign production mail under a selector nobody has
published. See "Sending domains" in mail/RUNBOOK-mx1-provision.md.

**The key is fixed, not rotated.** A created domain gets
`dkimManagement: Manual`. Stalwart's default is `Automatic`, which carries
a rotation schedule and date-stamped selectors; its rotation needs
Stalwart-managed DNS, which this estate does not use, and a key rotated
under a hand-published record fails DKIM for every message after it. Manual
means Stalwart never generates, retires or deletes a key on this domain on
its own.

Stalwart will not generate a key for a Manual domain, so this script does:
`openssl genpkey` on the mail host itself, piped straight into the loopback
API call. The private key is never written to disk, printed or logged, and
never leaves the host. Stalwart redacts it on every read.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)
MAIL_HOST = os.environ.get("STALWART_HOSTNAME", "mx1.branchleft.co.uk")

DEFAULT_SELECTOR = "bl"

# RSA, not Ed25519: a single key has to verify at every major receiver, and
# RSA-SHA256 is the only algorithm they all verify. 2048 bits is the size
# receivers expect and still fits a DNS provider's TXT field.
KEY_TYPE = "Dkim1RsaSha256"
RSA_BITS = 2048

DKIM_KEY_TAGS = {"Dkim1RsaSha256": "rsa", "Dkim1Ed25519Sha256": "ed25519"}

# p=none: the domain is new and warming, and aggregate reports need a
# receiving mailbox this domain does not have. Alignment is strict because
# every message from it is signed by us.
DMARC_VALUE = "v=DMARC1; p=none; adkim=s; aspf=s"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_SELECTOR_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


class Refused(Exception):
    """Live state this script will not change. Nothing has been written."""


@dataclass(frozen=True)
class Plan:
    create_domain: bool
    create_key: bool
    domain_id: str | None

    @property
    def is_noop(self) -> bool:
        return not (self.create_domain or self.create_key)


def validate_domain(name: str) -> str:
    if name != name.lower() or not _DOMAIN_RE.match(name) or len(name) > 253:
        raise Refused(f"{name!r} is not a lowercase fully-qualified domain name")
    return name


def validate_selector(selector: str) -> str:
    if not _SELECTOR_RE.match(selector):
        raise Refused(f"{selector!r} is not a valid DKIM selector")
    return selector


def plan_sending_domain(
    name: str,
    selector: str,
    domains: list[dict[str, Any]],
    signatures: list[dict[str, Any]],
) -> Plan:
    """Pure: what has to be created so `name` exists with an active key
    under `selector`. Raises Refused for any live state that would need an
    existing key or domain changed -- this planner only ever creates.
    """
    domain = next((d for d in domains if d.get("name") == name), None)
    if domain is None:
        return Plan(create_domain=True, create_key=True, domain_id=None)

    domain_id = domain["id"]
    keys = [s for s in signatures if s.get("domainId") == domain_id]
    ours = [s for s in keys if s.get("selector") == selector]
    others = sorted(s.get("selector", "?") for s in keys if s.get("selector") != selector)

    if ours:
        stage = ours[0].get("stage")
        if stage != "active":
            raise Refused(
                f"{name} has a {selector!r} key in stage {stage!r}; it will not sign, "
                "and this script does not modify existing keys"
            )
        return Plan(create_domain=False, create_key=False, domain_id=domain_id)

    if others:
        raise Refused(
            f"{name} already has DKIM keys under other selectors ({', '.join(others)}); "
            f"adding {selector!r} would sign its mail under an unpublished selector"
        )

    management = (domain.get("dkimManagement") or {}).get("@type")
    if management != "Manual":
        raise Refused(
            f"{name} has dkimManagement {management!r}; Stalwart may generate and rotate "
            "keys there itself, so this script will not add one"
        )

    # Only reachable after a run that created the domain and then failed
    # before its key: finish that run's work.
    return Plan(create_domain=False, create_key=True, domain_id=domain_id)


def build_set_calls(name: str, selector: str, plan: Plan, private_key_pem: str) -> list[list[Any]]:
    """The JMAP method calls that carry out `plan`. A new domain and its key
    go in one request, the key naming the domain by creation id."""
    calls: list[list[Any]] = []
    domain_ref = plan.domain_id
    if plan.create_domain:
        calls.append(
            [
                "x:Domain/set",
                {"create": {"domain": {"name": name, "dkimManagement": {"@type": "Manual"}}}},
                "domain",
            ]
        )
        domain_ref = "#domain"
    if plan.create_key:
        calls.append(
            [
                "x:DkimSignature/set",
                {
                    "create": {
                        "key": {
                            "@type": KEY_TYPE,
                            "domainId": domain_ref,
                            "selector": selector,
                            "privateKey": {"@type": "Text", "secret": private_key_pem},
                        }
                    }
                },
                "key",
            ]
        )
    return calls


def _txt_strings(value: str) -> str:
    """A TXT value as zone-file strings, split at DNS's 255-byte limit."""
    chunks = [value[i : i + 255] for i in range(0, len(value), 255)] or [""]
    return " ".join(f'"{chunk}"' for chunk in chunks)


def dns_records(
    name: str, selector: str, key: dict[str, Any], mail_host: str, dkim_only: bool
) -> list[dict[str, str]]:
    tag = DKIM_KEY_TAGS.get(key.get("@type", ""))
    if tag is None:
        raise Refused(f"unrecognised DKIM key type {key.get('@type')!r}")
    public_key = key.get("publicKey")
    if not public_key:
        raise Refused(f"{name}'s {selector!r} key has no public key to publish")

    records = [
        {
            "name": f"{selector}._domainkey.{name}",
            "type": "TXT",
            "value": f"v=DKIM1; k={tag}; h=sha256; p={public_key}",
        }
    ]
    if not dkim_only:
        records += [
            {"name": name, "type": "MX", "value": f"10 {mail_host}."},
            {"name": name, "type": "TXT", "value": "v=spf1 mx -all"},
            {"name": f"_dmarc.{name}", "type": "TXT", "value": DMARC_VALUE},
        ]
    return records


def format_zone(records: list[dict[str, str]]) -> str:
    lines = []
    for record in records:
        value = _txt_strings(record["value"]) if record["type"] == "TXT" else record["value"]
        lines.append(f"{record['name']}. 3600 IN {record['type']} {value}")
    return "\n".join(lines)


def find_key(
    name: str, selector: str, domains: list[dict[str, Any]], signatures: list[dict[str, Any]]
) -> dict[str, Any]:
    domain = next((d for d in domains if d.get("name") == name), None)
    if domain is None:
        raise RuntimeError(f"read-back: {name} does not exist after the write")
    for key in signatures:
        if key.get("domainId") == domain["id"] and key.get("selector") == selector:
            if key.get("stage") != "active":
                raise RuntimeError(f"read-back: {name}'s {selector!r} key is {key.get('stage')!r}, not active")
            return key
    raise RuntimeError(f"read-back: {name} has no {selector!r} key after the write")


def generate_private_key() -> str:
    result = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{RSA_BITS}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    pem = result.stdout
    if "-----BEGIN PRIVATE KEY-----" not in pem:
        raise RuntimeError("openssl genpkey returned no PKCS#8 private key")
    return pem


def _load_credentials() -> tuple[str, str]:
    with open(CREDENTIALS_PATH, encoding="utf-8") as f:
        username, secret = f.read().strip().split(":", 1)
    return username, secret


def _jmap(auth: tuple[str, str], calls: list[list[Any]]) -> list[list[Any]]:
    body = json.dumps({"using": ["urn:ietf:params:jmap:core"], "methodCalls": calls}).encode()
    req = urllib.request.Request(f"{BASE_URL}/jmap", data=body, method="POST")
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        responses = json.loads(resp.read())["methodResponses"]
    for method, result, _ in responses:
        if method == "error":
            raise RuntimeError(f"JMAP call failed: {result}")
        # A /set call succeeds while rejecting individual objects; without
        # this a refused create reads as success.
        for rejection in ("notCreated", "notUpdated", "notDestroyed"):
            if result.get(rejection):
                raise RuntimeError(f"{method} rejected objects ({rejection}): {result[rejection]}")
    return responses


def _read_state(auth: tuple[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    responses = _jmap(
        auth,
        [["x:Domain/get", {}, "domains"], ["x:DkimSignature/get", {}, "keys"]],
    )
    return responses[0][1]["list"], responses[1][1]["list"]


def reconcile(name: str, selector: str, dkim_only: bool) -> tuple[Plan, list[dict[str, str]]]:
    auth = _load_credentials()
    domains, signatures = _read_state(auth)
    plan = plan_sending_domain(name, selector, domains, signatures)
    if not plan.is_noop:
        _jmap(auth, build_set_calls(name, selector, plan, generate_private_key()))
        domains, signatures = _read_state(auth)
    key = find_key(name, selector, domains, signatures)
    return plan, dns_records(name, selector, key, MAIL_HOST, dkim_only)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("domain")
    parser.add_argument("--selector", default=DEFAULT_SELECTOR)
    parser.add_argument("--dkim-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        name = validate_domain(args.domain)
        selector = validate_selector(args.selector)
        plan, records = reconcile(name, selector, args.dkim_only)
    except Refused as exc:
        print(f"provision_sending_domain: refused, nothing written: {exc}", file=sys.stderr)
        return 2
    except urllib.error.URLError as exc:
        print(f"provision_sending_domain: could not reach the Stalwart API at {BASE_URL}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"domain": name, "selector": selector, "changed": not plan.is_noop, "records": records}, indent=2))
    else:
        if plan.create_domain:
            verb = "created the domain and its DKIM key"
        elif plan.create_key:
            verb = "domain present, created its DKIM key"
        else:
            verb = "already present, no-op"
        print(f"provision_sending_domain: {name} (selector {selector}): {verb}")
        print("provision_sending_domain: records to publish:")
        print(format_zone(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
