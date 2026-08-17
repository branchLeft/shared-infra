#!/usr/bin/env python3
"""Manually triggers an AcmeRenewal task for the mail domain -- not part of
run-all.sh, since Stalwart schedules its own renewals automatically once a
certificate has been issued (see mail/RUNBOOK-mx1-provision.md's "What
remains owner-gated" section). Use this only for testing, or if a
scheduling problem is suspected.

Looks up the domain id live rather than assuming it (registry ids are not
guaranteed stable across a rebuild). Usage:
    python3 trigger_acme_renewal.py
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.request

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
HOSTNAME = os.environ.get("STALWART_HOSTNAME", "mx1.branchleft.co.uk")
CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)


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
    with open(CREDENTIALS_PATH, encoding="utf-8") as f:
        username, secret = f.read().strip().split(":", 1)
    auth = (username, secret)

    domains = _jmap_call(auth, "x:Domain/get", {})["list"]
    mail_zone = HOSTNAME.split(".", 1)[1] if "." in HOSTNAME else HOSTNAME
    matches = [d for d in domains if d["name"] == mail_zone]
    if not matches:
        print(f"trigger_acme_renewal: no domain named {mail_zone!r} found", file=sys.stderr)
        return 1
    domain_id = matches[0]["id"]

    result = _jmap_call(
        auth, "x:Task/set", {"create": {"t1": {"@type": "AcmeRenewal", "domainId": domain_id}}}
    )
    if "t1" in result.get("created", {}):
        print(f"trigger_acme_renewal: created AcmeRenewal task for domain {mail_zone!r} ({domain_id})")
        print("watch progress with: docker logs -f stalwart")
        return 0

    print(f"trigger_acme_renewal: not created: {result.get('notCreated')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
