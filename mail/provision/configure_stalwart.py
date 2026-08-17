#!/usr/bin/env python3
"""Reconciles Stalwart's own settings (network listeners, the mail domain's
ACME SAN list, log output) to the state this platform needs, using
Stalwart's JMAP-style management API -- see
mail/RUNBOOK-mx1-provision.md#stalwart-config-as-code for why this script,
not a TOML file, is the config-as-code artifact for this version of
Stalwart.

Idempotent: every change is computed as a diff against live state, so a
second run with nothing left to do makes zero API calls beyond the GETs
used to compute that. Uses only the standard library (no `requests`, no
`jq` -- neither is assumed present on the host) so it runs anywhere
python3 does.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
HOSTNAME = os.environ.get("STALWART_HOSTNAME", "mx1.branchleft.co.uk")
CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)

# Every listener this platform cares about, checked field-by-field on
# every run. Per-listener reasoning: mail/RUNBOOK-mx1-provision.md's "What
# it reconciles, and why".
MANAGED_LISTENERS: dict[str, dict[str, Any]] = {
    "smtp": {"bind": {"[::]:25": True}, "protocol": "smtp", "useTls": True, "tlsImplicit": False},
    "submissions": {
        "bind": {"[::]:465": True},
        "protocol": "smtp",
        "useTls": True,
        "tlsImplicit": True,
    },
    "imaps": {"bind": {"[::]:993": True}, "protocol": "imap", "useTls": True, "tlsImplicit": True},
    "https": {"bind": {"[::]:443": True}, "protocol": "http", "useTls": True, "tlsImplicit": True},
    "http": {"bind": {"[::]:8080": True}, "protocol": "http", "useTls": True, "tlsImplicit": False},
    "submission": {
        "bind": {"[::]:587": True},
        "protocol": "smtp",
        "useTls": True,
        "tlsImplicit": False,
    },
}

# Only recreated if missing entirely -- the others are assumed to always
# exist (Stalwart's own wizard creates them); if an operator has
# deliberately removed one of those, this script edits it back into shape
# once it reappears but does not resurrect it from nothing.
CREATE_IF_MISSING = {"submission"}

# Out of this story's scope entirely (no mailboxes exist yet, and neither
# port is in mail/firewall.ts's rule set) -- removed if bootstrap created
# them, so the running server's surface matches what's actually reachable.
REMOVED_LISTENER_NAMES = ("pop3s", "sieve")

TRACER_TARGET_TYPE = "Stdout"

# Keeps the webadmin off port 443 without touching ACME eligibility --
# reasoning and incident history: mail/RUNBOOK-mx1-provision.md's "The
# ACME decision".
HTTP_DENY_HTTPS_LISTENER = {
    "match": {"0": {"if": "listener == 'https'", "then": "421"}},
    "else": "200",
}

# The one ACME provider this platform manages, identified by directory URL
# since AcmeProvider objects have no natural name field. Contact address
# matches the domain's real postmaster role address, not an invented one.
ACME_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
ACME_PROVIDER_TARGET: dict[str, Any] = {
    "directory": ACME_DIRECTORY,
    "challengeType": "TlsAlpn01",
    "contact": {"mailto:postmaster@branchleft.co.uk": True},
    "renewBefore": "R23",
    "maxRetries": 10,
    "reuseKey": False,
}


def _field_diff(current: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """Field-by-field diff of only the fields `target` cares about --
    ignores every field the listener has that isn't part of the managed
    spec (socketBacklog, maxConnections, etc. are Stalwart's own defaults
    and none of this script's business).
    """
    return {field: value for field, value in target.items() if current.get(field) != value}


def plan_listener_changes(listeners: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure diff: given the live NetworkListener list, return the
    x:NetworkListener/set arguments needed to reach the target state, or an
    empty dict if nothing needs to change. No network I/O -- this is the
    part covered by the unit tests.
    """
    by_name = {item["name"]: item for item in listeners}
    update: dict[str, dict[str, Any]] = {}
    create: dict[str, dict[str, Any]] = {}
    destroy: list[str] = []

    for name, target in MANAGED_LISTENERS.items():
        listener = by_name.get(name)
        if listener is None:
            if name in CREATE_IF_MISSING:
                create[name] = {"name": name, **target}
            continue

        diff = _field_diff(listener, target)
        if diff:
            update[listener["id"]] = diff

    for name in REMOVED_LISTENER_NAMES:
        listener = by_name.get(name)
        if listener is not None:
            destroy.append(listener["id"])

    args: dict[str, Any] = {}
    if update:
        args["update"] = update
    if create:
        args["create"] = create
    if destroy:
        args["destroy"] = destroy
    return args


def plan_http_change(http_singletons: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure diff: return the x:Http/set arguments needed so the Http
    singleton denies the "https" listener at the HTTP layer, or an empty
    dict if it already does. Only `allowedEndpoints` is managed -- rate
    limits, CORS, etc. are left at whatever they already are.
    """
    if not http_singletons:
        # The singleton has never been materialized (Stalwart's default
        # applies implicitly, per-request, without a stored object) --
        # treat that the same as "wrong", since the default lets 443
        # through unrestricted.
        return {"create": {"singleton": {"allowedEndpoints": HTTP_DENY_HTTPS_LISTENER}}}

    current = http_singletons[0]
    if current.get("allowedEndpoints") == HTTP_DENY_HTTPS_LISTENER:
        return {}
    return {"update": {current["id"]: {"allowedEndpoints": HTTP_DENY_HTTPS_LISTENER}}}


def plan_acme_provider(providers: list[dict[str, Any]]) -> tuple[dict[str, Any], str | None]:
    """Pure diff: return the x:AcmeProvider/set arguments needed so exactly
    one provider matches ACME_PROVIDER_TARGET (matched by directory URL,
    the closest thing this object type has to a natural key), plus the id
    that provider will have (None if it still needs creating).
    """
    for provider in providers:
        if provider.get("directory") == ACME_DIRECTORY:
            diff = _field_diff(provider, ACME_PROVIDER_TARGET)
            if diff:
                return {"update": {provider["id"]: diff}}, provider["id"]
            return {}, provider["id"]

    return {"create": {"production": dict(ACME_PROVIDER_TARGET)}}, None


def plan_domain_sans(
    domain: dict[str, Any], required_sans: set[str], acme_provider_id: str | None
) -> dict[str, Any] | None:
    """Pure diff: return the x:Domain/set update needed so the domain's
    certificate covers `required_sans` and uses `acme_provider_id`, or None
    if it already does. `acme_provider_id` of None means the caller hasn't
    resolved/created the managed provider yet (its own x:AcmeProvider/set
    call hasn't run); the domain update is deferred to the next run rather
    than pointed at a provider that doesn't exist.
    """
    cert = domain.get("certificateManagement", {})
    if cert.get("@type") != "Automatic":
        return None
    if acme_provider_id is None:
        return None

    current_sans = set(cert.get("subjectAlternativeNames", {}).keys())
    missing = required_sans - current_sans
    provider_drifted = cert.get("acmeProviderId") != acme_provider_id
    if not missing and not provider_drifted:
        return None

    new_sans = dict.fromkeys(current_sans | required_sans, True)
    return {
        domain["id"]: {
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": acme_provider_id,
                "subjectAlternativeNames": new_sans,
            }
        }
    }


def plan_tracer_change(tracers: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pure diff: switch the tracer to stdout if it isn't already, so
    `docker logs` shows live activity instead of a log path that's never
    mounted outside the container.
    """
    if not tracers:
        return None
    tracer = tracers[0]
    if tracer.get("@type") == TRACER_TARGET_TYPE:
        return None
    return {
        tracer["id"]: {
            "@type": TRACER_TARGET_TYPE,
            "ansi": False,
            "multiline": False,
            "enable": True,
            "level": tracer.get("level", "info"),
            "lossy": False,
            "events": {},
            "eventsPolicy": "exclude",
        }
    }


def _request(method: str, path: str, auth: tuple[str, str], body: bytes | None = None) -> Any:
    import base64

    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, method=method)
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _jmap_call(auth: tuple[str, str], method: str, args: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(
        {"using": ["urn:ietf:params:jmap:core"], "methodCalls": [[method, args, "0"]]}
    ).encode()
    response = _request("POST", "/jmap", auth, body)
    name, result, _ = response["methodResponses"][0]
    if name == "error":
        raise RuntimeError(f"{method} failed: {result}")
    return result


def _read_bootstrap_password() -> str:
    # Stalwart prints the bootstrap banner to stderr, not stdout -- capture
    # both, the same way `docker logs stalwart 2>&1` would on a terminal.
    out = subprocess.run(
        ["docker", "logs", "stalwart"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    ).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("password:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError(
        "no bootstrap password found in `docker logs stalwart` -- "
        "if the server is already bootstrapped this is expected; "
        f"check {CREDENTIALS_PATH} instead"
    )


def _complete_bootstrap() -> tuple[str, str]:
    """Finishes Stalwart's setup wizard with its own inferred defaults
    (hostname/domain/storage -- all already correct from the
    STALWART_HOSTNAME env var and the container's fresh volumes) and
    returns the resulting permanent admin credential. Only runs once per
    fresh deployment; a re-run against an already-bootstrapped server
    never reaches this path.
    """
    temp_auth = ("admin", _read_bootstrap_password())
    result = _jmap_call(temp_auth, "x:Bootstrap/set", {"update": {"singleton": {}}})
    updated = result["updated"]["singleton"]
    username, secret = updated["username"], updated["secret"]

    subprocess.run(["docker", "restart", "stalwart"], check=True, capture_output=True)
    import time

    time.sleep(6)  # container needs to leave bootstrap mode before the API answers again

    with open(CREDENTIALS_PATH, "w", encoding="utf-8") as f:
        f.write(f"{username}:{secret}\n")
    os.chmod(CREDENTIALS_PATH, 0o600)
    print(f"configure_stalwart: bootstrap complete, credential written to {CREDENTIALS_PATH}")
    return username, secret


def _load_credentials() -> tuple[str, str]:
    with open(CREDENTIALS_PATH, encoding="utf-8") as f:
        username, secret = f.read().strip().split(":", 1)
    return username, secret


def _is_bootstrap_mode(auth: tuple[str, str]) -> bool:
    account = _request("GET", "/api/account", auth)
    return "sysBootstrapUpdate" in account.get("permissions", [])


def _reconcile_listeners(auth: tuple[str, str]) -> bool:
    listeners = _jmap_call(auth, "x:NetworkListener/get", {})["list"]
    listener_args = plan_listener_changes(listeners)
    if not listener_args:
        print("configure_stalwart: network listeners already up to date, no-op")
        return False
    _jmap_call(auth, "x:NetworkListener/set", listener_args)
    print("configure_stalwart: updated network listeners")
    return True


def _reconcile_acme_provider(auth: tuple[str, str]) -> tuple[bool, str | None]:
    providers = _jmap_call(auth, "x:AcmeProvider/get", {})["list"]
    acme_args, acme_provider_id = plan_acme_provider(providers)
    if not acme_args:
        print("configure_stalwart: ACME provider already up to date, no-op")
        return False, acme_provider_id

    result = _jmap_call(auth, "x:AcmeProvider/set", acme_args)
    if "create" in acme_args:
        acme_provider_id = next(iter(result["created"].values()))["id"]
        print("configure_stalwart: created the production ACME provider")
    else:
        print("configure_stalwart: corrected the production ACME provider's fields")
    return True, acme_provider_id


def _reconcile_domains(auth: tuple[str, str], acme_provider_id: str | None) -> bool:
    domains = _jmap_call(auth, "x:Domain/get", {})["list"]
    changed = False
    for domain in domains:
        domain_args = plan_domain_sans(domain, {HOSTNAME}, acme_provider_id)
        if not domain_args:
            print(f"configure_stalwart: domain {domain['name']}'s SAN list/ACME provider already up to date, no-op")
            continue
        _jmap_call(auth, "x:Domain/set", {"update": domain_args})
        print(f"configure_stalwart: updated domain {domain['name']}'s SAN list/ACME provider")
        changed = True
    return changed


def _reconcile_http_access(auth: tuple[str, str]) -> bool:
    http_singletons = _jmap_call(auth, "x:Http/get", {"ids": ["singleton"]})["list"]
    http_args = plan_http_change(http_singletons)
    if not http_args:
        print("configure_stalwart: HTTP access-control rule already up to date, no-op")
        return False
    _jmap_call(auth, "x:Http/set", http_args)
    print("configure_stalwart: set the HTTP access-control rule keeping the webadmin off port 443")
    return True


def _reconcile_tracer(auth: tuple[str, str]) -> bool:
    tracers = _jmap_call(auth, "x:Tracer/get", {})["list"]
    tracer_args = plan_tracer_change(tracers)
    if not tracer_args:
        print("configure_stalwart: tracer already set to stdout, no-op")
        return False
    _jmap_call(auth, "x:Tracer/set", {"update": tracer_args})
    print("configure_stalwart: switched log tracer to stdout")
    return True


def main() -> int:
    if os.path.exists(CREDENTIALS_PATH):
        auth = _load_credentials()
    else:
        auth = _complete_bootstrap()

    if _is_bootstrap_mode(auth):
        # Credentials file existed but bootstrap hadn't actually been
        # finished (e.g. a previous run wrote it then failed before the
        # restart) -- finish it now rather than proceeding with a
        # temporary account.
        auth = _complete_bootstrap()

    # ACME provider must be reconciled (and its id known) before domains,
    # since a domain's certificateManagement points at it by id.
    acme_changed, acme_provider_id = _reconcile_acme_provider(auth)

    changed = any(
        [
            _reconcile_listeners(auth),
            acme_changed,
            _reconcile_domains(auth, acme_provider_id),
            _reconcile_http_access(auth),
            _reconcile_tracer(auth),
        ]
    )

    if changed:
        subprocess.run(["docker", "restart", "stalwart"], check=True, capture_output=True)
        print("configure_stalwart: restarted stalwart to apply changes")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as exc:
        print(f"configure_stalwart: could not reach the Stalwart API at {BASE_URL}: {exc}", file=sys.stderr)
        sys.exit(1)
