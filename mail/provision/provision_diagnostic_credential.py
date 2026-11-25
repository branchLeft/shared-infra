#!/usr/bin/env python3
"""Provisions the read-only diagnostic API key for Stalwart on mx1; mechanism, the two fences and the failure modes are in provision_diagnostic_credential.md.
Usage (on mx1, as root; every run reads before it writes):
    python3 provision_diagnostic_credential.py --dry-run   # reads only, prints the plan
    python3 provision_diagnostic_credential.py             # creates what is missing, then proves the scope
    python3 provision_diagnostic_credential.py --revoke    # destroys the key and its local record
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import configure_stalwart

SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)
CREDENTIAL_LABEL = os.environ.get("CREDENTIAL_LABEL", "diagnostic-read-only")

ACCOUNT_LOCAL = "diagnostic"
ACCOUNT_DOMAIN = "branchleft.co.uk"
ACCOUNT_DESCRIPTION = "Read-only diagnostics account (no mailbox access, no password)"
ROLE_DESCRIPTION = "Diagnostic read-only: reads the queue, reports and logs, changes nothing"
API_KEY_DESCRIPTION = "mail-diagnostic-read-only"
KEY_LIFETIME_DAYS = 180

# Each object the key may read. Metric and Trace are Enterprise-only in v0.16.
READ_OBJECTS: tuple[str, ...] = (
    "QueuedMessage",
    "ArfExternalReport",
    "DmarcExternalReport",
    "DmarcInternalReport",
    "TlsExternalReport",
    "TlsInternalReport",
    "Log",
)
# The whole permission set, on the role and again on the key. A permission the
# server does not know is rejected by x:Role/set, so a typo here fails loudly
# instead of leaving a narrower or wider grant than this tuple says.
PERMISSIONS: tuple[str, ...] = ("authenticate",) + tuple(
    f"sys{obj}{verb}" for obj in READ_OBJECTS for verb in ("Get", "Query")
)

# The Stalwart version this scope was written against; the test fails when
# docker-compose.yml pins another one, so a bump re-asks the question.
VERIFIED_STALWART_VERSION = "v0.16.17"

# Objects the key must NOT reach, each with one call that changes nothing even
# if the server wrongly allowed it (a destroy or update of an id that does not
# exist answers notFound). Every one must answer `forbidden`.
DENIED_PROBES: tuple[tuple[str, dict[str, Any]], ...] = (
    ("x:Account/get", {}),
    ("x:Account/query", {}),
    ("x:Account/set", {"update": {"none": {"description": "x"}}}),
    ("x:Role/get", {}),
    ("x:ApiKey/get", {}),
    ("x:AppPassword/get", {}),
    ("x:Domain/get", {}),
    ("x:Domain/set", {"destroy": ["none"]}),
    ("x:Http/get", {}),
    ("x:BlockedIp/set", {"destroy": ["none"]}),
    ("x:QueuedMessage/set", {"destroy": ["none"]}),
    ("x:DkimSignature/get", {}),
    ("x:Action/set", {"destroy": ["none"]}),
)


class Refused(Exception):
    """Live or committed state this script will not act on. Nothing written."""


def permission_map(names: tuple[str, ...] = PERMISSIONS) -> dict[str, bool]:
    return {name: True for name in names}


def build_role_create_args() -> dict[str, Any]:
    return {
        "description": ROLE_DESCRIPTION,
        "roleIds": {},
        "enabledPermissions": permission_map(),
        "disabledPermissions": {},
    }


def build_account_create_args(domain_id: str, role_id: str) -> dict[str, Any]:
    # No `credentials`: the account has no password of its own.
    return {
        "@type": "User",
        "name": ACCOUNT_LOCAL,
        "domainId": domain_id,
        "description": ACCOUNT_DESCRIPTION,
        "roles": {"@type": "Custom", "roleIds": {role_id: True}},
        "permissions": {"@type": "Inherit"},
    }


def build_api_key_create_args(now: datetime) -> dict[str, Any]:
    expires = (now + timedelta(days=KEY_LIFETIME_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "description": API_KEY_DESCRIPTION,
        "expiresAt": expires,
        "allowedIps": {},
        # Replace, never Inherit: the key holds exactly these permissions
        # whatever the account is later given.
        "permissions": {"@type": "Replace", "permissions": permission_map()},
    }


def _names(value: Any) -> set[str]:
    """The names in a JMAP Set<Permission>, sent as {name: true} or as a list."""
    if isinstance(value, dict):
        return {str(name) for name, on in value.items() if on}
    if isinstance(value, list):
        return {str(name) for name in value}
    return set()


def check_role(role: dict[str, Any]) -> None:
    """Refused unless `role` grants exactly PERMISSIONS and extends nothing."""
    if _names(role.get("enabledPermissions")) != set(PERMISSIONS):
        raise Refused(
            "the diagnostic role holds permissions this script did not write; "
            "reconcile it by hand before re-running"
        )
    if _names(role.get("disabledPermissions")) or _names(role.get("roleIds")):
        raise Refused("the diagnostic role disables or extends something; reconcile it by hand")


def check_account(account: dict[str, Any], role_id: str) -> None:
    """Refused unless the account is the custom-role account this script makes."""
    roles = account.get("roles")
    if not isinstance(roles, dict) or roles.get("@type") != "Custom" or _names(roles.get("roleIds")) != {role_id}:
        raise Refused(f"{ACCOUNT_LOCAL}@{ACCOUNT_DOMAIN} holds roles other than the diagnostic role")
    permissions = account.get("permissions")
    if permissions is not None and (not isinstance(permissions, dict) or permissions.get("@type") != "Inherit"):
        raise Refused(f"{ACCOUNT_LOCAL}@{ACCOUNT_DOMAIN} has its own permissions set; it must inherit")
    for credential in account.get("credentials") or []:
        if isinstance(credential, dict) and credential.get("@type") == "Password":
            raise Refused(f"{ACCOUNT_LOCAL}@{ACCOUNT_DOMAIN} has a password; it must have none")


def classify(status: int, body: Any) -> str:
    """One word for what a single-call JMAP response says: `allowed`,
    `forbidden`, or `other: <detail>`. Anything not clearly one of the first
    two is `other`, which the caller treats as a failure."""
    if status in (401, 403):
        return "forbidden" if status == 403 else "other: HTTP 401 (key not accepted)"
    if status != 200 or not isinstance(body, dict):
        return f"other: HTTP {status}"
    responses = body.get("methodResponses")
    if not isinstance(responses, list) or len(responses) != 1 or not isinstance(responses[0], list):
        return "other: no single method response"
    name, result = responses[0][0], responses[0][1]
    if name == "error":
        kind = result.get("type") if isinstance(result, dict) else None
        return "forbidden" if kind == "forbidden" else f"other: method error {kind!r}"
    if isinstance(result, dict) and any(result.get(k) for k in ("notCreated", "notUpdated", "notDestroyed")):
        # The call ran and rejected the object itself (for example notFound):
        # the permission check passed, so this is not forbidden.
        return "other: the call was permitted and rejected on its object"
    return "allowed"


Probe = Callable[[str, str, dict[str, Any]], str]


# Objects whose query can answer invalidArguments on a server that holds the
# permission. Stalwart checks sysLogQuery before the handler runs (a missing
# permission is `forbidden`), and Log/query then answers invalidArguments
# ("No log tracers configured") when no file Log tracer is enabled, which is
# the Stdout tracer configure_stalwart.py sets on mx1. Only that answer counts
# as proof of the permission; a forbidden or any other answer is still a problem.
PERMISSION_ONLY_OBJECTS: tuple[str, ...] = ("Log",)
PERMISSION_PROVEN_VERDICT = "other: method error 'invalidArguments'"


def verify_scope(probe: Probe, token: str) -> list[str]:
    """Every way the key's real behaviour differs from the intended scope;
    empty when it reads what it should and is refused everything else."""
    problems: list[str] = []
    for obj in READ_OBJECTS:
        verdict = probe(token, f"x:{obj}/query", {"limit": 1})
        accepted = {"allowed"}
        if obj in PERMISSION_ONLY_OBJECTS:
            accepted.add(PERMISSION_PROVEN_VERDICT)
        if verdict not in accepted:
            problems.append(f"x:{obj}/query should be allowed: {verdict}")
    for method, args in DENIED_PROBES:
        verdict = probe(token, method, args)
        if verdict != "forbidden":
            problems.append(f"{method} should be forbidden: {verdict}")
    return problems


def http_probe(token: str, method: str, args: dict[str, Any]) -> str:
    """Sends one call with the key to the loopback API and classifies it."""
    body = json.dumps(
        {"using": ["urn:ietf:params:jmap:core"], "methodCalls": [[method, args, "0"]]}
    ).encode()
    request = urllib.request.Request(f"{configure_stalwart.BASE_URL}/jmap", data=body, method="POST")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return classify(resp.status, json.loads(resp.read()))
    except urllib.error.HTTPError as exc:
        return classify(exc.code, None)


def _load_recorded_secret() -> str | None:
    if not os.path.exists(SERVICE_CREDENTIALS_PATH):
        return None
    with open(SERVICE_CREDENTIALS_PATH, encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise RuntimeError(f"{SERVICE_CREDENTIALS_PATH}:{line_number} is malformed (no ':' separator)")
            label, secret = line.split(":", 1)
            if label == CREDENTIAL_LABEL:
                return secret
    return None


def _record_secret(secret: str) -> None:
    descriptor = os.open(SERVICE_CREDENTIALS_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as f:
        f.write(f"{CREDENTIAL_LABEL}:{secret}\n")
    os.chmod(SERVICE_CREDENTIALS_PATH, 0o600)


def remove_recorded_secret(path: str, label: str) -> bool:
    """Drops every `label:` line from the label:secret file, keeping the rest."""
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    kept = [line for line in lines if line.split(":", 1)[0].strip() != label]
    if len(kept) == len(lines):
        return False
    temporary = f"{path}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as f:
        f.writelines(kept)
    os.replace(temporary, path)
    return True


Auth = tuple[str, str]


def _call(auth: Auth, method: str, args: dict[str, Any]) -> dict[str, Any]:
    return configure_stalwart._jmap_call(auth, method, args)


def _domain_id(auth: Auth) -> str:
    for domain in _call(auth, "x:Domain/get", {})["list"]:
        if domain.get("name") == ACCOUNT_DOMAIN:
            return str(domain["id"])
    raise Refused(f"domain {ACCOUNT_DOMAIN} does not exist here")


def _find_role(auth: Auth) -> dict[str, Any] | None:
    for role in _call(auth, "x:Role/get", {})["list"]:
        if role.get("description") == ROLE_DESCRIPTION:
            return dict(role)
    return None


def _find_account(auth: Auth, domain_id: str) -> dict[str, Any] | None:
    accounts = _call(auth, "x:Account/get", {"properties": ["name", "domainId", "roles", "permissions", "credentials"]})
    for account in accounts["list"]:
        if account.get("name") == ACCOUNT_LOCAL and account.get("domainId") == domain_id:
            return dict(account)
    return None


def _key_ids(auth: Auth, account_id: str) -> list[str]:
    found = _call(auth, "x:ApiKey/get", {"accountId": account_id, "properties": ["description"]})["list"]
    return [str(k["id"]) for k in found if k.get("description") == API_KEY_DESCRIPTION]


def _destroy_keys(auth: Auth, account_id: str) -> int:
    ids = _key_ids(auth, account_id)
    if ids:
        _call(auth, "x:ApiKey/set", {"accountId": account_id, "destroy": ids})
    return len(ids)


def revoke() -> int:
    """Destroys the key and its local record; leaves the role and the account,
    which can sign in as nothing without a credential."""
    auth = configure_stalwart._load_credentials()
    domain_id = _domain_id(auth)
    account = _find_account(auth, domain_id)
    destroyed = 0 if account is None else _destroy_keys(auth, str(account["id"]))
    removed = remove_recorded_secret(SERVICE_CREDENTIALS_PATH, CREDENTIAL_LABEL)
    print(
        f"provision_diagnostic_credential: REVOKED -- destroyed {destroyed} API key(s), "
        f"{'removed' if removed else 'found no'} local record under {CREDENTIAL_LABEL!r}"
    )
    return 0


def main(argv: list[str] | None = None, probe: Probe = http_probe, now: datetime | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--revoke" in args:
        return revoke()
    dry_run = "--dry-run" in args
    moment = now or datetime.now(timezone.utc)
    auth = configure_stalwart._load_credentials()

    # Every read and every refusal happens before the first write.
    domain_id = _domain_id(auth)
    role = _find_role(auth)
    if role is not None:
        check_role(role)
    account = _find_account(auth, domain_id) if role is not None else None
    if account is not None:
        check_account(account, str(role["id"]) if role else "")
    key_ids = _key_ids(auth, str(account["id"])) if account is not None else []
    recorded = _load_recorded_secret()
    if len(key_ids) > 1:
        raise Refused(f"{len(key_ids)} API keys named {API_KEY_DESCRIPTION!r} exist; run --revoke and re-run")
    if recorded is not None and not key_ids:
        raise Refused(
            f"a secret is recorded under {CREDENTIAL_LABEL!r} in {SERVICE_CREDENTIALS_PATH} but no key exists; "
            "remove that stale line first"
        )
    if key_ids and recorded is None:
        print(
            f"provision_diagnostic_credential: WARNING -- {API_KEY_DESCRIPTION!r} exists but nothing is "
            f"recorded under {CREDENTIAL_LABEL!r}; its secret cannot be recovered. Run --revoke, then re-run.",
            file=sys.stderr,
        )
        return 1

    if dry_run:
        planned = [
            *(["create the role"] if role is None else []),
            *([f"create the account {ACCOUNT_LOCAL}@{ACCOUNT_DOMAIN}"] if account is None else []),
            *(["create the API key"] if not key_ids else ["prove the existing key's scope"]),
        ]
        print("provision_diagnostic_credential: DRY RUN, nothing written; would " + "; ".join(planned))
        return 0

    if role is None:
        created = _call(auth, "x:Role/set", {"create": {"r": build_role_create_args()}})
        role = {"id": created["created"]["r"]["id"]}
        print("provision_diagnostic_credential: created the diagnostic role")
    if account is None:
        created = _call(auth, "x:Account/set", {"create": {"a": build_account_create_args(domain_id, str(role["id"]))}})
        account = {"id": created["created"]["a"]["id"]}
        print(f"provision_diagnostic_credential: created the account {ACCOUNT_LOCAL}@{ACCOUNT_DOMAIN}")

    fresh = not key_ids
    if fresh:
        created = _call(
            auth,
            "x:ApiKey/set",
            {"accountId": str(account["id"]), "create": {"k": build_api_key_create_args(moment)}},
        )
        secret = created["created"]["k"].get("secret")
        if not isinstance(secret, str) or not secret:
            _destroy_keys(auth, str(account["id"]))
            raise Refused("Stalwart did not return the new key's secret; the key was destroyed. Nothing is recorded")
        _record_secret(secret)
        print(
            f"provision_diagnostic_credential: created the API key, recorded under {CREDENTIAL_LABEL!r} "
            f"at {SERVICE_CREDENTIALS_PATH}"
        )
    else:
        secret = str(recorded)

    try:
        problems = verify_scope(probe, secret)
    except BaseException:
        # A transport error, a timeout or an interrupt: the fresh key is unproven, so it goes.
        if fresh:
            _destroy_keys(auth, str(account["id"]))
            remove_recorded_secret(SERVICE_CREDENTIALS_PATH, CREDENTIAL_LABEL)
        raise
    if problems:
        if fresh:
            _destroy_keys(auth, str(account["id"]))
            remove_recorded_secret(SERVICE_CREDENTIALS_PATH, CREDENTIAL_LABEL)
        for problem in problems:
            print(f"provision_diagnostic_credential: {problem}", file=sys.stderr)
        print(
            "provision_diagnostic_credential: FAILED, the key does not have the intended scope"
            + ("; it was destroyed and its record removed" if fresh else "; run --revoke"),
            file=sys.stderr,
        )
        return 1
    print(
        f"provision_diagnostic_credential: scope proven -- the key reads {len(READ_OBJECTS)} objects "
        f"and was refused all {len(DENIED_PROBES)} probes of anything else"
    )
    return 0


def run() -> int:
    try:
        return main()
    except Refused as exc:
        print(f"provision_diagnostic_credential: REFUSED, nothing written: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run())
