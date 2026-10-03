#!/usr/bin/env python3
"""Provisions the mail collector's submission credential, scoped to send as
any address in COLLECTOR_SENDING_DOMAINS and never as the main domain.
Mechanism, refusals and failure modes: provision_collector_submission_credential.md.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import urllib.error
from typing import Any

import configure_stalwart
from provision_website_submission_credential import plan_app_password_action

SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)

MAIN_DOMAIN = "branchleft.co.uk"

# Each must already exist on the server (provision_sending_domain.py).
COLLECTOR_SENDING_DOMAINS: tuple[str, ...] = ("trypublicpress.co.uk",)

# With mustMatchSender off for this account, its own address grants nothing.
COLLECTOR_ACCOUNT_LOCAL = "collector"
COLLECTOR_ACCOUNT_DOMAIN = "trypublicpress.co.uk"
COLLECTOR_ACCOUNT_DESCRIPTION = "Mail collector submission account (no mailbox access)"

# Must be unique across this directory's wrappers: test_provision_mailboxes.py.
CREDENTIAL_LABEL = os.environ.get("CREDENTIAL_LABEL", "collector-smtp")

# The app password's description is this script's idempotency key.
APP_PASSWORD_DESCRIPTION = "mail-collector-submission"

# The only two permissions an SMTP submission asserts in Stalwart v0.16.17.
CREDENTIAL_PERMISSIONS = ("authenticate", "emailSend")

# Stalwart v0.16.17's shipped defaults, kept as every other account's branch.
DEFAULT_MUST_MATCH_SENDER = "true"
DEFAULT_IS_SENDER_ALLOWED = (
    "!is_empty(authenticated_as) || !key_exists('spam-block', sender_domain)"
)
DEFAULT_MAIL_STAGE_HOOK = "false"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_LOCAL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")


class Refused(Exception):
    """Live or committed state this script will not act on. Nothing written."""


def validate_sending_domains(domains: tuple[str, ...], main_domain: str = MAIN_DOMAIN) -> None:
    """Raises Refused unless every domain is a plain lower-case name outside
    the main domain. The pattern also keeps a quote out of the expression."""
    if not domains:
        raise Refused("no sending domains: the collector would be able to send as nothing")
    for domain in domains:
        if not _DOMAIN_RE.match(domain):
            raise Refused(f"{domain!r} is not a plain lower-case domain name")
        if domain == main_domain or domain.endswith("." + main_domain):
            raise Refused(
                f"{domain!r} is the main domain or under it; the collector must never send as it"
            )
    if len(set(domains)) != len(domains):
        raise Refused(f"duplicate sending domain in {domains!r}")


def collector_address(local: str = COLLECTOR_ACCOUNT_LOCAL, domain: str = COLLECTOR_ACCOUNT_DOMAIN) -> str:
    if not _LOCAL_RE.match(local) or not _DOMAIN_RE.match(domain):
        raise Refused(f"{local!r}@{domain!r} is not a plain lower-case address")
    return f"{local}@{domain}"


def collector_condition(address: str) -> str:
    return f"authenticated_as == '{address}'"


def sender_domain_check(domains: tuple[str, ...]) -> str:
    # Stalwart's own isSenderAllowed default uses `||`, so it parses.
    return " || ".join(f"sender_domain == '{domain}'" for domain in domains)


def build_is_sender_allowed(address: str, domains: tuple[str, ...]) -> dict[str, Any]:
    validate_sending_domains(domains)
    return {
        "match": {"0": {"if": collector_condition(address), "then": sender_domain_check(domains)}},
        "else": DEFAULT_IS_SENDER_ALLOWED,
    }


def build_must_match_sender(address: str) -> dict[str, Any]:
    return {
        "match": {"0": {"if": collector_condition(address), "then": "false"}},
        "else": DEFAULT_MUST_MATCH_SENDER,
    }


def _normalise(text: Any) -> str:
    return " ".join(str(text).split())


def _matches(expression: Any) -> list[dict[str, Any]]:
    if not isinstance(expression, dict):
        return []
    match = expression.get("match") or {}
    if isinstance(match, dict):
        return [match[key] for key in sorted(match, key=lambda k: (len(str(k)), str(k)))]
    return list(match)


def _same_expression(current: Any, target: dict[str, Any]) -> bool:
    if not isinstance(current, dict):
        return False
    if _normalise(current.get("else", "")) != _normalise(target["else"]):
        return False
    current_matches = _matches(current)
    target_matches = _matches(target)
    if len(current_matches) != len(target_matches):
        return False
    return all(
        _normalise(c.get("if", "")) == _normalise(t["if"])
        and _normalise(c.get("then", "")) == _normalise(t["then"])
        for c, t in zip(current_matches, target_matches)
    )


def plan_expression(current: Any, target: dict[str, Any], default_else: str, name: str) -> dict[str, Any] | None:
    """None if `current` is already `target`; `target` if `current` is the
    default or this script's own earlier output; Refused otherwise."""
    if _same_expression(current, target):
        return None
    if current is None:
        return target
    if not isinstance(current, dict):
        raise Refused(f"{name} has an unexpected shape ({current!r})")
    current_matches = _matches(current)
    is_default_else = _normalise(current.get("else", default_else)) == _normalise(default_else)
    if is_default_else and not current_matches:
        return target
    if (
        is_default_else
        and len(current_matches) == 1
        and _normalise(current_matches[0].get("if", "")) == _normalise(target["match"]["0"]["if"])
    ):
        return target
    raise Refused(
        f"{name} holds a value this script did not write ({current!r}); "
        "reconcile it by hand before re-running"
    )


def check_mail_stage_hooks(mail_stage: dict[str, Any]) -> None:
    """Refused if rewrite or script, which run after isSenderAllowed, is set."""
    for field in ("rewrite", "script"):
        value = mail_stage.get(field)
        if value is None:
            continue
        if not isinstance(value, dict) or _matches(value) or (
            _normalise(value.get("else", DEFAULT_MAIL_STAGE_HOOK)) != DEFAULT_MAIL_STAGE_HOOK
        ):
            raise Refused(
                f"MtaStageMail.{field} is set ({value!r}); it runs after the sender-domain "
                "check and could change the collector's sender past it"
            )


def build_account_create_args(local: str, domain_id: str) -> dict[str, Any]:
    # No `credentials`: the account has no password of its own.
    return {
        "@type": "User",
        "name": local,
        "domainId": domain_id,
        "description": COLLECTOR_ACCOUNT_DESCRIPTION,
    }


def build_app_password_create_args(description: str, permissions: tuple[str, ...]) -> dict[str, Any]:
    if not permissions:
        raise Refused("an empty Replace list would leave the credential unable to submit")
    return {
        "description": description,
        "permissions": {"@type": "Replace", "permissions": {name: True for name in permissions}},
    }


def plan_credential(account_exists: bool, exists_remotely: bool, recorded_locally: bool) -> str:
    """"create", "none" or "orphaned"; Refused on a stale local record,
    which would otherwise shadow the new secret under the same label."""
    if recorded_locally and not exists_remotely:
        raise Refused(
            f"a secret is recorded under {CREDENTIAL_LABEL!r} in {SERVICE_CREDENTIALS_PATH} but no "
            f"{APP_PASSWORD_DESCRIPTION!r} credential exists"
            + ("" if account_exists else " (nor the account)")
            + "; remove that stale line first"
        )
    return plan_app_password_action(exists_remotely, recorded_locally)


def _domain_ids(auth: tuple[str, str]) -> dict[str, str]:
    domains = configure_stalwart._jmap_call(auth, "x:Domain/get", {})["list"]
    return {domain["name"]: domain["id"] for domain in domains}


def _find_account(auth: tuple[str, str], local: str, domain_id: str) -> str | None:
    accounts = configure_stalwart._jmap_call(
        auth, "x:Account/get", {"properties": ["name", "domainId"]}
    )["list"]
    for account in accounts:
        if account.get("name") == local and account.get("domainId") == domain_id:
            return str(account["id"])
    return None


def _create_account(auth: tuple[str, str], create_args: dict[str, Any]) -> str:
    result = configure_stalwart._jmap_call(auth, "x:Account/set", {"create": {"c": create_args}})
    return str(result["created"]["c"]["id"])


def _app_password_exists(auth: tuple[str, str], account_id: str) -> bool:
    result = configure_stalwart._jmap_call(
        auth, "x:AppPassword/get", {"accountId": account_id, "properties": ["description"]}
    )
    return any(entry.get("description") == APP_PASSWORD_DESCRIPTION for entry in result["list"])


def _create_app_password(auth: tuple[str, str], account_id: str, create_args: dict[str, Any]) -> str:
    result = configure_stalwart._jmap_call(
        auth, "x:AppPassword/set", {"accountId": account_id, "create": {"s": create_args}}
    )
    return str(result["created"]["s"]["secret"])


def _load_recorded_secret() -> str | None:
    if not os.path.exists(SERVICE_CREDENTIALS_PATH):
        return None
    with open(SERVICE_CREDENTIALS_PATH, encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise RuntimeError(
                    f"{SERVICE_CREDENTIALS_PATH}:{line_number} is malformed (no ':' separator)"
                )
            label, secret = line.split(":", 1)
            if label == CREDENTIAL_LABEL:
                return secret
    return None


def _record_secret(secret: str) -> None:
    with open(SERVICE_CREDENTIALS_PATH, "a", encoding="utf-8") as f:
        f.write(f"{CREDENTIAL_LABEL}:{secret}\n")
    os.chmod(SERVICE_CREDENTIALS_PATH, 0o600)


def remove_recorded_secret(path: str, label: str) -> bool:
    """Drops every `label:` line from the label:secret file, keeping the rest.
    Returns whether anything was removed."""
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


def _destroy_app_passwords(auth: tuple[str, str], account_id: str) -> int:
    found = configure_stalwart._jmap_call(
        auth, "x:AppPassword/get", {"accountId": account_id, "properties": ["description"]}
    )["list"]
    ids = [entry["id"] for entry in found if entry.get("description") == APP_PASSWORD_DESCRIPTION]
    if ids:
        configure_stalwart._jmap_call(auth, "x:AppPassword/set", {"accountId": account_id, "destroy": ids})
    return len(ids)


def revoke() -> int:
    """Destroys the collector's app password and its local record. Leaves
    the account and both expressions, which match nothing without it."""
    auth = configure_stalwart._load_credentials()
    domain_id = _domain_ids(auth).get(COLLECTOR_ACCOUNT_DOMAIN)
    account_id = None if domain_id is None else _find_account(auth, COLLECTOR_ACCOUNT_LOCAL, domain_id)
    destroyed = 0 if account_id is None else _destroy_app_passwords(auth, account_id)
    removed = remove_recorded_secret(SERVICE_CREDENTIALS_PATH, CREDENTIAL_LABEL)
    print(
        f"provision_collector_submission_credential: REVOKED -- destroyed {destroyed} app password(s), "
        f"{'removed' if removed else 'found no'} local record under {CREDENTIAL_LABEL!r}"
    )
    return 0


def _get_singleton(auth: tuple[str, str], object_type: str) -> dict[str, Any]:
    found = configure_stalwart._jmap_call(auth, f"x:{object_type}/get", {"ids": ["singleton"]})["list"]
    if not found:
        raise RuntimeError(f"x:{object_type}/get returned no singleton")
    return dict(found[0])


def _set_singleton(auth: tuple[str, str], object_type: str, patch: dict[str, Any]) -> None:
    # Checked here as well as in _jmap_call: the next write is only safe if this one landed.
    result = configure_stalwart._jmap_call(auth, f"x:{object_type}/set", {"update": {"singleton": patch}})
    if result.get("notUpdated") or "singleton" not in (result.get("updated") or {}):
        raise RuntimeError(f"x:{object_type}/set did not apply: {result.get('notUpdated')!r}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--revoke" in args:
        return revoke()
    dry_run = "--dry-run" in args
    address = collector_address()
    is_sender_allowed = build_is_sender_allowed(address, COLLECTOR_SENDING_DOMAINS)
    must_match_sender = build_must_match_sender(address)

    auth = configure_stalwart._load_credentials()

    # Every read and every refusal happens before the first write.
    domain_ids = _domain_ids(auth)
    missing = [d for d in (COLLECTOR_ACCOUNT_DOMAIN, *COLLECTOR_SENDING_DOMAINS) if d not in domain_ids]
    if missing:
        raise Refused(f"domain(s) {missing} do not exist here; run provision_sending_domain.py first")

    mail_stage = _get_singleton(auth, "MtaStageMail")
    auth_stage = _get_singleton(auth, "MtaStageAuth")
    check_mail_stage_hooks(mail_stage)
    mail_patch = plan_expression(
        mail_stage.get("isSenderAllowed"), is_sender_allowed, DEFAULT_IS_SENDER_ALLOWED,
        "MtaStageMail.isSenderAllowed",
    )
    auth_patch = plan_expression(
        auth_stage.get("mustMatchSender"), must_match_sender, DEFAULT_MUST_MATCH_SENDER,
        "MtaStageAuth.mustMatchSender",
    )

    account_id = _find_account(auth, COLLECTOR_ACCOUNT_LOCAL, domain_ids[COLLECTOR_ACCOUNT_DOMAIN])
    exists_remotely = account_id is not None and _app_password_exists(auth, account_id)
    action = plan_credential(account_id is not None, exists_remotely, _load_recorded_secret() is not None)
    if action == "orphaned":
        print(
            f"provision_collector_submission_credential: WARNING -- {APP_PASSWORD_DESCRIPTION!r} "
            f"exists on {address} but nothing is recorded under {CREDENTIAL_LABEL!r}; its plaintext "
            "cannot be recovered. Destroy it via x:AppPassword/set and re-run.",
            file=sys.stderr,
        )
        return 1

    if dry_run:
        planned = [
            *(["set MtaStageMail.isSenderAllowed"] if mail_patch is not None else []),
            *(["set MtaStageAuth.mustMatchSender"] if auth_patch is not None else []),
            *([f"create the account {address}"] if account_id is None else []),
            *(["create the app password"] if action == "create" else []),
        ]
        print(
            "provision_collector_submission_credential: DRY RUN, nothing written; would "
            + ("; ".join(planned) if planned else "change nothing")
        )
        return 0

    # Domain restriction first, so the collector is never exempt from the
    # exact-address check without already being held to its domains.
    changed = False
    if mail_patch is not None:
        _set_singleton(auth, "MtaStageMail", {"isSenderAllowed": mail_patch})
        print("provision_collector_submission_credential: set MtaStageMail.isSenderAllowed")
        changed = True
    if auth_patch is not None:
        _set_singleton(auth, "MtaStageAuth", {"mustMatchSender": auth_patch})
        print("provision_collector_submission_credential: set MtaStageAuth.mustMatchSender")
        changed = True

    # Restart now, not at the end: a later failure must not leave stored but
    # unloaded expressions that a re-run would see as already reconciled.
    if changed:
        subprocess.run(["docker", "restart", "stalwart"], check=True, capture_output=True)
        configure_stalwart._wait_for_stalwart_ready(auth)
        print("provision_collector_submission_credential: restarted stalwart to apply changes")

    if account_id is None:
        account_id = _create_account(
            auth, build_account_create_args(COLLECTOR_ACCOUNT_LOCAL, domain_ids[COLLECTOR_ACCOUNT_DOMAIN])
        )
        print(f"provision_collector_submission_credential: created the account {address}")

    if action == "create":
        secret = _create_app_password(
            auth, account_id, build_app_password_create_args(APP_PASSWORD_DESCRIPTION, CREDENTIAL_PERMISSIONS)
        )
        _record_secret(secret)
        print(
            f"provision_collector_submission_credential: created the credential for {address}, "
            f"recorded under {CREDENTIAL_LABEL!r} at {SERVICE_CREDENTIALS_PATH}"
        )
    else:
        print("provision_collector_submission_credential: credential already provisioned, no-op")

    # Proves storage, not enforcement: check_collector_sender_scope.py does that.
    stored_mail = _get_singleton(auth, "MtaStageMail").get("isSenderAllowed")
    stored_auth = _get_singleton(auth, "MtaStageAuth").get("mustMatchSender")
    if not (_same_expression(stored_mail, is_sender_allowed) and _same_expression(stored_auth, must_match_sender)):
        raise RuntimeError("read-back does not match what was written; the sender scope is NOT in place")
    print(
        "provision_collector_submission_credential: sender scope stored -- "
        f"{address} may send as @{', @'.join(COLLECTOR_SENDING_DOMAINS)} only"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as exc:
        print(f"provision_collector_submission_credential: REFUSED, nothing written: {exc}", file=sys.stderr)
        sys.exit(2)
    except urllib.error.HTTPError as exc:
        print(
            f"provision_collector_submission_credential: HTTP {exc.code} from the Stalwart API: "
            f"{exc.read().decode(errors='replace')}",
            file=sys.stderr,
        )
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"provision_collector_submission_credential: could not reach the Stalwart API: {exc}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as exc:
        print(f"provision_collector_submission_credential: {exc}", file=sys.stderr)
        sys.exit(1)
