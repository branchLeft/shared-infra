#!/usr/bin/env python3
"""Provisions the sign-in service's (Zitadel's) submission credential: an
account `noreply@publicpress.co.uk` with no password of its own and one app
password that can authenticate and submit mail, and nothing else. It can send
as that one address and no other.
Mechanism, refusals and failure modes: provision_zitadel_submission_credential.md.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.error
from typing import Any

import configure_stalwart
from provision_website_submission_credential import plan_app_password_action

SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)

MAIN_DOMAIN = "branchleft.co.uk"

# The only address this credential may send as. The product domain, not the
# main one: customers see the product's name (the owner's ruling of 2026-09-24
# on branchLeft/workspace#1282). The domain must already exist on the server
# (provision_sending_domain.py publicpress.co.uk --dkim-only).
ACCOUNT_LOCAL = "noreply"
ACCOUNT_DOMAIN = "publicpress.co.uk"
ACCOUNT_DESCRIPTION = "Sign-in service submission account (no mailbox access)"

# Must be unique across this directory's wrappers: test_provision_mailboxes.py.
CREDENTIAL_LABEL = os.environ.get("CREDENTIAL_LABEL", "zitadel-smtp")

# The app password's description is this script's idempotency key.
APP_PASSWORD_DESCRIPTION = "zitadel-transactional-submission"

# The only two permissions an SMTP submission asserts in Stalwart v0.16.17.
CREDENTIAL_PERMISSIONS = ("authenticate", "emailSend")

# Stalwart v0.16.17's shipped default: the MAIL FROM must equal the
# authenticated account's own address (or an alias; this account has none).
DEFAULT_MUST_MATCH_SENDER = "true"

# The password manager entry the owner stores the secret under.
PASSWORD_MANAGER_ENTRY = "mx1 stalwart / publicpress / zitadel-smtp-submission"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_LOCAL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")


class Refused(Exception):
    """Live or committed state this script will not act on. Nothing written."""


def account_address(local: str = ACCOUNT_LOCAL, domain: str = ACCOUNT_DOMAIN) -> str:
    """Raises Refused unless the address is plain and outside the main domain:
    this credential must never be able to send as branchleft.co.uk."""
    if not _LOCAL_RE.match(local) or not _DOMAIN_RE.match(domain):
        raise Refused(f"{local!r}@{domain!r} is not a plain lower-case address")
    if domain == MAIN_DOMAIN or domain.endswith("." + MAIN_DOMAIN):
        raise Refused(f"{domain!r} is the main domain or under it; this credential must never send as it")
    return f"{local}@{domain}"


def _normalise(text: Any) -> str:
    return " ".join(str(text).split())


def check_must_match_sender(current: Any, address: str) -> None:
    """Refused unless the exact-address rule applies to `address`. It does when
    the expression's fallback is the shipped `true` and no branch names this
    address: another account's branch (the collector's) is none of this
    script's business, but a branch for this account, or a fallback of
    `false`, would let it send as anyone."""
    if current is None:
        return
    if not isinstance(current, dict):
        raise Refused(f"MtaStageAuth.mustMatchSender has an unexpected shape ({current!r})")
    if _normalise(current.get("else", DEFAULT_MUST_MATCH_SENDER)) != DEFAULT_MUST_MATCH_SENDER:
        raise Refused(
            "MtaStageAuth.mustMatchSender does not fall back to the shipped `true` "
            f"({current!r}); this account would be able to send as any address"
        )
    match = current.get("match") or {}
    branches = list(match.values()) if isinstance(match, dict) else list(match)
    for branch in branches:
        if address in _normalise(branch.get("if", "")):
            raise Refused(
                f"MtaStageAuth.mustMatchSender has a branch for {address} ({branch!r}); "
                "the exact-address rule must apply to it"
            )


def build_account_create_args(local: str, domain_id: str) -> dict[str, Any]:
    # No `credentials`: the account has no password of its own.
    return {
        "@type": "User",
        "name": local,
        "domainId": domain_id,
        "description": ACCOUNT_DESCRIPTION,
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
    if "c" not in (result.get("created") or {}):
        raise RuntimeError(f"x:Account/set did not create the account: {result.get('notCreated')!r}")
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
    if "s" not in (result.get("created") or {}):
        raise RuntimeError(f"x:AppPassword/set did not create the credential: {result.get('notCreated')!r}")
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
    descriptor = os.open(SERVICE_CREDENTIALS_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as f:
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
    """Destroys the app password and its local record. Leaves the account,
    which cannot sign in without it."""
    auth = configure_stalwart._load_credentials()
    domain_id = _domain_ids(auth).get(ACCOUNT_DOMAIN)
    account_id = None if domain_id is None else _find_account(auth, ACCOUNT_LOCAL, domain_id)
    destroyed = 0 if account_id is None else _destroy_app_passwords(auth, account_id)
    removed = remove_recorded_secret(SERVICE_CREDENTIALS_PATH, CREDENTIAL_LABEL)
    print(
        f"provision_zitadel_submission_credential: REVOKED -- destroyed {destroyed} app password(s), "
        f"{'removed' if removed else 'found no'} local record under {CREDENTIAL_LABEL!r}"
    )
    return 0


def show_secret_once(secret: str, address: str) -> None:
    """Prints the secret, once, only to a person at a terminal. Anywhere else
    (a pipe, a log, a CI step) it stays on this host in the credentials file."""
    if not sys.stdout.isatty():
        print(
            "provision_zitadel_submission_credential: the secret was NOT printed because this is not a "
            f"terminal; it is recorded under {CREDENTIAL_LABEL!r} in {SERVICE_CREDENTIALS_PATH}. "
            "Re-run over `ssh -t` to see it."
        )
        return
    line = f"  {secret}  "
    bar = "=" * len(line)
    print(
        f"\n{bar}\n{line}\n{bar}\n"
        f"The credential for {address}, shown ONCE. Store it now in the password manager as\n"
        f"  {PASSWORD_MANAGER_ENTRY}\n"
        "then clear this terminal. It is not shown again.\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--revoke" in args:
        return revoke()
    dry_run = "--dry-run" in args
    address = account_address()

    auth = configure_stalwart._load_credentials()

    # Every read and every refusal happens before the first write.
    domain_ids = _domain_ids(auth)
    if ACCOUNT_DOMAIN not in domain_ids:
        raise Refused(
            f"domain {ACCOUNT_DOMAIN!r} does not exist here; run "
            f"`provision_sending_domain.py {ACCOUNT_DOMAIN} --dkim-only` first"
        )
    auth_stage = configure_stalwart._jmap_call(auth, "x:MtaStageAuth/get", {"ids": ["singleton"]})["list"]
    if not auth_stage:
        raise RuntimeError("x:MtaStageAuth/get returned no singleton")
    check_must_match_sender(auth_stage[0].get("mustMatchSender"), address)

    account_id = _find_account(auth, ACCOUNT_LOCAL, domain_ids[ACCOUNT_DOMAIN])
    exists_remotely = account_id is not None and _app_password_exists(auth, account_id)
    action = plan_credential(account_id is not None, exists_remotely, _load_recorded_secret() is not None)
    if action == "orphaned":
        print(
            f"provision_zitadel_submission_credential: WARNING -- {APP_PASSWORD_DESCRIPTION!r} "
            f"exists on {address} but nothing is recorded under {CREDENTIAL_LABEL!r}; its plaintext "
            "cannot be recovered. Run with --revoke, then run again.",
            file=sys.stderr,
        )
        return 1

    if dry_run:
        planned = [
            *([f"create the account {address}"] if account_id is None else []),
            *(["create the app password"] if action == "create" else []),
        ]
        print(
            "provision_zitadel_submission_credential: DRY RUN, nothing written; would "
            + ("; ".join(planned) if planned else "change nothing")
        )
        return 0

    if account_id is None:
        account_id = _create_account(
            auth, build_account_create_args(ACCOUNT_LOCAL, domain_ids[ACCOUNT_DOMAIN])
        )
        print(f"provision_zitadel_submission_credential: created the account {address}")

    if action == "create":
        secret = _create_app_password(
            auth, account_id, build_app_password_create_args(APP_PASSWORD_DESCRIPTION, CREDENTIAL_PERMISSIONS)
        )
        # Recorded before it is shown: a lost terminal must not lose the secret.
        _record_secret(secret)
        print(
            f"provision_zitadel_submission_credential: created the credential for {address}, "
            f"recorded under {CREDENTIAL_LABEL!r} at {SERVICE_CREDENTIALS_PATH}"
        )
        show_secret_once(secret, address)
    else:
        print("provision_zitadel_submission_credential: credential already provisioned, no-op")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as exc:
        print(f"provision_zitadel_submission_credential: REFUSED, nothing written: {exc}", file=sys.stderr)
        sys.exit(2)
    except urllib.error.HTTPError as exc:
        print(
            f"provision_zitadel_submission_credential: HTTP {exc.code} from the Stalwart API: "
            f"{exc.read().decode(errors='replace')}",
            file=sys.stderr,
        )
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"provision_zitadel_submission_credential: could not reach the Stalwart API: {exc}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as exc:
        print(f"provision_zitadel_submission_credential: {exc}", file=sys.stderr)
        sys.exit(1)
