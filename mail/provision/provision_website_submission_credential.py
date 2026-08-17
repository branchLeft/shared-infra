#!/usr/bin/env python3
"""Provisions a dedicated, submission-only SMTP credential attached to an
existing mailbox account -- one that can send as that account's address but
cannot read its mailbox, or any mailbox, via IMAP. So a leaked app
credential (a website env var, a Ghost config value, ...) can never expose
real mail. Parameterised via SEND_AS_LOCAL / CREDENTIAL_LABEL /
APP_PASSWORD_DESCRIPTION (environment variables, defaults below) so the same
logic provisions every submission-only credential this platform needs --
currently the website contact form (branchLeft/website#61, send-as info@,
wired up by 60-provision-website-submission-credential.sh) and the blog's
transactional mail (send-as blog@, wired up by
61-provision-blog-submission-credential.sh).

Confirmed from Stalwart's own source before writing this, not assumed by
analogy to provision_mailboxes.py's Account creation:

1. Stalwart has no separate "submission-only" principal type -- the
   registry's AccountType enum is only User/Group (crates/registry/src/
   schema/enums.rs). The idiomatic mechanism for a narrowly-scoped,
   independently-revocable credential is instead a *secondary credential*
   (an "app password") attached to an *existing* account, created via
   `x:AppPassword/set` -- a different registry object (ObjectType::AppPassword)
   from the account's own `credentials` list, which explicitly refuses
   secondary credentials passed there directly ("Secondary credentials
   cannot be set directly", crates/jmap/src/registry/mapping/principal.rs).
   The server generates and returns the secret once, in the create
   response -- it can never be retrieved again, same as a real app-password
   flow anywhere else.
2. A **separate account** claiming the target address (e.g.
   `info@branchleft.co.uk`) as a send-as alias was the first design
   considered and doesn't work: both an account's own primary address and
   every `EmailAlias` register the same global-unique `(name, domainId)`
   index (`Property::Email` in UserAccount::index and EmailAlias::index,
   crates/registry/src/schema/structs_impl.rs) -- and that address is
   already claimed as the real mailbox's own primary address. A second
   account can't alias it, for any local part under this domain. An app
   password attached to the *existing* account sidesteps this entirely:
   `authenticated_as` for that session already *is* the target address, so
   Stalwart's sender-restriction check (`must_match_sender`,
   crates/smtp/src/inbound/mail.rs -- defaults to `true` when unconfigured,
   per crates/registry/src/schema/structs_impl.rs's
   MtaStageAuth::ctx_must_match_sender, and nothing on this box has ever
   overridden it) is satisfied trivially, with no alias needed.
3. IMAP access is blocked *for this credential specifically*, not the
   account as a whole: an app password's own `permissions` field
   (`CredentialPermissions::Disable`) clears listed permissions from a
   *copy* of the account's effective permissions for sessions authenticated
   with that credential only (crates/common/src/auth/access_token.rs) --
   the account's real password credential is untouched, so a human can
   still IMAP into the account normally with its own password if ever
   needed. `imapAuthenticate` is the permission IMAP's own
   LOGIN/AUTHENTICATE handler asserts before anything else runs
   (crates/imap/src/op/authenticate.rs) -- disabling it blocks IMAP login
   outright, verified live (see
   mail/RUNBOOK-mx1-provision.md#website-submission-credential): a wrong
   password gets a normal tagged NO response; this credential's *correct*
   password instead gets the connection closed immediately, a distinctly
   different, stricter rejection.

Idempotent: keyed on the app password's `description` (the only
free-text, listable-without-secret field on this object) -- a second run
finds one already present and no-ops. If Stalwart's create response is
lost after it actually applied (the same class of risk
provision_mailboxes.py's credential-loss fix addresses) there is no way to
recover the plaintext after the fact -- this script detects that state
(a credential with the right description exists remotely, but nothing is
recorded locally) and reports it loudly rather than treating it as a
silent no-op; see plan_app_password_action.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
ADMIN_CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)
SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "branchleft.co.uk")

# The existing mailbox (provisioned by provision_mailboxes.py) this
# credential authenticates into and is restricted to send as -- not a new
# account. See the module docstring for why. One invocation of this script
# provisions exactly one credential; the caller (a 6x-provision-*.sh
# wrapper) selects which via these three environment variables, all
# defaulting to the original website/info@ credential so
# 60-provision-website-submission-credential.sh keeps working unchanged.
SEND_AS_LOCAL = os.environ.get("SEND_AS_LOCAL", "info")

# Key under which the generated secret is recorded in SERVICE_CREDENTIALS_PATH.
CREDENTIAL_LABEL = os.environ.get("CREDENTIAL_LABEL", "info-website-submission")

# The app password's `description` on Stalwart's side -- also this script's
# idempotency key, so it must stay stable across runs.
APP_PASSWORD_DESCRIPTION = os.environ.get(
    "APP_PASSWORD_DESCRIPTION", "website-contact-form-submission"
)

# Cleared from this credential's own effective permissions -- see the
# module docstring's point 3. IMAP's AUTHENTICATE/LOGIN handlers assert
# this before any mailbox becomes reachable.
DISABLED_PERMISSIONS = ("imapAuthenticate",)


def build_app_password_create_args(
    description: str, disabled_permissions: tuple[str, ...]
) -> dict[str, Any]:
    """The x:AppPassword/set create object -- pure, no I/O."""
    return {
        "description": description,
        "permissions": {
            "@type": "Disable",
            "permissions": {name: True for name in disabled_permissions},
        },
    }


def plan_app_password_action(existing_remotely: bool, recorded_locally: bool) -> str:
    """Pure diff. Returns one of:
    "create"   -- no app password with our description exists yet
    "orphaned" -- one exists remotely but nothing is recorded locally --
                  the credential-loss scenario this script can detect but
                  not fix (the plaintext is gone; see the module docstring)
    "none"     -- already provisioned and already recorded, no-op
    """
    if not existing_remotely:
        return "create"
    if not recorded_locally:
        return "orphaned"
    return "none"


def _request(method: str, path: str, auth: tuple[str, str], body: bytes | None = None) -> Any:
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, method=method)
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _jmap_call(auth: tuple[str, str], method: str, args: dict[str, Any], using: list[str] | None = None) -> dict[str, Any]:
    body = json.dumps(
        {"using": using or ["urn:ietf:params:jmap:core"], "methodCalls": [[method, args, "0"]]}
    ).encode()
    response = _request("POST", "/jmap", auth, body)
    name, result, _ = response["methodResponses"][0]
    if name == "error":
        raise RuntimeError(f"{method} failed: {result}")
    return result


def _load_admin_credentials() -> tuple[str, str]:
    with open(ADMIN_CREDENTIALS_PATH, encoding="utf-8") as f:
        username, secret = f.read().strip().split(":", 1)
    return username, secret


def _get_domain_id(auth: tuple[str, str], domain_name: str) -> str:
    domains = _jmap_call(auth, "x:Domain/get", {})["list"]
    for domain in domains:
        if domain["name"] == domain_name:
            return domain["id"]
    raise RuntimeError(f"no Domain object named {domain_name!r}")


def _get_account_id(auth: tuple[str, str], local: str, domain_id: str) -> str:
    # Only "name"/"domainId" requested -- never touches `credentials`.
    accounts = _jmap_call(auth, "x:Account/get", {"properties": ["name", "domainId"]})["list"]
    for account in accounts:
        if account.get("name") == local and account.get("domainId") == domain_id:
            return account["id"]
    raise RuntimeError(
        f"no Account named {local!r} under domain {domain_id!r} -- expected "
        "provision_mailboxes.py to have already created it"
    )


def _app_password_exists(auth: tuple[str, str], account_id: str, description: str) -> bool:
    # Only "description" requested -- never touches the (hashed) `secret`.
    result = _jmap_call(auth, "x:AppPassword/get", {"accountId": account_id, "properties": ["description"]})
    return any(entry.get("description") == description for entry in result["list"])


def _create_app_password(auth: tuple[str, str], account_id: str, create_args: dict[str, Any]) -> str:
    result = _jmap_call(auth, "x:AppPassword/set", {"accountId": account_id, "create": {"s": create_args}})
    if "s" not in result.get("created", {}):
        raise RuntimeError(f"x:AppPassword/set did not create the credential: {result.get('notCreated')}")
    return result["created"]["s"]["secret"]


def _load_recorded_secret() -> str | None:
    if not os.path.exists(SERVICE_CREDENTIALS_PATH):
        return None
    with open(SERVICE_CREDENTIALS_PATH, encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                # A disk-full mid-append or a hand-edited file could leave a
                # line with no secret at all -- fail with a clear reason
                # rather than an unpacking ValueError and a raw traceback.
                raise RuntimeError(
                    f"{SERVICE_CREDENTIALS_PATH}:{line_number} is malformed "
                    "(no ':' separator) -- expected 'label:secret'"
                )
            label, secret = line.split(":", 1)
            if label == CREDENTIAL_LABEL:
                return secret
    return None


def _record_secret(secret: str) -> None:
    with open(SERVICE_CREDENTIALS_PATH, "a", encoding="utf-8") as f:
        f.write(f"{CREDENTIAL_LABEL}:{secret}\n")
    os.chmod(SERVICE_CREDENTIALS_PATH, 0o600)


def main() -> int:
    auth = _load_admin_credentials()
    domain_id = _get_domain_id(auth, MAIL_DOMAIN)
    account_id = _get_account_id(auth, SEND_AS_LOCAL, domain_id)

    existing_remotely = _app_password_exists(auth, account_id, APP_PASSWORD_DESCRIPTION)
    recorded_locally = _load_recorded_secret() is not None

    action = plan_app_password_action(existing_remotely, recorded_locally)
    if action == "create":
        create_args = build_app_password_create_args(APP_PASSWORD_DESCRIPTION, DISABLED_PERMISSIONS)
        secret = _create_app_password(auth, account_id, create_args)
        _record_secret(secret)
        print(
            f"provision_website_submission_credential: created the submission credential "
            f"for {SEND_AS_LOCAL}@{MAIL_DOMAIN}, recorded at {SERVICE_CREDENTIALS_PATH}"
        )
    elif action == "orphaned":
        print(
            "provision_website_submission_credential: WARNING -- an app password named "
            f"{APP_PASSWORD_DESCRIPTION!r} already exists on {SEND_AS_LOCAL}@{MAIL_DOMAIN} but "
            f"no matching secret is recorded at {SERVICE_CREDENTIALS_PATH} -- its plaintext "
            "cannot be recovered. Destroy that credential via the admin API and re-run this "
            "script to get a fresh one (see mail/RUNBOOK-mx1-provision.md).",
            file=sys.stderr,
        )
        return 1
    else:
        print("provision_website_submission_credential: already provisioned, no-op")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.HTTPError as exc:
        print(
            f"provision_website_submission_credential: HTTP {exc.code} from the Stalwart API: "
            f"{exc.read().decode(errors='replace')}",
            file=sys.stderr,
        )
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(
            f"provision_website_submission_credential: could not reach the Stalwart API at {BASE_URL}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except RuntimeError as exc:
        # The same failure-mode path every other clear-reason error in this
        # script already raises (missing domain/account, a create call
        # Stalwart itself rejected, a malformed credentials-file line) --
        # printed plainly instead of a raw traceback.
        print(f"provision_website_submission_credential: {exc}", file=sys.stderr)
        sys.exit(1)
