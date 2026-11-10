#!/usr/bin/env python3
"""Provisions branchLeft's own mailboxes on Stalwart:
real mailbox accounts for every local part in MAILBOXES, plus a per-mailbox
Sieve script on each address in ROLE_ADDRESSES that copies inbound mail to
rob@ (`redirect :copy`, RFC 3894).

Mailbox accounts use the same "x:<Type>/get" / "x:<Type>/set" registry API
family configure_stalwart.py already uses for listeners/domains
(`x:Account/set`), but the per-mailbox Sieve script does not: despite the
name, `x:SieveUserScript` is an admin-managed *global* script (includable by
name via Sieve's `:global`, RFC 6609), not a per-mailbox filter. The actual
per-mailbox mechanism is the standard JMAP Sieve capability
(`urn:ietf:params:jmap:sieve`, `SieveScript/set`) via blob upload + activate.
See mail/RUNBOOK-mx1-provision.md#mailbox-provisioning for how this was
verified and the live request/response evidence.

Also note: `List<T>`-typed registry fields (`credentials`, `aliases`)
serialize as a JSON object keyed "0", "1", ... not a JSON array.

Idempotent: existing mailboxes are left alone (this script never rewrites a
password once set -- that is rotate_admin_credential.py's model, not this
one's); each role's Sieve script is left alone if a script of the same name
already holds the same content and is active, otherwise corrected. A second
run against fully-reconciled state makes only GET calls.

`--domain D --only L` (both, or neither) creates only L@D instead of the
fixed list; D must be in ALLOWED_DOMAINS and L must match
ONLY_LOCALPART_PATTERN, else exit 2 before any credential is read. Such a
mailbox always gets the copy-forward to rob@ on MAIL_DOMAIN, and its secret
is recorded under the full address (recorded_secret_key). See
mail/RUNBOOK-mx1-provision.md#mailbox-provisioning.

Mailbox passwords are persisted at MAILBOX_CREDENTIALS_PATH (mode 600,
root-owned, on-box only) *before* the create call that sets them, not after
-- see resolve_mailbox_secret and _reconcile_accounts for why. Never
printed, never logged, never returned to the caller. See "Secrets" in
mail/RUNBOOK-mx1-provision.md.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

BASE_URL = os.environ.get("STALWART_BASE_URL", "http://127.0.0.1:8080")
ADMIN_CREDENTIALS_PATH = os.environ.get(
    "STALWART_CREDENTIALS_PATH", "/root/.stalwart-admin-credentials"
)
MAILBOX_CREDENTIALS_PATH = os.environ.get(
    "MAILBOX_CREDENTIALS_PATH", "/root/.stalwart-mailbox-credentials"
)
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "branchleft.co.uk")

# Real mailboxes this script provisions (extended for
# abuse@ -- required as a receivable contact address for Microsoft SNDS
# ownership verification and RFC 2142 abuse-reporting convention -- and for
# blog@ -- the account the blog's submission-only SMTP credential
# authenticates into and sends as, see provision_website_submission_credential.py
# -- and for acme@ -- the Hetzner edge's ACME_EMAIL, see hetzner/RUNBOOK-edge.md
# -- and for alerts@ -- the account Alertmanager's submission-only SMTP
# credential authenticates into and sends as, see hetzner/RUNBOOK-monitoring.md
# -- and for noreply@ -- the account Nextcloud's submission-only SMTP
# credential authenticates into and sends as, see
# mail/RUNBOOK-mx1-provision.md#nextcloud-submission-credential
# -- and for psl@ -- the role contact published in the Public Suffix List
# entry for sites.publicpress.co.uk, which the list's maintainers email and
# expect answered within 30 days, see mail/RUNBOOK-mx1-provision.md#mailbox-provisioning).
MAILBOXES = ("rob", "contact", "info", "sales", "complaints", "abuse", "blog", "acme", "alerts", "noreply", "psl")

# The ones that get a copy-forward to rob@ -- rob@ itself gets no script.
# Exactly one `redirect` each, never two: a second is dropped at delivery while
# the script still compiles and diffs clean. See
# mail/RUNBOOK-mx1-provision.md#mailbox-provisioning.
ROLE_ADDRESSES = ("contact", "info", "sales", "complaints", "abuse", "blog", "acme", "alerts", "noreply", "psl")

FORWARD_TARGET = f"rob@{MAIL_DOMAIN}"

# `--domain D --only L` creates exactly L@D and nothing else. Both flags are
# required together; with neither, the script behaves exactly as it always
# has. D must be one of these domains (a closed set, not a pattern: a typo or
# a hostile argument can never mint an account on a domain nobody listed), and
# L must match ONLY_LOCALPART_PATTERN. A domain is added here in the change
# that needs it, never taken from the command line.
ALLOWED_DOMAINS = ("branchleft.co.uk", "blog.branchleft.co.uk")
# \Z, not $: `$` also matches before a trailing newline.
ONLY_LOCALPART_PATTERN = re.compile(r"[a-z][a-z0-9]{0,31}\Z")
SIEVE_SCRIPT_NAME = "forward-copy-to-rob"
SIEVE_CAPABILITIES = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:sieve"]
SIEVE_SCRIPT_SET = "SieveScript/set"


def sieve_script_contents(forward_target: str) -> str:
    """The exact script every role address gets -- `:copy` (RFC 3894) so the
    original delivery to the role mailbox is kept, not suppressed, alongside
    the redirected copy. Pure and parameterised on the forward target purely
    so tests don't hardcode a live email address twice.
    """
    return f'require ["copy"];\nredirect :copy "{forward_target}";\n'


def validate_target(domain: str | None, only: str | None) -> str | None:
    """Pure check of the `--domain` / `--only` pair. Returns None when the
    pair is usable (both absent, or both present and valid), else the reason
    it is refused. Nothing is read or written before this passes.
    """
    if domain is None and only is None:
        return None
    if domain is None or only is None:
        return "--domain and --only must be given together"
    if domain not in ALLOWED_DOMAINS:
        return f"domain {domain!r} is not one of {', '.join(ALLOWED_DOMAINS)}"
    if ONLY_LOCALPART_PATTERN.match(only) is None:
        return f"local part {only!r} does not match {ONLY_LOCALPART_PATTERN.pattern}"
    return None


def parse_args(argv: list[str]) -> tuple[str, str] | None:
    """Returns (domain, local) for a targeted run, or None for the default
    run. A refused pair exits 2 before any credential is read.
    """
    parser = argparse.ArgumentParser(
        prog="provision_mailboxes.py",
        description="With no flags, provisions branchLeft's own mailboxes. "
        "With --domain and --only, creates only that one mailbox.",
    )
    parser.add_argument("--domain", help="one of: " + ", ".join(ALLOWED_DOMAINS))
    parser.add_argument("--only", metavar="LOCALPART", help="the one local part to create")
    args = parser.parse_args(argv)
    reason = validate_target(args.domain, args.only)
    if reason is not None:
        print(f"provision_mailboxes: refused, nothing written: {reason}", file=sys.stderr)
        raise SystemExit(2)
    if args.domain is None:
        return None
    return args.domain, args.only


def recorded_secret_key(local: str, domain: str) -> str:
    """The key a mailbox's secret is recorded under in MAILBOX_CREDENTIALS_PATH.
    The main domain keeps the bare local part (the file's existing format);
    any other domain uses the full address, so hello@blog.branchleft.co.uk and
    a later hello@branchleft.co.uk can never share or reuse one secret.
    """
    return local if domain == MAIL_DOMAIN else f"{local}@{domain}"


def forwards_to_rob(local: str, domain: str) -> bool:
    """Whether the mailbox gets the copy-forward to rob@. On the main domain
    that is exactly ROLE_ADDRESSES, as it always was; on any other domain
    every mailbox the script is asked to create does (rob@ lives only on the
    main domain, so there is no loop).
    """
    return local in ROLE_ADDRESSES if domain == MAIL_DOMAIN else True


def missing_mailboxes(mailboxes: tuple[str, ...], existing_names: set[str]) -> list[str]:
    """Pure diff: local-parts in `mailboxes` that don't have an Account
    under this domain yet, preserving MAILBOXES' order. Empty if all
    already exist.
    """
    return [local for local in mailboxes if local not in existing_names]


def build_account_create_args(local: str, domain_id: str, secret: str) -> dict[str, Any]:
    """The actual x:Account/set create object for one mailbox -- separated
    from plan_account_creates so the domain_id substitution (impure-adjacent:
    depends on a value fetched from the live domain list) has a single,
    directly testable place to live.
    """
    return {
        "@type": "User",
        "name": local,
        "domainId": domain_id,
        "credentials": {"0": {"@type": "Password", "secret": secret}},
    }


def plan_sieve_action(existing: dict[str, Any] | None, target_contents: str) -> str:
    """Pure diff for one role account's forwarding script. `existing` is
    None if no script named SIEVE_SCRIPT_NAME exists yet for that account,
    else {"id", "isActive", "contents"} (contents already downloaded by the
    caller -- this function does no I/O). Returns one of:
    "create"   -- no script by this name exists yet
    "update"   -- a script exists but its content has drifted
    "activate" -- content matches but it isn't the active script
    "none"     -- content matches and it's already active
    """
    if existing is None:
        return "create"
    if existing["contents"] != target_contents:
        return "update"
    if not existing["isActive"]:
        return "activate"
    return "none"


def _request(method: str, path: str, auth: tuple[str, str], body: bytes | None = None, content_type: str | None = None) -> Any:
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, method=method)
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    if content_type is not None:
        req.add_header("Content-Type", content_type)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _jmap_call(auth: tuple[str, str], method: str, args: dict[str, Any], using: list[str] | None = None) -> dict[str, Any]:
    body = json.dumps(
        {"using": using or ["urn:ietf:params:jmap:core"], "methodCalls": [[method, args, "0"]]}
    ).encode()
    response = _request("POST", "/jmap", auth, body, content_type="application/json")
    name, result, _ = response["methodResponses"][0]
    if name == "error":
        raise RuntimeError(f"{method} failed: {result}")
    return result


def _load_admin_credentials() -> tuple[str, str]:
    with open(ADMIN_CREDENTIALS_PATH, encoding="utf-8") as f:
        username, secret = f.read().strip().split(":", 1)
    return username, secret


def _load_recorded_secrets() -> dict[str, str]:
    if not os.path.exists(MAILBOX_CREDENTIALS_PATH):
        return {}
    recorded: dict[str, str] = {}
    with open(MAILBOX_CREDENTIALS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            local, secret = line.split(":", 1)
            recorded[local] = secret
    return recorded


def resolve_mailbox_secret(local: str, recorded_secrets: dict[str, str], generate_secret: Callable[[], str]) -> str:
    """Reuses a secret already recorded for `local` if one exists, otherwise
    calls `generate_secret()` for a fresh one. Recorded secrets are written
    to disk *before* the create call that uses them (see
    `_reconcile_accounts`), so a create that reports success but whose
    response never arrives (crash, reboot, dropped connection) leaves a
    secret on disk that already matches whatever Stalwart actually set --
    the next run must reuse it, not generate and record a different one,
    or the account becomes permanently unrecoverable (no companion
    mailbox-password-reset tool exists; rotate_admin_credential.py only
    handles the single admin credential). `generate_secret` is injected
    so this stays testable without patching the `secrets` module.
    """
    if local in recorded_secrets:
        return recorded_secrets[local]
    return generate_secret()


def _record_mailbox_secret(local: str, secret: str) -> None:
    # Append-only, and only for a secret not already on disk -- see
    # resolve_mailbox_secret. rotate_admin_credential.py's model (generate,
    # verify, only then persist) is for deliberate rotation, not this
    # reconciliation script.
    with open(MAILBOX_CREDENTIALS_PATH, "a", encoding="utf-8") as f:
        f.write(f"{local}:{secret}\n")
    os.chmod(MAILBOX_CREDENTIALS_PATH, 0o600)


def _get_domain_id(auth: tuple[str, str], domain_name: str) -> str:
    domains = _jmap_call(auth, "x:Domain/get", {})["list"]
    for domain in domains:
        if domain["name"] == domain_name:
            return domain["id"]
    raise RuntimeError(
        f"no Domain object named {domain_name!r} -- expected configure_stalwart.py's "
        "bootstrap/reconciliation to have already created it"
    )


def _get_existing_account_names(auth: tuple[str, str], domain_id: str) -> dict[str, str]:
    # Only "name"/"domainId" requested -- per JMAP Get semantics the server
    # returns just the requested properties (plus id), so this call never
    # touches the `credentials` field at all, let alone prints it.
    accounts = _jmap_call(auth, "x:Account/get", {"properties": ["name", "domainId"]})["list"]
    return {a["name"]: a["id"] for a in accounts if a.get("domainId") == domain_id}


def _create_account(auth: tuple[str, str], local: str, create_args: dict[str, Any]) -> str:
    result = _jmap_call(auth, "x:Account/set", {"create": {local: create_args}})
    if local not in result.get("created", {}):
        raise RuntimeError(f"x:Account/set did not create {local!r}: {result.get('notCreated')}")
    return result["created"][local]["id"]


def _get_sieve_script(auth: tuple[str, str], account_id: str, name: str) -> dict[str, Any] | None:
    result = _jmap_call(
        auth, "SieveScript/get", {"accountId": account_id, "ids": None}, using=SIEVE_CAPABILITIES
    )
    for script in result["list"]:
        if script["name"] == name:
            return script
    return None


def _download_blob(auth: tuple[str, str], account_id: str, blob_id: str, name: str) -> str:
    quoted_name = urllib.parse.quote(name)
    path = f"/jmap/download/{account_id}/{blob_id}/{quoted_name}?accept=application/sieve"
    req = urllib.request.Request(f"{BASE_URL}{path}", method="GET")
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")


def _upload_blob(auth: tuple[str, str], account_id: str, contents: str) -> str:
    result = _request(
        "POST",
        f"/jmap/upload/{account_id}/",
        auth,
        body=contents.encode("utf-8"),
        content_type="application/sieve",
    )
    return result["blobId"]


def _create_sieve_script(auth: tuple[str, str], account_id: str, name: str, contents: str) -> None:
    blob_id = _upload_blob(auth, account_id, contents)
    result = _jmap_call(
        auth,
        SIEVE_SCRIPT_SET,
        {
            "accountId": account_id,
            "create": {"s": {"name": name, "blobId": blob_id}},
            "onSuccessActivateScript": "#s",
        },
        using=SIEVE_CAPABILITIES,
    )
    if "s" not in result.get("created", {}):
        raise RuntimeError(f"{SIEVE_SCRIPT_SET} did not create {name!r}: {result.get('notCreated')}")


def _update_sieve_script(auth: tuple[str, str], account_id: str, script_id: str, contents: str) -> None:
    blob_id = _upload_blob(auth, account_id, contents)
    result = _jmap_call(
        auth,
        SIEVE_SCRIPT_SET,
        {
            "accountId": account_id,
            "update": {script_id: {"blobId": blob_id}},
            "onSuccessActivateScript": script_id,
        },
        using=SIEVE_CAPABILITIES,
    )
    if script_id not in result.get("updated", {}):
        raise RuntimeError(f"{SIEVE_SCRIPT_SET} did not update {script_id!r}: {result.get('notUpdated')}")


def _activate_sieve_script(auth: tuple[str, str], account_id: str, script_id: str) -> None:
    result = _jmap_call(
        auth,
        SIEVE_SCRIPT_SET,
        {"accountId": account_id, "update": {script_id: {}}, "onSuccessActivateScript": script_id},
        using=SIEVE_CAPABILITIES,
    )
    if script_id not in result.get("updated", {}):
        raise RuntimeError(f"{SIEVE_SCRIPT_SET} did not activate {script_id!r}: {result.get('notUpdated')}")


def _reconcile_accounts(
    auth: tuple[str, str],
    domain_id: str,
    mailboxes: tuple[str, ...] | None = None,
    domain: str | None = None,
) -> dict[str, str]:
    """Returns {local_part: account_id} for all of MAILBOXES (or, for a
    targeted run, the `mailboxes` given on `domain`), creating whichever
    don't exist yet.

    Ordering matters here: the secret is resolved and persisted to disk
    *before* the x:Account/set call that uses it, not after. If that call's
    response is lost after Stalwart already applied it (crash, reboot,
    dropped connection), the secret already on disk is guaranteed to be the
    one that was actually sent -- a re-run either finds the account already
    exists (nothing left to do) or retries the same create with the same
    secret (resolve_mailbox_secret reuses a recorded one rather than
    generating a new one). Persisting *after* a successful-but-unconfirmed
    create would instead risk a real mailbox with a password that never
    reached disk and no way to recover it short of a manual admin-console
    reset.
    """
    mailboxes = MAILBOXES if mailboxes is None else mailboxes
    domain = MAIL_DOMAIN if domain is None else domain
    existing = _get_existing_account_names(auth, domain_id)
    missing = missing_mailboxes(mailboxes, set(existing))
    recorded_secrets = _load_recorded_secrets()

    account_ids = dict(existing)
    for local in missing:
        key = recorded_secret_key(local, domain)
        secret = resolve_mailbox_secret(key, recorded_secrets, lambda: secrets.token_urlsafe(32))
        if key not in recorded_secrets:
            _record_mailbox_secret(key, secret)
        create_args = build_account_create_args(local, domain_id, secret)
        account_id = _create_account(auth, local, create_args)
        account_ids[local] = account_id
        print(f"provision_mailboxes: created mailbox {local}@{domain} (id {account_id})")

    if not missing:
        print("provision_mailboxes: all mailboxes already exist, no-op")

    return account_ids


def _reconcile_role_sieve_script(
    auth: tuple[str, str], local: str, account_id: str, domain: str | None = None
) -> bool:
    domain = MAIL_DOMAIN if domain is None else domain
    target_contents = sieve_script_contents(FORWARD_TARGET)
    script = _get_sieve_script(auth, account_id, SIEVE_SCRIPT_NAME)

    existing = None
    if script is not None:
        contents = _download_blob(auth, account_id, script["blobId"], f"{SIEVE_SCRIPT_NAME}.siv")
        existing = {"id": script["id"], "isActive": script["isActive"], "contents": contents}

    action = plan_sieve_action(existing, target_contents)
    if action == "create":
        _create_sieve_script(auth, account_id, SIEVE_SCRIPT_NAME, target_contents)
        print(f"provision_mailboxes: created and activated the forwarding script for {local}@{domain}")
    elif action == "update":
        _update_sieve_script(auth, account_id, existing["id"], target_contents)
        print(f"provision_mailboxes: corrected the forwarding script's content for {local}@{domain}")
    elif action == "activate":
        _activate_sieve_script(auth, account_id, existing["id"])
        print(f"provision_mailboxes: reactivated the forwarding script for {local}@{domain}")
    else:
        print(f"provision_mailboxes: forwarding script for {local}@{domain} already up to date, no-op")
    return action != "none"


def main(target: tuple[str, str] | None = None) -> int:
    """`target` is (domain, local) for a targeted run (already validated by
    parse_args), None for the default run over MAILBOXES.
    """
    if target is not None:
        return _main_targeted(*target)
    auth = _load_admin_credentials()
    domain_id = _get_domain_id(auth, MAIL_DOMAIN)

    account_ids = _reconcile_accounts(auth, domain_id)

    changed = False
    for local in ROLE_ADDRESSES:
        changed = _reconcile_role_sieve_script(auth, local, account_ids[local]) or changed

    if not changed:
        print("provision_mailboxes: nothing left to reconcile")

    return 0


def _main_targeted(domain: str, local: str) -> int:
    # Re-checked here so no caller can reach the Stalwart API with an
    # unvalidated pair, whatever it passed in.
    reason = validate_target(domain, local)
    if reason is not None:
        print(f"provision_mailboxes: refused, nothing written: {reason}", file=sys.stderr)
        return 2
    auth = _load_admin_credentials()
    domain_id = _get_domain_id(auth, domain)
    account_ids = _reconcile_accounts(auth, domain_id, (local,), domain)
    changed = False
    if forwards_to_rob(local, domain):
        changed = _reconcile_role_sieve_script(auth, local, account_ids[local], domain)
    if not changed:
        print("provision_mailboxes: nothing left to reconcile")
    return 0


if __name__ == "__main__":
    target = parse_args(sys.argv[1:])
    try:
        sys.exit(main(target))
    except urllib.error.HTTPError as exc:
        # Must come before URLError -- HTTPError is a URLError subclass.
        print(f"provision_mailboxes: HTTP {exc.code} from the Stalwart API: {exc.read().decode(errors='replace')}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"provision_mailboxes: could not reach the Stalwart API at {BASE_URL}: {exc}", file=sys.stderr)
        sys.exit(1)
