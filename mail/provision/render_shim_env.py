#!/usr/bin/env python3
"""Renders /etc/mailgun-shim/env for the shim image shim-compose.yml pins.
Run by 63-deploy-mailgun-shim.sh on every deploy -- re-rendering is idempotent
by construction (the same secret in always produces the same file out) and
safe to repeat: the file is written atomically, so a crash or disk-full
mid-write can never leave a truncated or half-written env file for docker
compose to read.

What the env must hold depends on the image: each shim image reads its own set
of variables. shim-env-contracts.json (beside this file, the one home of that
table) maps each pinned image digest to a contract -- the secret's label in
SERVICE_CREDENTIALS_PATH and the exact env lines. This script reads the single
digest out of the compose file compose itself reads (SHIM_COMPOSE_PATH) and
renders that digest's contract. A digest the table does not list is REFUSED,
with nothing written: the env of an image nobody described is a guess, and a
wrong guess stops the container at start or runs it unauthenticated.

Two secrets, two kinds. An SMTP submission credential (mint=false) is created
by 62-provision-shim-submission-credential.sh on Stalwart, so this script only
reads it and never writes the credentials file. A drain token (mint=true) has
no remote system to create it on: it is generated locally on first use
(secrets.token_urlsafe, matching rotate_admin_credential.py's own generation)
and recorded in the same flat label:secret file, so a re-run reuses it rather
than minting a new one and locking out whatever already holds the old one.

Never prints a secret, or any string containing it, to stdout or stderr --
only mode-600 file writes.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
import tempfile

PROVISION_DIR = os.path.dirname(os.path.abspath(__file__))

SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)
SHIM_ENV_PATH = os.environ.get("SHIM_ENV_PATH", "/etc/mailgun-shim/env")
# The compose file compose actually reads (63 passes its installed copy). The default is the
# sibling in this directory, which is what 63 installs.
SHIM_COMPOSE_PATH = os.environ.get(
    "SHIM_COMPOSE_PATH", os.path.join(PROVISION_DIR, "shim-compose.yml")
)
CONTRACTS_PATH = os.path.join(PROVISION_DIR, "shim-env-contracts.json")

SECRET_PLACEHOLDER = "{secret}"  # noqa: S105 -- a template marker, never a value
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
# The one shim `image:` line of the compose file. A tag pin, a placeholder digest or a second
# shim line does not match exactly once, and is refused.
IMAGE_LINE = re.compile(
    r"^\s*image:\s*ghcr\.io/branchleft/mailgun-shim@(sha256:[0-9a-f]{64})\s*$", re.MULTILINE
)


class ContractError(Exception):
    """A refusal to render. Names a digest, a file or a label, never a secret."""


def validate_table(table: object, path: str = CONTRACTS_PATH) -> dict:
    """Pure. Returns `table` if it has the shape this script relies on, else refuses."""
    if not isinstance(table, dict) or set(table) != {"contracts", "digests"}:
        raise ContractError(f"{path} must hold exactly 'contracts' and 'digests'")
    contracts, digests = table["contracts"], table["digests"]
    if not isinstance(contracts, dict) or not isinstance(digests, dict):
        raise ContractError(f"{path}: 'contracts' and 'digests' must be objects")
    for name, contract in contracts.items():
        label = contract.get("secret_label") if isinstance(contract, dict) else None
        lines = contract.get("env_lines") if isinstance(contract, dict) else None
        if (
            not isinstance(label, str)
            or not label
            or not isinstance(contract.get("mint"), bool)
            or not isinstance(lines, list)
            or not all(isinstance(line, str) for line in lines)
            or sum(line.count(SECRET_PLACEHOLDER) for line in lines) != 1
        ):
            raise ContractError(
                f"{path}: contract {name!r} needs a secret_label, a boolean mint and env_lines "
                f"holding {SECRET_PLACEHOLDER} exactly once"
            )
    for digest, name in digests.items():
        if DIGEST_PATTERN.fullmatch(digest) is None or name not in contracts:
            raise ContractError(f"{path}: digest {digest!r} is malformed or names no contract")
    return table


def load_table(path: str = CONTRACTS_PATH) -> dict:
    """Reads and validates the contract table; a missing or unparsable file refuses."""
    try:
        with open(path, encoding="utf-8") as f:
            return validate_table(json.load(f), path)
    except (OSError, ValueError) as exc:
        raise ContractError(f"cannot read the contract table {path}: {type(exc).__name__}") from None


def digest_in_compose(compose_text: str, path: str = "<compose>") -> str:
    """Pure. The shim image digest of the compose file: its one pinned `image:` line."""
    found = IMAGE_LINE.findall(compose_text)
    if len(found) != 1:
        raise ContractError(
            f"{path} must hold exactly one mailgun-shim image line pinned by sha256 digest, "
            f"and holds {len(found)}"
        )
    return found[0]


def contract_for_compose(
    compose_text: str, table: dict, path: str = "<compose>", table_path: str = CONTRACTS_PATH
) -> dict:
    """Pure. The contract for the compose file's pinned digest, or a refusal naming the digest
    and the table file when the table does not list it.
    """
    digest = digest_in_compose(compose_text, path)
    name = table["digests"].get(digest)
    if name is None:
        raise ContractError(
            f"image digest {digest} in {path} has no contract in {table_path}: refusing to "
            "render an environment for an image nobody has described"
        )
    return table["contracts"][name]


def find_credential_secret(
    credentials_text: str, label: str, path: str = "<credentials>"
) -> str | None:
    """Pure. Scans SERVICE_CREDENTIALS_PATH's own 'label:secret' per-line
    format for `label`, mirroring
    provision_website_submission_credential.py's _load_recorded_secret --
    same malformed-line failure mode (a disk-full mid-append or a
    hand-edited file could leave a line with no ':' at all), reported the
    same way rather than as a raw ValueError from an unpacking split().
    Takes the file's text directly (not a path) so this stays testable
    without touching the filesystem; `path` is only used to make a raised
    error message point somewhere real.
    """
    for line_number, raw_line in enumerate(credentials_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if ":" not in line:
            raise RuntimeError(
                f"{path}:{line_number} is malformed (no ':' separator) -- "
                "expected 'label:secret'"
            )
        found_label, secret = line.split(":", 1)
        if found_label == label:
            return secret
    return None


def generate_drain_token() -> str:
    """The only impure step in provisioning the token -- separated out so a
    test can substitute a deterministic value at this one call site rather
    than mocking the stdlib.
    """
    return secrets.token_urlsafe(32)


def append_credential_atomic(path: str, label: str, secret: str) -> None:
    """Appends 'label:secret\\n' to `path`, mirroring
    provision_website_submission_credential.py's _record_secret: an append,
    never a rewrite, so every other script's own line already in this file
    is untouched. Creates the file at mode 600 if it doesn't exist yet --
    this script may be the first thing to ever write to it on a fresh host,
    unlike every 6x-provision-*.sh caller, which assumes the file (or
    nothing) is already there.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    file_existed = os.path.exists(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{label}:{secret}\n")
    os.chmod(path, 0o600)
    del file_existed  # mode is asserted unconditionally regardless of prior state


def ensure_drain_token(credentials_path: str, label: str) -> str:
    """Returns `label`'s secret from `credentials_path` if one is already
    recorded there; otherwise generates a fresh token, appends it, and
    returns the new value. A missing file is treated as empty rather than
    an error -- unlike every other secret this repo provisions, this one
    has no upstream system that must run first. Used only by a contract
    with mint=true.
    """
    credentials_text = ""
    if os.path.exists(credentials_path):
        with open(credentials_path, encoding="utf-8") as f:
            credentials_text = f.read()

    existing = find_credential_secret(credentials_text, label, path=credentials_path)
    if existing is not None:
        return existing

    token = generate_drain_token()
    append_credential_atomic(credentials_path, label, token)
    return token


def read_recorded_secret(credentials_path: str, label: str) -> str:
    """Returns the secret recorded under `label`, and never writes the file. Used by a contract
    with mint=false, whose secret another script (62-) created on a remote system.
    """
    if not os.path.exists(credentials_path):
        raise ContractError(
            f"{credentials_path} does not exist -- run "
            "62-provision-shim-submission-credential.sh first"
        )
    with open(credentials_path, encoding="utf-8") as f:
        secret = find_credential_secret(f.read(), label, path=credentials_path)
    if secret is None:
        raise ContractError(
            f"no {label!r} entry in {credentials_path} -- run "
            "62-provision-shim-submission-credential.sh first"
        )
    return secret


def render_env_file(contract: dict, secret: str) -> str:
    """Pure. The exact contents of /etc/mailgun-shim/env for a contract -- one KEY=value
    per line, no quoting or escaping beyond that (docker compose's
    `env_file` parser doesn't expect shell-style quoting, and none of these
    values contain characters that would need it -- every secret here is
    url-safe by construction, see provision_mailboxes.py and generate_drain_token).
    """
    lines = [line.replace(SECRET_PLACEHOLDER, secret) for line in contract["env_lines"]]
    return "\n".join(lines) + "\n"


def write_env_file_atomic(path: str, contents: str) -> None:
    """Writes `contents` to `path` atomically at mode 600: a temp file in
    the same directory (so the final os.replace is same-filesystem, hence
    atomic), created via mkstemp -- which is already mode 600 from the
    moment it exists, never briefly world-readable the way a plain write
    followed by a later os.chmod would be -- explicitly re-asserted here
    anyway so that guarantee doesn't silently depend on mkstemp's default.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".mailgun-shim-env.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    try:
        table = load_table(CONTRACTS_PATH)
        try:
            with open(SHIM_COMPOSE_PATH, encoding="utf-8") as f:
                compose_text = f.read()
        except OSError as exc:
            raise ContractError(
                f"cannot read the compose file {SHIM_COMPOSE_PATH}: {type(exc).__name__}"
            ) from None
        contract = contract_for_compose(compose_text, table, SHIM_COMPOSE_PATH, CONTRACTS_PATH)
        label = contract["secret_label"]
        if contract["mint"]:
            secret = ensure_drain_token(SERVICE_CREDENTIALS_PATH, label)
        else:
            secret = read_recorded_secret(SERVICE_CREDENTIALS_PATH, label)
    except (ContractError, RuntimeError) as exc:
        print(f"render_shim_env: {exc}", file=sys.stderr)
        return 1

    write_env_file_atomic(SHIM_ENV_PATH, render_env_file(contract, secret))
    print(f"render_shim_env: wrote {SHIM_ENV_PATH} (mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
