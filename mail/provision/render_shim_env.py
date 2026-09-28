#!/usr/bin/env python3
"""Renders /etc/mailgun-shim/env from the shim's own drain-auth token plus
its fixed, non-secret configuration. Run by 63-deploy-mailgun-shim.sh on
every deploy -- re-rendering is idempotent by construction (the same token
in always produces the same file out) and safe to repeat: the file is
written atomically, so a crash or disk-full mid-write can never leave a
truncated or half-written env file for docker compose to read.

The shim's own outbound delivery (worker.ts/smtp.ts, and the SMTP_HOST/
PORT/SECURE/USER/PASS env vars this file used to render for them) is gone --
a drain handover replaced it: the shim only queues mail and hands it to
whatever polls GET /drain and acks what it took. SHIM_DRAIN_TOKEN is that
endpoint's one credential (config.ts's requireEnv -- an unset value fails
the container closed rather than starting silently unauthenticated), and
unlike every other credential this repo provisions there is no remote
system to create it on: it is this script's own secret. Generated locally
on first use
(secrets.token_urlsafe, matching rotate_admin_credential.py's own
generation) and recorded in SERVICE_CREDENTIALS_PATH under
DRAIN_TOKEN_LABEL -- the same flat label:secret file the 6x-provision-*.sh
scripts already share -- so a re-run reuses the same token rather than
minting a new one and silently locking out whatever already holds the old
one (the mail collector, once it exists, and every other 6x script's own
label lives in this same file untouched).

Never prints the token, or any string containing it, to stdout or stderr --
only mode-600 file writes.
"""
from __future__ import annotations

import os
import secrets
import sys
import tempfile

SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)
SHIM_ENV_PATH = os.environ.get("SHIM_ENV_PATH", "/etc/mailgun-shim/env")

# The label this token is recorded under in SERVICE_CREDENTIALS_PATH -- must
# stay distinct from every 6x-provision-*.sh CREDENTIAL_LABEL in that same
# file (test_provision_mailboxes.py asserts those are unique; this one isn't
# a Stalwart app password at all, so it lives outside that check, but the
# file format and the "one label per secret" rule are shared).
DRAIN_TOKEN_LABEL = os.environ.get("DRAIN_TOKEN_LABEL", "shim-drain-token")

# The shim's fixed configuration. PORT is pinned to match shim-compose.yml's
# own container-side mapping ('127.0.0.1:8825:8080') and healthcheck (both
# hardcode 8080) explicitly, rather than relying on it happening to equal
# config.ts's own default -- everything else config.ts reads
# (SHIM_MESSAGES_PER_HOUR, the SHIM_DRAIN_* tunables,
# SHIM_MAX_RECIPIENTS_PER_MESSAGE, the SMTP front door's own SMTP_LISTEN_*
# family) defaults sanely inside the shim itself, so this deployment leaves
# those unset rather than pinning a value nothing here needs to override.
PORT = "8080"
SHIM_DB_PATH = "/data/shim.db"
SHIM_THROTTLE_PATH = "/data/throttle.json"


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
    has no upstream system that must run first.
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


def render_env_file(drain_token: str) -> str:
    """Pure. The exact contents of /etc/mailgun-shim/env -- one KEY=value
    per line, no quoting or escaping beyond that (docker compose's
    `env_file` parser doesn't expect shell-style quoting, and none of these
    values contain characters that would need it -- this token is
    `secrets.token_urlsafe` output, url-safe by construction).
    """
    lines = [
        f"PORT={PORT}",
        f"SHIM_DB_PATH={SHIM_DB_PATH}",
        f"SHIM_THROTTLE_PATH={SHIM_THROTTLE_PATH}",
        f"SHIM_DRAIN_TOKEN={drain_token}",
    ]
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
        drain_token = ensure_drain_token(SERVICE_CREDENTIALS_PATH, DRAIN_TOKEN_LABEL)
    except RuntimeError as exc:
        print(f"render_shim_env: {exc}", file=sys.stderr)
        return 1

    write_env_file_atomic(SHIM_ENV_PATH, render_env_file(drain_token))
    print(f"render_shim_env: wrote {SHIM_ENV_PATH} (mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
