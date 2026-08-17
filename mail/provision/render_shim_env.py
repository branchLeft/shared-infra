#!/usr/bin/env python3
"""Renders /etc/mailgun-shim/env from the mailgun-shim's own submission
credential (SERVICE_CREDENTIALS_PATH's `blog-shim-bulk-submission` entry,
created by 62-provision-shim-submission-credential.sh) plus the shim's
fixed, non-secret configuration. Run by 63-deploy-mailgun-shim.sh on every
deploy -- re-rendering is idempotent by construction (the same credential in
always produces the same file out) and safe to repeat: the file is written
atomically, so a crash or disk-full mid-write can never leave a truncated or
half-written env file for docker compose to read.

SMTP_HOST is mx1's own public hostname, not loopback -- nodemailer's
STARTTLS certificate verification has to match the name Stalwart's own
certificate presents (mx1.branchleft.co.uk, not 127.0.0.1 or "localhost"),
and traffic addressed to the host's own hostname never actually leaves the
box, so routing through the public name costs nothing here.

Never prints the secret, or any string containing it, to stdout or stderr --
only a mode-600 file write.
"""
from __future__ import annotations

import os
import sys
import tempfile

SERVICE_CREDENTIALS_PATH = os.environ.get(
    "SERVICE_CREDENTIALS_PATH", "/root/.stalwart-service-credentials"
)
SHIM_ENV_PATH = os.environ.get("SHIM_ENV_PATH", "/etc/mailgun-shim/env")

# The credential label 62-provision-shim-submission-credential.sh records
# this secret under -- see provision_website_submission_credential.py's
# CREDENTIAL_LABEL parameterisation.
CREDENTIAL_LABEL = os.environ.get("CREDENTIAL_LABEL", "blog-shim-bulk-submission")

# The shim's fixed configuration -- everything but SMTP_PASS is non-secret
# and the same on every render. Matches the shim's own env-var contract
# (PORT, SHIM_DB_PATH, SHIM_THROTTLE_PATH, SMTP_HOST/PORT/SECURE/USER/PASS).
PORT = "8080"
SHIM_DB_PATH = "/data/shim.db"
SHIM_THROTTLE_PATH = "/data/throttle.json"
SMTP_HOST = "mx1.branchleft.co.uk"
SMTP_PORT = "587"
SMTP_SECURE = "false"
SMTP_USER = "blog@branchleft.co.uk"


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


def render_env_file(smtp_pass: str) -> str:
    """Pure. The exact contents of /etc/mailgun-shim/env -- one KEY=value
    per line, no quoting or escaping beyond that (docker compose's
    `env_file` parser doesn't expect shell-style quoting, and none of these
    values contain characters that would need it -- an app-password secret
    is Stalwart-generated `secrets.token_urlsafe` output, url-safe by
    construction, see provision_mailboxes.py).
    """
    lines = [
        f"PORT={PORT}",
        f"SHIM_DB_PATH={SHIM_DB_PATH}",
        f"SHIM_THROTTLE_PATH={SHIM_THROTTLE_PATH}",
        f"SMTP_HOST={SMTP_HOST}",
        f"SMTP_PORT={SMTP_PORT}",
        f"SMTP_SECURE={SMTP_SECURE}",
        f"SMTP_USER={SMTP_USER}",
        f"SMTP_PASS={smtp_pass}",
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
    if not os.path.exists(SERVICE_CREDENTIALS_PATH):
        print(
            f"render_shim_env: {SERVICE_CREDENTIALS_PATH} does not exist -- "
            "run 62-provision-shim-submission-credential.sh first",
            file=sys.stderr,
        )
        return 1

    with open(SERVICE_CREDENTIALS_PATH, encoding="utf-8") as f:
        credentials_text = f.read()

    try:
        secret = find_credential_secret(
            credentials_text, CREDENTIAL_LABEL, path=SERVICE_CREDENTIALS_PATH
        )
    except RuntimeError as exc:
        print(f"render_shim_env: {exc}", file=sys.stderr)
        return 1

    if secret is None:
        print(
            f"render_shim_env: no {CREDENTIAL_LABEL!r} entry in "
            f"{SERVICE_CREDENTIALS_PATH} -- run "
            "62-provision-shim-submission-credential.sh first",
            file=sys.stderr,
        )
        return 1

    write_env_file_atomic(SHIM_ENV_PATH, render_env_file(secret))
    print(f"render_shim_env: wrote {SHIM_ENV_PATH} (mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
