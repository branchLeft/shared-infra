#!/usr/bin/env bash
# Thin wrapper so run-all.sh has a uniform per-step interface. All the
# actual logic (and its idempotency) lives in
# provision_website_submission_credential.py -- see that file,
# 60/61-...sh for the same pattern applied to the website and blog
# transactional credentials, and mail/RUNBOOK-mx1-provision.md for what
# this provisions and why. Parameterised here for the mailgun-shim's own
# bulk-mail submission credential on the existing blog@ account -- a
# second, independently revocable app password alongside 61's
# blog-ghost-smtp transactional one, so retiring or rotating either path
# never touches the other.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SEND_AS_LOCAL=blog \
CREDENTIAL_LABEL=blog-shim-bulk-submission \
APP_PASSWORD_DESCRIPTION=mailgun-shim-bulk-submission \
    python3 "$SCRIPT_DIR/provision_website_submission_credential.py"
