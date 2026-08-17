#!/usr/bin/env bash
# Thin wrapper so run-all.sh has a uniform per-step interface. All the
# actual logic (and its idempotency) lives in
# provision_website_submission_credential.py -- see that file and
# mail/RUNBOOK-mx1-provision.md for what it provisions and why. Same script
# as 60-provision-website-submission-credential.sh, parameterised here for
# the blog's send-as-blog@ credential instead of the website's send-as-info@
# one.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SEND_AS_LOCAL=blog \
CREDENTIAL_LABEL=blog-ghost-smtp \
APP_PASSWORD_DESCRIPTION=blog-ghost-transactional-submission \
    python3 "$SCRIPT_DIR/provision_website_submission_credential.py"
