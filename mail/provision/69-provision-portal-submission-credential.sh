#!/usr/bin/env bash
# Thin wrapper so run-all.sh has a uniform per-step interface. All the
# actual logic (and its idempotency) lives in
# provision_website_submission_credential.py -- see that file and
# mail/RUNBOOK-mx1-provision.md for what it provisions and why. Same script
# as 62-provision-shim-submission-credential.sh, parameterised here for the
# Professional enquiry mail of the tenant portal (send-as sales@, the enquiry
# recipient, so the owner replies from the same account). Its secret is
# recorded under its own label and read into the portal's host inputs by hand
# from the root-only credentials file, never printed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SEND_AS_LOCAL=sales \
CREDENTIAL_LABEL=portal-support-smtp \
APP_PASSWORD_DESCRIPTION=portal-support-transactional-submission \
    python3 "$SCRIPT_DIR/provision_website_submission_credential.py"
