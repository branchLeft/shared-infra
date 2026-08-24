#!/usr/bin/env bash
# Thin wrapper so run-all.sh has a uniform per-step interface. All the
# actual logic (and its idempotency) lives in
# provision_website_submission_credential.py -- see that file and
# mail/RUNBOOK-mx1-provision.md for what it provisions and why. Same script
# as 60-provision-website-submission-credential.sh, parameterised here for
# Alertmanager's send-as-alerts@ credential.
#
# Listed in run-all.sh rather than left as a one-off command so a rebuilt host
# comes back with alerting able to authenticate. A host that provisions the
# mailbox and its forwarding script but not this credential looks fully
# provisioned and cannot send a single alert.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SEND_AS_LOCAL=alerts \
CREDENTIAL_LABEL=alerting-submission \
APP_PASSWORD_DESCRIPTION=monitoring-alert-relay \
    python3 "$SCRIPT_DIR/provision_website_submission_credential.py"
