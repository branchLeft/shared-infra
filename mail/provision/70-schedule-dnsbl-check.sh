#!/usr/bin/env bash
# Installs an hourly cron.d entry that runs check_dnsbl_blocklist.py. A listed
# sending address silently kills deliverability for everyone sending through
# this host, so the listing has to be found by a check rather than by a
# complaint, and hourly is the resolution that gets. Idempotent: compares byte-for-byte against a temp file and
# only writes when the drop-in actually needs to change -- Debian's cron
# watches /etc/cron.d for changes on its own, so no daemon reload is needed
# either way. See mail/RUNBOOK-mx1-provision.md's "DNSBL blocklist
# monitoring" section for what the check does and how to read its output.
set -euo pipefail

DROPIN=/etc/cron.d/dnsbl-check
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
# Managed by shared-infra/mail/provision/70-schedule-dnsbl-check.sh --
# re-running that script overwrites hand edits here.
SHELL=/bin/bash
5 * * * * root python3 $SCRIPT_DIR/check_dnsbl_blocklist.py >> /var/log/dnsbl-check.cron.log 2>&1
EOF

if [[ -f "$DROPIN" ]] && cmp -s "$TMP" "$DROPIN"; then
    echo "70-schedule-dnsbl-check: $DROPIN already up to date, no-op"
    exit 0
fi

install -m 644 "$TMP" "$DROPIN"
echo "70-schedule-dnsbl-check: wrote $DROPIN"
