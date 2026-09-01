#!/usr/bin/env bash
# Deploys Stalwart via Docker Compose. Idempotent: `docker compose up -d`
# is itself a no-op when the running container already matches the compose
# file, so this script just keeps the on-box copy of the compose file in
# sync with the one committed here and lets compose decide whether anything
# needs to change.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR=/opt/stalwart
DEST_COMPOSE="$DEST_DIR/docker-compose.yml"

mkdir -p "$DEST_DIR"

# The compose file requires STALWART_PROMETHEUS_SECRET and has no default, so
# a rebuilt host with no .env would abort run-all.sh here -- at step 4 of 13,
# before mailboxes or any submission credential exists. Mint one instead.
#
# A generated secret nobody has copied to edge1 yet is the safe failure: the
# exporter is authenticated against a credential no client holds, so the
# endpoint is closed rather than open. Scraping resumes when an operator
# copies this value across, which is a monitoring gap, not a mail outage.
# Never overwrite an existing file -- that would silently break a working
# scrape on every re-run.
ENV_FILE="$DEST_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    umask 077
    printf 'STALWART_PROMETHEUS_SECRET=%s\n' \
        "$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48)" > "$ENV_FILE"
    echo "30-deploy-stalwart: minted a new $ENV_FILE (mode 600)"
    echo "30-deploy-stalwart: WARNING -- Prometheus will not scrape mx1 until this" >&2
    echo "30-deploy-stalwart: value is copied into edge1's /etc/branchleft/monitoring.env." >&2
    echo "30-deploy-stalwart: see mail/RUNBOOK-mx1-prometheus-metrics.md step 5." >&2
fi

if [[ -f "$DEST_COMPOSE" ]] && cmp -s "$SCRIPT_DIR/docker-compose.yml" "$DEST_COMPOSE"; then
    echo "30-deploy-stalwart: $DEST_COMPOSE already up to date"
else
    cp "$SCRIPT_DIR/docker-compose.yml" "$DEST_COMPOSE"
    echo "30-deploy-stalwart: updated $DEST_COMPOSE"
fi

docker compose -f "$DEST_COMPOSE" up -d

echo "30-deploy-stalwart: waiting for the container to report healthy"
for _ in $(seq 1 30); do
    status="$(docker inspect --format '{{.State.Health.Status}}' stalwart 2>/dev/null || echo "starting")"
    if [[ "$status" == "healthy" ]]; then
        echo "30-deploy-stalwart: stalwart is healthy"
        exit 0
    fi
    sleep 2
done

echo "30-deploy-stalwart: stalwart did not report healthy within 60s (last status: ${status:-unknown})" >&2
docker logs --tail 50 stalwart >&2 || true
exit 1
